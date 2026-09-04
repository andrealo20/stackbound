"""Thumb-2 decoding and stack-pointer abstract interpretation.

For each function this module answers two questions:

  1. how many bytes of stack the function itself can have allocated at any
     point, and
  2. at every call site, how many bytes were already allocated when the call
     was made.

The second number is what makes the whole-program bound tight.  Using the
function's maximum depth at every call site would be sound but pessimistic: a
function that allocates 512 bytes for a buffer *after* it has finished calling
its children never holds both at once.

The analysis is a forward fixpoint over the intra-procedural control flow graph.
It refuses rather than guesses: any instruction that writes SP in a way this
module does not model sets a flag on the function, and the analysis falls back
to a bound that is sound under any control flow (the sum of every stack
allocation in the function).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from capstone.arm_const import (
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_OP_REG,
    ARM_REG_LR,
    ARM_REG_PC,
    ARM_REG_SP,
)

from .elfinfo import ElfInfo, Function

_CC_SUFFIXES = (
    "eq",
    "ne",
    "cs",
    "hs",
    "cc",
    "lo",
    "mi",
    "pl",
    "vs",
    "vc",
    "hi",
    "ls",
    "ge",
    "lt",
    "gt",
    "le",
)


@dataclass
class CallSite:
    addr: int
    kind: str  # "direct" | "indirect" | "tail_direct" | "tail_indirect"
    sp_depth: int  # bytes already on the stack when the call happens
    target: int | None = None  # for direct calls
    reg: str | None = None  # for indirect calls, the register branched to

    @property
    def is_indirect(self) -> bool:
        return self.kind in ("indirect", "tail_indirect")


@dataclass
class FunctionAnalysis:
    fn: Function
    local_max: int = 0  # deepest own allocation, bytes
    calls: list[CallSite] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    insns: list[object] = field(default_factory=list)
    depth_at: dict[int, int] = field(default_factory=dict)
    unbounded: bool = False  # dynamic stack allocation
    unreached: list[int] = field(default_factory=list)
    succs: dict[int, list[int]] = field(default_factory=dict)
    conditional: set[int] = field(default_factory=set)

    @property
    def conservative(self) -> bool:
        return bool(
            self.flags
            & {"incomplete_cfg", "unhandled_sp_write", "inconsistent_sp", "decode_unstable"}
        )


def _disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return md


def _reg_bytes(insn, name: str) -> int:
    """Stack bytes moved by a push/pop style instruction."""
    total = 0
    for op in insn.operands:
        if op.type != ARM_OP_REG:
            continue
        rn = insn.reg_name(op.reg) or ""
        if rn == "sp" and name in ("stmdb", "ldm", "ldmia", "stm"):
            continue  # the base register, not part of the register list
        total += 8 if rn.startswith("d") else 4
    return total


def sp_delta(insn) -> tuple[int, bool]:
    """Return ``(bytes_allocated, understood)``.

    Positive means the instruction *grows* the stack (SP decreases).  The second
    element is False when the instruction writes SP in a way we do not model —
    the caller must then treat the function conservatively.
    """
    try:
        _, written = insn.regs_access()
    except capstone.CsError:  # pragma: no cover - capstone build without access info
        written = []
    if ARM_REG_SP not in written:
        return 0, True

    m = insn.mnemonic.split(".")[0].lower()
    ops = insn.operands

    if m in ("push", "vpush"):
        return _reg_bytes(insn, m), True
    if m in ("pop", "vpop"):
        return -_reg_bytes(insn, m), True
    if m in ("stmdb", "stmfd"):
        return _reg_bytes(insn, "stmdb"), True
    if m in ("ldm", "ldmia", "ldmfd"):
        return -_reg_bytes(insn, "ldm"), True

    if m in ("sub", "subs", "subw", "add", "adds", "addw"):
        sign = 1 if m.startswith("sub") else -1
        last = ops[-1] if ops else None
        if last is not None and last.type == ARM_OP_IMM:
            return sign * int(last.imm), True
        return 0, False  # sub sp, sp, rN -> dynamic

    if m in ("str", "strd", "ldr", "ldrd"):
        # SP-based access with writeback, in either indexing form:
        #   pre-index   str r0, [sp, #-4]!   SP -= 4   -> allocates
        #   post-index  ldr pc, [sp], #4     SP += 4   -> deallocates
        for op in ops:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_SP:
                disp = int(op.mem.disp)
                if disp:
                    return -disp, True
                for other in ops:
                    if other.type == ARM_OP_IMM:
                        return -int(other.imm), True
                return 0, False
        return 0, False

    return 0, False  # mov sp, rN and anything else


def _branch_target(insn) -> int | None:
    for op in insn.operands:
        if op.type == ARM_OP_IMM:
            return int(op.imm)
    return None


def _classify(insn) -> tuple[str, int | None, str | None]:
    """Return ``(kind, target, reg)`` where kind is one of
    call / icall / jump / cjump / ret / exit / tbranch / normal."""
    m = insn.mnemonic.lower()
    base = m.split(".")[0]

    if base == "bl":
        return "call", _branch_target(insn), None
    if base == "blx":
        for op in insn.operands:
            if op.type == ARM_OP_REG:
                return "icall", None, insn.reg_name(op.reg)
        return "call", _branch_target(insn), None
    if base == "bx":
        for op in insn.operands:
            if op.type == ARM_OP_REG:
                if op.reg == ARM_REG_LR:
                    return "ret", None, None
                return "ibranch", None, insn.reg_name(op.reg)
        return "ret", None, None
    if base in ("tbb", "tbh"):
        return "tbranch", None, None
    if base in ("pop", "ldm", "ldmia"):
        for op in insn.operands:
            if op.type == ARM_OP_REG and op.reg == ARM_REG_PC:
                return "ret", None, None
        return "normal", None, None
    if base == "ldr":
        loads_pc = any(op.type == ARM_OP_REG and op.reg == ARM_REG_PC for op in insn.operands)
        if loads_pc:
            from_stack = any(
                op.type == ARM_OP_MEM and op.mem.base == ARM_REG_SP for op in insn.operands
            )
            return ("ret" if from_stack else "ibranch"), None, None
        return "normal", None, None
    if base in ("cbz", "cbnz"):
        return "cjump", _branch_target(insn), None
    if base.startswith("b") and base != "bkpt" and base != "bic":
        rest = base[1:]
        if rest == "":
            return "jump", _branch_target(insn), None
        if rest in _CC_SUFFIXES:
            return "cjump", _branch_target(insn), None
    return "normal", None, None


def _it_mask(insns: list[object]) -> set[int]:
    """Addresses of instructions that execute conditionally inside an IT block."""
    conditional: set[int] = set()
    pending = 0
    for insn in insns:
        if pending > 0:
            conditional.add(insn.address)
            pending -= 1
            continue
        m = insn.mnemonic.lower().split(".")[0]
        if m.startswith("it") and set(m[1:]) <= {"t", "e"}:
            pending = len(m) - 1
    return conditional


def _literal_width(insn) -> int:
    """Bytes a PC-relative load takes out of the literal pool.

    ``ldrd`` is always two words.  ``vldr`` depends on the destination register:
    ``vldr d0, [pc, #n]`` loads eight bytes, ``vldr s0, [pc, #n]`` only four.
    Claiming eight for the single-precision form would hide the four bytes after
    the literal, and a real 32-bit instruction sitting there would be skipped.
    """
    mnemonic = insn.mnemonic.lower()
    if mnemonic.startswith("ldrd"):
        return 8
    if mnemonic.startswith("vldr"):
        ops = insn.operands
        dst = ops[0] if ops else None
        if dst is not None and dst.type == ARM_OP_REG:
            name = insn.reg_name(dst.reg) or ""
            return 8 if name.startswith("d") else 4
    return 4


def _literal_ranges(insns) -> list[tuple[int, int]]:
    """Byte ranges inside a function that hold literal-pool data, not code.

    GCC places constant pools between or after functions and sometimes inside
    them.  Disassembling a pool produces nonsense instructions; if one of them
    happens to write SP the whole analysis is corrupted, so pools are located
    and removed before anything is interpreted.
    """
    ranges: list[tuple[int, int]] = []
    for insn in insns:
        for op in insn.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                base = (insn.address + 4) & ~3
                lit = base + int(op.mem.disp)
                ranges.append((lit, lit + _literal_width(insn)))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _decode(md, fn: Function, data: list[tuple[int, int]]) -> list[object]:
    """Disassemble a function, skipping known data ranges."""
    insns: list[object] = []
    pos = fn.addr
    while pos < fn.end:
        starts = [s for (s, _) in data if s >= pos]
        nxt = min(starts) if starts else fn.end
        nxt = min(nxt, fn.end)
        if nxt > pos:
            chunk = fn.code[pos - fn.addr : nxt - fn.addr]
            insns.extend(md.disasm(chunk, pos))
        ends = [e for (s, e) in data if s == nxt]
        pos = max(ends) if ends else fn.end
    return insns


def _decode_stable(md, fn: Function) -> tuple[list[object], list[tuple[int, int]], bool]:
    """Decode, find pools, decode again until the pool set stops changing.

    The third element says whether the pool set actually converged.  When it did
    not, the decode is one of a sequence that never settled and the instructions
    returned are not trustworthy, so the caller must treat the function
    conservatively rather than quietly using the last iteration.
    """
    data: list[tuple[int, int]] = []
    insns = _decode(md, fn, data)
    stable = False
    for _ in range(3):
        found = [r for r in _literal_ranges(insns) if fn.addr <= r[0] < fn.end]
        if found == data:
            stable = True
            break
        data = found
        insns = _decode(md, fn, data)
    return insns, data, stable


def analyse_function(elf: ElfInfo, fn: Function) -> FunctionAnalysis:
    md = _disassembler()
    insns, _pools, stable = _decode_stable(md, fn)
    res = FunctionAnalysis(fn=fn, insns=insns)
    if not stable:
        res.flags.add("decode_unstable")

    if not insns:
        res.flags.add("no_code")
        return res

    by_addr = {i.address: i for i in insns}
    order = [i.address for i in insns]
    index = {a: k for k, a in enumerate(order)}
    conditional = _it_mask(insns)
    res.conditional = conditional

    # Sound fallback used when the CFG cannot be trusted: assume every stack
    # allocation in the function is live at the same time.
    total_alloc = 0
    for insn in insns:
        delta, ok = sp_delta(insn)
        if not ok:
            res.flags.add("unhandled_sp_write")
            m = insn.mnemonic.lower().split(".")[0]
            if m == "mov":
                # mov sp, rN: the new SP comes from a register whose value this
                # analysis does not have.  GCC's frame-pointer epilogue looks
                # exactly like this, which is why the flag names the form.
                res.flags.add("sp_from_register")
                res.unbounded = True
            elif m in ("sub", "subs", "subw"):
                res.flags.add("dynamic_allocation")
                res.unbounded = True
        if delta > 0:
            total_alloc += delta

    # ---- forward fixpoint over the CFG ---------------------------------
    depth_in: dict[int, int] = {fn.addr: 0}
    work = [fn.addr]
    seen: set[int] = set()
    local_max = 0

    while work:
        addr = work.pop()
        insn = by_addr.get(addr)
        if insn is None:
            continue
        seen.add(addr)
        depth = depth_in[addr]
        local_max = max(local_max, depth)

        delta, ok = sp_delta(insn)
        after = depth + (delta if ok else 0)
        local_max = max(local_max, after)

        kind, target, reg = _classify(insn)
        if kind in ("call", "icall", "ibranch", "jump", "cjump", "tbranch"):
            res.depth_at[addr] = depth

        succs: list[int] = []
        k = index[addr]
        fallthrough = order[k + 1] if k + 1 < len(order) else None
        is_cond = addr in conditional

        if kind in ("normal", "call", "icall"):
            if fallthrough is not None:
                succs.append(fallthrough)
        elif kind == "cjump":
            if target is not None and fn.addr <= target < fn.end:
                succs.append(target)
            if fallthrough is not None:
                succs.append(fallthrough)
        elif kind == "jump":
            if target is not None and fn.addr <= target < fn.end:
                succs.append(target)
            if is_cond and fallthrough is not None:
                succs.append(fallthrough)
        elif kind in ("ret", "ibranch"):
            if is_cond and fallthrough is not None:
                succs.append(fallthrough)
        elif kind == "tbranch":
            res.flags.add("incomplete_cfg")
            if fallthrough is not None:
                succs.append(fallthrough)

        res.succs[addr] = [s for s in succs if s in by_addr]
        for s in succs:
            if s not in by_addr:
                continue
            prev = depth_in.get(s)
            if prev is None:
                depth_in[s] = after
                work.append(s)
            elif prev != after:
                if after > prev:
                    depth_in[s] = after
                    work.append(s)
                res.flags.add("inconsistent_sp")

    # Alignment padding between the last instruction and a literal pool is
    # unreachable by construction and must not be mistaken for lost control flow.
    unreached = [
        i for i in insns if i.address not in seen and i.mnemonic.split(".")[0].lower() != "nop"
    ]
    if unreached:
        res.flags.add("incomplete_cfg")
        res.unreached = [i.address for i in unreached]

    # ---- call sites ------------------------------------------------------
    for insn in insns:
        kind, target, reg = _classify(insn)
        depth = res.depth_at.get(insn.address)
        if depth is None:
            depth = total_alloc  # unreached instruction: be conservative
        if res.conservative:
            depth = max(depth, total_alloc)

        if kind == "call" and target is not None:
            res.calls.append(CallSite(insn.address, "direct", depth, target=target))
        elif kind == "icall":
            res.calls.append(CallSite(insn.address, "indirect", depth, reg=reg))
        elif kind == "jump" and target is not None and not (fn.addr <= target < fn.end):
            res.calls.append(CallSite(insn.address, "tail_direct", depth, target=target))
        elif kind == "ibranch" and reg is not None:
            res.calls.append(CallSite(insn.address, "tail_indirect", depth, reg=reg))

    res.local_max = max(local_max, total_alloc) if res.conservative else local_max
    return res


def analyse_all(elf: ElfInfo) -> dict[int, FunctionAnalysis]:
    return {addr: analyse_function(elf, fn) for addr, fn in elf.functions.items()}
