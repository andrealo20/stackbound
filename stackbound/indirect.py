"""Resolution of indirect calls.

Free stack analysers stop at `blx r3`.  This module tries four things in order
and records which one succeeded, so the precision of the result is measurable
rather than asserted:

  1. **literal** — the pointer is a constant from the literal pool.  One target,
     exactly.
  2. **table** — the pointer was loaded from an object in a read-only section.
     The contents are fixed at link time, so the candidate set is read straight
     out of the image.  Exact, even when the index is unknown.
  3. **typed** — the pointer was loaded from a mutable object whose DWARF type
     is a pointer to a function.  Candidates are the address-taken functions
     whose signature matches.
  4. **any** — nothing is known.  Candidates are every address-taken function
     in the image.  Sound, and usually expensive.

Tiers 1 and 2 are exact; tier 3 is an over-approximation limited by the type
system; tier 4 is the fallback every free tool would have to use everywhere.

The pointer value is recovered by a forward dataflow over the function's control
flow graph, with a meet at join points: a register keeps its value only if every
predecessor agrees on it.  That is what lets a table base register loaded before
a loop still be known at a call site inside the loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from capstone.arm_const import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP

from .elfinfo import ElfInfo, GlobalVar
from .thumb import CallSite, FunctionAnalysis

logger = logging.getLogger(__name__)

TIERS = ("literal", "table", "typed", "any", "manual")


# ---- abstract values -----------------------------------------------------


@dataclass(frozen=True)
class Const:
    value: int


@dataclass(frozen=True)
class SymAddr:
    """Address of a static object (or function), plus a constant offset."""

    addr: int
    off: int = 0


@dataclass(frozen=True)
class Load:
    """Value loaded from a static object; ``off`` is None if the index is unknown."""

    base: int
    off: int | None


class _Unknown:
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
        return cls._inst

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNKNOWN"


UNKNOWN = _Unknown()
Value = Const | SymAddr | Load | _Unknown


def _meet(a: Value, b: Value) -> Value:
    return a if a == b else UNKNOWN


@dataclass
class Resolution:
    site: CallSite
    tier: str
    targets: list[int]
    detail: str = ""

    @property
    def exact(self) -> bool:
        return self.tier in ("literal", "table", "manual")


class IndirectResolver:
    def __init__(
        self,
        elf: ElfInfo,
        manual: dict[int, list[str]] | None = None,
        any_includes_vectors: bool = False,
    ):
        self.elf = elf
        self.manual = manual or {}
        excluded = set() if any_includes_vectors else elf.vector_only
        #: every function an unresolved indirect call could reach
        self.candidates = sorted(elf.address_taken - excluded)
        # signature -> matching address-taken functions
        self._by_sig: dict[str, list[int]] = {}
        for addr in self.candidates:
            fn = elf.functions[addr]
            sig = elf.signatures.get(fn.name)
            if sig:
                self._by_sig.setdefault(sig, []).append(addr)

    # -- dataflow ---------------------------------------------------------
    def _propagate(self, fa: FunctionAnalysis) -> dict[int, dict[int, Value]]:
        """Register state on entry to each instruction."""
        insns = {i.address: i for i in fa.insns}
        if not insns:
            return {}
        entry = fa.fn.addr
        preds: dict[int, list[int]] = {a: [] for a in insns}
        for a, ss in fa.succs.items():
            for s in ss:
                preds.setdefault(s, []).append(a)

        state_in: dict[int, dict[int, Value]] = {entry: {}}
        work = [entry]
        guard = 0
        while work and guard < 20000:
            guard += 1
            addr = work.pop()
            insn = insns.get(addr)
            if insn is None:
                continue
            out = self._transfer(insn, dict(state_in.get(addr, {})), fa)
            for s in fa.succs.get(addr, []):
                if s not in insns:
                    continue
                if s not in state_in:
                    state_in[s] = dict(out)
                    work.append(s)
                else:
                    merged = {}
                    old = state_in[s]
                    for reg in set(old) | set(out):
                        merged[reg] = _meet(old.get(reg, UNKNOWN), out.get(reg, UNKNOWN))
                    merged = {r: v for r, v in merged.items() if v is not UNKNOWN}
                    if merged != old:
                        state_in[s] = merged
                        work.append(s)
        if work and guard >= 20000:
            logger.warning(
                f"Dataflow analysis did not converge for {fa.fn.name} after {guard} iterations; "
                "indirect call resolution may be incomplete"
            )
        return state_in

    def _transfer(self, insn, state: dict[int, Value], fa: FunctionAnalysis) -> dict[int, Value]:
        m = insn.mnemonic.lower().split(".")[0]
        ops = insn.operands
        conditional = insn.address in fa.conditional

        def assign(reg: int, value: Value) -> None:
            if conditional:
                value = _meet(state.get(reg, UNKNOWN), value)
            if value is UNKNOWN:
                state.pop(reg, None)
            else:
                state[reg] = value

        try:
            _, written = insn.regs_access()
        except Exception:
            written = []

        if m == "ldr" and len(ops) >= 2 and ops[0].type == ARM_OP_REG:
            dst = ops[0].reg
            if ops[1].type == ARM_OP_MEM:
                mem = ops[1].mem
                if mem.base == ARM_REG_PC:
                    lit = ((insn.address + 4) & ~3) + int(mem.disp)
                    word = self.elf.read_word(lit)
                    if word is None:
                        assign(dst, UNKNOWN)
                    elif self.elf.globals.get(word) is not None or self.elf.section_at(word):
                        assign(dst, SymAddr(word))
                    else:
                        assign(dst, Const(word))
                    return state
                if mem.base != ARM_REG_SP:
                    base = state.get(mem.base, UNKNOWN)
                    if isinstance(base, SymAddr):
                        if mem.index == 0:
                            assign(dst, Load(base.addr, base.off + int(mem.disp)))
                        else:
                            assign(dst, Load(base.addr, None))
                        return state
            assign(dst, UNKNOWN)
            return state

        if m in ("mov", "movs") and len(ops) == 2 and ops[0].type == ARM_OP_REG:
            if ops[1].type == ARM_OP_REG:
                assign(ops[0].reg, state.get(ops[1].reg, UNKNOWN))
            elif ops[1].type == ARM_OP_IMM:
                assign(ops[0].reg, Const(int(ops[1].imm)))
            else:
                assign(ops[0].reg, UNKNOWN)
            return state

        if m in ("add", "adds", "addw") and len(ops) == 3 and ops[2].type == ARM_OP_IMM:
            base = state.get(ops[1].reg, UNKNOWN) if ops[1].type == ARM_OP_REG else UNKNOWN
            if isinstance(base, SymAddr):
                assign(ops[0].reg, SymAddr(base.addr, base.off + int(ops[2].imm)))
            else:
                assign(ops[0].reg, UNKNOWN)
            return state

        for reg in written:
            assign(reg, UNKNOWN)
        return state

    # -- resolution -------------------------------------------------------
    def _object_at(self, addr: int) -> GlobalVar | None:
        for gv in self.elf.globals.values():
            if gv.addr <= addr < gv.addr + gv.size:
                return gv
        return None

    def _functions_in(self, addr: int, size: int) -> list[int]:
        out: list[int] = []
        for off in range(0, size, 4):
            word = self.elf.read_word(addr + off)
            if word is None:
                continue
            if word & 1 and (word & ~1) in self.elf.functions:
                out.append(word & ~1)
        return sorted(set(out))

    def _typed_candidates(self, sig: str) -> list[int]:
        return list(self._by_sig.get(sig, []))

    def resolve(self, fa: FunctionAnalysis) -> list[Resolution]:
        sites = [c for c in fa.calls if c.is_indirect]
        if not sites:
            return []
        state_in = self._propagate(fa)
        insn_by_addr = {i.address: i for i in fa.insns}

        out: list[Resolution] = []
        for site in sites:
            if site.addr in self.manual:
                targets = [
                    self.elf.by_name[n].addr
                    for n in self.manual[site.addr]
                    if n in self.elf.by_name
                ]
                out.append(Resolution(site, "manual", sorted(set(targets)), "from config"))
                continue

            insn = insn_by_addr.get(site.addr)
            reg = None
            if insn is not None:
                for op in insn.operands:
                    if op.type == ARM_OP_REG:
                        reg = op.reg
                        break
            value = state_in.get(site.addr, {}).get(reg, UNKNOWN) if reg is not None else UNKNOWN
            out.append(self._classify(site, value))
        return out

    def _classify(self, site: CallSite, value: Value) -> Resolution:
        # tier 1: a constant pointer
        if isinstance(value, Const) and (value.value & ~1) in self.elf.functions:
            return Resolution(site, "literal", [value.value & ~1], "constant pointer")
        if isinstance(value, SymAddr) and value.off == 0:
            if (value.addr & ~1) in self.elf.functions:
                return Resolution(site, "literal", [value.addr & ~1], "constant pointer")

        if isinstance(value, Load):
            gv = self._object_at(value.base)
            if gv is not None and gv.readonly:
                # tier 2: contents fixed at link time
                if value.off is not None and 0 <= value.off < gv.size:
                    word = self.elf.read_word(gv.addr + value.off)
                    if word is not None and (word & ~1) in self.elf.functions:
                        return Resolution(
                            site, "table", [word & ~1], f"{gv.name}[{value.off // 4}]"
                        )
                targets = self._functions_in(gv.addr, gv.size)
                if targets:
                    return Resolution(
                        site, "table", targets, f"contents of const {gv.name}[{gv.size // 4}]"
                    )
            if gv is not None:
                # tier 3: type of the object it was loaded from
                type_str = gv.elem_type_str or gv.type_str
                sig = self.elf.pointee_signature(type_str)
                if sig:
                    targets = self._typed_candidates(sig)
                    if targets:
                        return Resolution(site, "typed", targets, f"type of {gv.name}: {sig}")

        # tier 4: sound fallback
        return Resolution(
            site, "any", list(self.candidates), "unknown pointer: all address-taken functions"
        )
