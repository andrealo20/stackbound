"""ELF and DWARF front end.

Everything stackbound knows about a firmware image comes from here: the code
bytes of each function, the contents of read-only data, the vector table, the
DWARF type of every global, and the set of functions whose address appears
anywhere in the image.

Nothing in this module reasons about stack depth; it only answers questions
about the binary.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile


@dataclass
class Function:
    """A function symbol.  ``addr`` always has the Thumb bit cleared."""

    name: str
    addr: int
    size: int
    code: bytes = b""

    @property
    def end(self) -> int:
        return self.addr + self.size


@dataclass
class GlobalVar:
    name: str
    addr: int
    size: int
    readonly: bool
    type_str: str | None = None  # canonical type, e.g. "u32(*)(u32)"
    elem_type_str: str | None = None  # for arrays: the element type


@dataclass
class Section:
    name: str
    addr: int
    data: bytes
    writable: bool
    executable: bool
    alloc: bool

    @property
    def end(self) -> int:
        return self.addr + len(self.data)


# --------------------------------------------------------------------------
# DWARF type canonicalisation
# --------------------------------------------------------------------------
#
# Two functions have the same signature if and only if their canonical strings
# are equal.  The canonical form deliberately drops typedefs, const and
# volatile, because none of them affect which function a pointer may point to:
# `typedef uint32_t u32; u32 f(u32)` and `unsigned int f(unsigned int)` are the
# same target for an indirect call.


def _strip(die):
    """Follow typedef / const / volatile wrappers to the underlying type DIE."""
    seen = 0
    while die is not None and die.tag in (
        "DW_TAG_typedef",
        "DW_TAG_const_type",
        "DW_TAG_volatile_type",
        "DW_TAG_restrict_type",
    ):
        seen += 1
        if seen > 32:  # pathological or cyclic debug info
            return None
        die = _type_of(die)
    return die


def _type_of(die):
    attr = die.attributes.get("DW_AT_type")
    if attr is None:
        return None
    try:
        return die.get_DIE_from_attribute("DW_AT_type")
    except (AttributeError, KeyError):
        return None


def canonical_type(die) -> str:
    """Canonical string for a DWARF type DIE.  ``None`` means C ``void``."""
    die = _strip(die)
    if die is None:
        return "void"

    tag = die.tag
    if tag == "DW_TAG_base_type":
        name = die.attributes.get("DW_AT_name")
        size = die.attributes.get("DW_AT_byte_size")
        base = name.value.decode() if name else "?"
        return f"{base}:{size.value if size else '?'}"

    if tag == "DW_TAG_pointer_type":
        return canonical_type(_type_of(die)) + "*"

    if tag == "DW_TAG_array_type":
        return canonical_type(_type_of(die)) + "[]"

    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
        name = die.attributes.get("DW_AT_name")
        kind = tag.replace("DW_TAG_", "").replace("_type", "")
        return f"{kind} {name.value.decode() if name else '<anon>'}"

    if tag == "DW_TAG_subroutine_type":
        return _signature(die)

    return tag.replace("DW_TAG_", "")


def _signature(die) -> str:
    """Canonical signature of a subprogram or subroutine type DIE."""
    ret = canonical_type(_type_of(die))
    params: list[str] = []
    variadic = False
    for child in die.iter_children():
        if child.tag == "DW_TAG_formal_parameter":
            params.append(canonical_type(_type_of(child)))
        elif child.tag == "DW_TAG_unspecified_parameters":
            variadic = True
    if variadic:
        params.append("...")
    return f"{ret}({','.join(params) if params else 'void'})"


def _const_addr(die) -> int | None:
    """Static address of a variable, if its location is a plain DW_OP_addr."""
    loc = die.attributes.get("DW_AT_location")
    if loc is None:
        return None
    expr = loc.value
    if isinstance(expr, list) and len(expr) == 5 and expr[0] == 0x03:  # DW_OP_addr
        return struct.unpack("<I", bytes(expr[1:5]))[0]
    return None


# --------------------------------------------------------------------------


class ElfInfo:
    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "rb")
        try:
            self.elf = ELFFile(self._fh)

            self.sections: list[Section] = []
            self.functions: dict[int, Function] = {}  # addr (even) -> Function
            self.by_name: dict[str, Function] = {}
            self.globals: dict[int, GlobalVar] = {}  # addr -> GlobalVar
            self.signatures: dict[str, str] = {}  # function name -> signature
            self.address_taken: set[int] = set()
            self.taken_by_vectors: set[int] = set()
            self.taken_by_code: set[int] = set()
            self.entry = self.elf.header["e_entry"] & ~1

            self._load_sections()
            self._load_symbols()
            self._load_dwarf()
            self._scan_address_taken()
        except Exception:
            self._fh.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # -- sections ---------------------------------------------------------
    def _load_sections(self) -> None:
        for sec in self.elf.iter_sections():
            flags = sec["sh_flags"]
            if not (flags & SH_FLAGS.SHF_ALLOC):
                continue
            data = b"" if sec["sh_type"] == "SHT_NOBITS" else sec.data()
            self.sections.append(
                Section(
                    name=sec.name,
                    addr=sec["sh_addr"],
                    data=data,
                    writable=bool(flags & SH_FLAGS.SHF_WRITE),
                    executable=bool(flags & SH_FLAGS.SHF_EXECINSTR),
                    alloc=True,
                )
            )

    def section_at(self, addr: int) -> Section | None:
        for sec in self.sections:
            if sec.addr <= addr < sec.end:
                return sec
        return None

    def read_bytes(self, addr: int, n: int) -> bytes | None:
        sec = self.section_at(addr)
        if sec is None or not sec.data:
            return None
        off = addr - sec.addr
        if off + n > len(sec.data):
            return None
        return sec.data[off : off + n]

    def read_word(self, addr: int) -> int | None:
        raw = self.read_bytes(addr, 4)
        return None if raw is None else struct.unpack("<I", raw)[0]

    def is_readonly(self, addr: int) -> bool:
        sec = self.section_at(addr)
        return sec is not None and not sec.writable

    # -- symbols ----------------------------------------------------------
    def _load_symbols(self) -> None:
        symtab = self.elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError(f"{self.path}: no .symtab (build with -g, do not strip)")

        self.symbol_values: dict[str, int] = {}
        self._weak: dict[int, bool] = {}
        for sym in symtab.iter_symbols():
            info = sym["st_info"]
            value = sym["st_value"]
            name = sym.name
            if not name:
                continue
            self.symbol_values.setdefault(name, value)

            if info["type"] == "STT_FUNC":
                addr = value & ~1  # ARM sets bit 0 on Thumb function symbols
                size = sym["st_size"]
                if size == 0:
                    continue
                existing = self.functions.get(addr)
                if existing is None:
                    self._weak[addr] = info["bind"] != "STB_GLOBAL"
                    fn = Function(name=name, addr=addr, size=size)
                    self.functions[addr] = fn
                    self.by_name[name] = fn
                else:
                    # Aliases (weak handler symbols) share an address.  Report
                    # the strong name, but make every alias resolvable.
                    if info["bind"] == "STB_GLOBAL" and self._weak.get(existing.addr, True):
                        existing.name = name
                        self._weak[existing.addr] = False
                    self.by_name[name] = existing

            elif info["type"] == "STT_OBJECT" and sym["st_size"] > 0:
                self.globals[value] = GlobalVar(
                    name=name,
                    addr=value,
                    size=sym["st_size"],
                    readonly=self.is_readonly(value),
                )

        for fn in self.functions.values():
            fn.code = self.read_bytes(fn.addr, fn.size) or b""

    def function_at(self, addr: int) -> Function | None:
        addr &= ~1
        fn = self.functions.get(addr)
        if fn is not None:
            return fn
        for f in self.functions.values():
            if f.addr <= addr < f.end:
                return f
        return None

    # -- DWARF ------------------------------------------------------------
    def _load_dwarf(self) -> None:
        if not self.elf.has_dwarf_info():
            return
        dwarf = self.elf.get_dwarf_info()
        for cu in dwarf.iter_CUs():
            try:
                dies = list(cu.iter_DIEs())
            except (AttributeError, KeyError, ValueError):
                # Skip CUs with malformed DWARF
                continue
            for die in dies:
                if die.tag == "DW_TAG_subprogram" and "DW_AT_low_pc" in die.attributes:
                    name = die.attributes.get("DW_AT_name")
                    if name is not None:
                        self.signatures[name.value.decode()] = _signature(die)
                elif die.tag == "DW_TAG_variable":
                    addr = _const_addr(die)
                    if addr is None:
                        continue
                    gv = self.globals.get(addr)
                    if gv is None:
                        continue
                    tdie = _strip(_type_of(die))
                    gv.type_str = canonical_type(tdie)
                    if tdie is not None and tdie.tag == "DW_TAG_array_type":
                        gv.elem_type_str = canonical_type(_type_of(tdie))

    def pointee_signature(self, type_str: str | None) -> str | None:
        """If ``type_str`` is a pointer to a function, return the signature."""
        if not type_str or not type_str.endswith("*"):
            return None
        inner = type_str[:-1]
        return inner if "(" in inner and inner.endswith(")") else None

    # -- address-taken ----------------------------------------------------
    def _scan_address_taken(self) -> None:
        """Any 32-bit word in an allocated section that equals ``f | 1`` for a
        known function ``f`` is treated as taking that function's address.

        This over-approximates: an unrelated constant can collide with a
        function address.  Over-approximating is the safe direction here — it
        can only add candidates to an indirect call, never remove one.
        """
        starts = set(self.functions.keys())
        for sec in self.sections:
            if not sec.data:
                continue
            for off in range(0, len(sec.data) - 3, 4):
                word = struct.unpack("<I", sec.data[off : off + 4])[0]
                if word & 1 and (word & ~1) in starts:
                    target = word & ~1
                    self.address_taken.add(target)
                    if sec.name == ".vectors":
                        self.taken_by_vectors.add(target)
                    else:
                        self.taken_by_code.add(target)

    @property
    def vector_only(self) -> set[int]:
        """Functions whose address appears only in the vector table.

        The vector table is read by the hardware, not by C code, so an entry
        there is evidence of an exception entry point rather than of a function
        pointer that some indirect call could load.  Excluding these from the
        "any" fallback keeps the reset handler out of every unresolved call
        site, which otherwise makes the whole call graph one giant cycle and
        every bound unbounded.

        This is a documented assumption, not a theorem: firmware that calls its
        own handlers through a pointer would violate it.  Set
        ``any_includes_vectors`` in the configuration to switch it off.
        """
        return self.taken_by_vectors - self.taken_by_code

    # -- vector table -----------------------------------------------------
    def vector_table(self) -> tuple[int, list[tuple[int, Function | None]]]:
        """Return ``(initial_sp, [(index, function), ...])``.

        Index 0 is the initial stack pointer and is returned separately; index 1
        is Reset, 2..15 are the system exceptions and 16+ are external IRQs.
        """
        sec = None
        for s in self.sections:
            if s.name == ".vectors":
                sec = s
                break
        if sec is None:
            sec = self.section_at(self.entry)
        if sec is None or len(sec.data) < 8:
            return 0, []

        initial_sp = struct.unpack("<I", sec.data[0:4])[0]
        out: list[tuple[int, Function | None]] = []
        n = min(len(sec.data) // 4, 256)
        for i in range(1, n):
            word = struct.unpack("<I", sec.data[i * 4 : i * 4 + 4])[0]
            if word == 0:
                continue
            out.append((i, self.function_at(word & ~1)))
        return initial_sp, out

    # -- stack region -----------------------------------------------------
    def stack_region(self) -> tuple[int, int] | None:
        """(bottom, top) from the _stack_bottom / _stack_top linker symbols."""
        bottom = self.symbol_values.get("_stack_bottom")
        top = self.symbol_values.get("_stack_top")
        if bottom is None or top is None or top <= bottom:
            return None
        return bottom, top

    def close(self) -> None:
        self._fh.close()
