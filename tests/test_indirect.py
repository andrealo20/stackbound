"""Indirect resolution tests.

Each tier makes a claim that can be falsified by naming a function that must be
in the candidate set and one that must not.
"""

from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs
from capstone.arm_const import ARM_REG_R0, ARM_REG_R3

from stackbound.analyze import Options, analyse
from stackbound.elfinfo import ElfInfo
from stackbound.indirect import IndirectResolver, Load, SymAddr
from stackbound.thumb import analyse_all

from .conftest import needs_gcc


def _resolutions(path):
    elf = ElfInfo(path)
    resolver = IndirectResolver(elf)
    out = []
    for fa in analyse_all(elf).values():
        for r in resolver.resolve(fa):
            out.append((elf, fa.fn.name, r))
    return out


@needs_gcc
def test_const_table_is_read_exactly(firmware):
    res = _resolutions(firmware["table"])
    assert res, "no indirect call sites found"
    for elf, _fn, r in res:
        assert r.tier == "table"
        names = {elf.functions[t].name for t in r.targets}
        assert names == {"cmd_small", "cmd_medium", "cmd_large"}
        # cmd_orphan's address is taken, but it is not in the table
        assert "cmd_orphan" not in names


@needs_gcc
def test_type_matching_excludes_other_signatures(firmware):
    res = _resolutions(firmware["global_fp"])
    assert len(res) == 1
    elf, _fn, r = res[0]
    assert r.tier == "typed"
    names = {elf.functions[t].name for t in r.targets}
    assert names == {"hook_a", "hook_b"}
    assert not (names & {"decoy_ptr", "decoy_two"})


@needs_gcc
def test_parameter_falls_back_to_every_address_taken_function(firmware):
    res = _resolutions(firmware["param_fp"])
    assert len(res) == 1
    elf, _fn, r = res[0]
    assert r.tier == "any"
    names = {elf.functions[t].name for t in r.targets}
    # work_never is never passed to apply(), but nothing in the binary says so
    assert {"work_small", "work_big", "work_never"} <= names


@needs_gcc
def test_vector_only_functions_are_excluded_from_the_fallback(firmware):
    """Reset_Handler's address appears only in the vector table.  Including it
    as a possible target of every unresolved call makes the call graph cyclic
    and every bound unbounded."""
    elf = ElfInfo(firmware["param_fp"])
    assert elf.by_name["Reset_Handler"].addr in elf.vector_only
    resolver = IndirectResolver(elf)
    assert elf.by_name["Reset_Handler"].addr not in resolver.candidates

    permissive = IndirectResolver(elf, any_includes_vectors=True)
    assert elf.by_name["Reset_Handler"].addr in permissive.candidates


@needs_gcc
def test_resolution_reduces_the_bound(firmware, configs):
    """Resolving is not decoration: it has to move the number."""
    elf_path = firmware["global_fp"]
    full = analyse(ElfInfo(elf_path), Options(indirect_mode="full"))
    blind = analyse(ElfInfo(elf_path), Options(indirect_mode="any"))
    assert full.total < blind.total


def _thumb(hexbytes, addr=0x1000):
    """Decode Thumb-2 machine code, for tests that need no firmware."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return list(md.disasm(bytes.fromhex(hexbytes), addr))


TABLE = 0x2000


def _walk_table_loop():
    """``p = table; for (;;) (*p++)();`` as GCC writes it.

    1000: ldr   r4, [pc, #8]      @ r4 = table
    1002: ldr.w r3, [r4], #4      @ r3 = *p, p++
    1006: blx   r3
    1008: b     1002
    """
    insns = _thumb("024c 54f8043b 9847 fbe7")
    elf = SimpleNamespace(
        read_word=lambda addr: TABLE, globals={TABLE: object()}, section_at=lambda a: True
    )
    resolver = IndirectResolver.__new__(IndirectResolver)
    resolver.elf = elf
    fa = SimpleNamespace(
        fn=SimpleNamespace(addr=0x1000),
        insns=insns,
        succs={0x1000: [0x1002], 0x1002: [0x1006], 0x1006: [0x1008], 0x1008: [0x1002]},
        conditional=set(),
    )
    return resolver, fa


def test_post_indexed_load_moves_the_base():
    """A pointer stepped through a table reaches every entry, not just the first."""
    resolver, fa = _walk_table_loop()
    state_in, converged = resolver._propagate(fa)
    assert converged
    assert state_in[0x1006][ARM_REG_R3] == Load(TABLE, None)


def test_a_call_clobbers_the_argument_registers():
    """After ``bl`` r0 is the return value, not the argument it was given."""
    resolver, fa = _walk_table_loop()
    bl = _thumb("00f004f8")[0]
    out = resolver._transfer(bl, {ARM_REG_R0: SymAddr(TABLE)}, fa)
    assert ARM_REG_R0 not in out


def test_unknown_manual_target_is_an_error():
    elf = SimpleNamespace(by_name={"on_rx": object()})
    with pytest.raises(ValueError, match="on_rxx"):
        IndirectResolver(elf, manual={0x1C42: ["on_rx", "on_rxx"]})
