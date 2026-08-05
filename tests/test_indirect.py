"""Indirect resolution tests.

Each tier makes a claim that can be falsified by naming a function that must be
in the candidate set and one that must not.
"""

from stackbound.analyze import Options, analyse
from stackbound.elfinfo import ElfInfo
from stackbound.indirect import IndirectResolver
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
