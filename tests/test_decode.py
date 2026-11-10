"""Decoder tests.

The expected numbers here were computed by hand from the disassembly, not by
running the tool and writing down what it said.  Each one is reproducible:

    arm-none-eabi-objdump -d firmware/build/direct.elf

``level_a`` starts with ``push {r4, lr}`` (8 bytes) and ``sub sp, #128``, so 136
bytes are in use when it calls ``level_b``.  ``level_b`` pushes 8 and subtracts
256, so 264.  ``level_c`` pushes 4 (``push {lr}``) and subtracts 68, so 72.
"""

import struct

import pytest
from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

from stackbound.elfinfo import ElfInfo, Section
from stackbound.thumb import _classify, analyse_all, analyse_function

from .conftest import needs_gcc

EXPECTED_LOCAL = {
    "level_a": 136,
    "level_b": 264,
    "level_c": 72,
    "shallow": 24,
}


@needs_gcc
def test_local_frames_match_disassembly(firmware):
    elf = ElfInfo(firmware["direct"])
    for name, expected in EXPECTED_LOCAL.items():
        fa = analyse_function(elf, elf.by_name[name])
        assert fa.local_max == expected, name


@needs_gcc
def test_call_site_depth_is_not_the_function_maximum(firmware):
    """level_b allocates 264 bytes and calls level_c while holding all of it."""
    elf = ElfInfo(firmware["direct"])
    fa = analyse_function(elf, elf.by_name["level_b"])
    depths = sorted({c.sp_depth for c in fa.calls})
    assert depths == [264]


@needs_gcc
def test_no_function_is_flagged_in_the_benchmark(firmware):
    """Every benchmark ELF must decode cleanly.

    A flag here does not mean the bound is wrong, flagged functions fall back
    to a sound over-approximation, but it does mean the tool stopped
    understanding the code, and on this corpus that should not happen.
    """
    for case, path in firmware.items():
        elf = ElfInfo(path)
        flagged = {fa.fn.name: sorted(fa.flags) for fa in analyse_all(elf).values() if fa.flags}
        assert flagged == {}, f"{case}: {flagged}"


@needs_gcc
def test_literal_pools_are_not_decoded_as_code(firmware):
    """A constant pool disassembles into nonsense; if any of it were executed as
    an instruction the SP tracking would be wrong.  ``app_name`` is a two
    instruction function followed by a pool."""
    elf = ElfInfo(firmware["direct"])
    fa = analyse_function(elf, elf.by_name["app_name"])
    assert fa.local_max == 0
    assert fa.flags == set()


@needs_gcc
def test_thumb_bit_is_stripped_from_symbols(firmware):
    elf = ElfInfo(firmware["direct"])
    for fn in elf.functions.values():
        assert fn.addr % 2 == 0


@needs_gcc
def test_vector_table(firmware):
    elf = ElfInfo(firmware["isr_nesting"])
    initial_sp, vectors = elf.vector_table()
    bottom, top = elf.stack_region()
    assert initial_sp == top
    by_index = {i: (fn.name if fn else None) for i, fn in vectors}
    assert by_index[1] == "Reset_Handler"
    assert by_index[16] == "IRQ0_Handler"
    assert by_index[17] == "IRQ1_Handler"
    assert by_index[18] == "IRQ2_Handler"


def _thumb(hexbytes, addr=0x1000):
    """Decode Thumb-2 machine code, for tests that need no firmware."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    md.detail = True
    return list(md.disasm(bytes.fromhex(hexbytes), addr))


def test_conditional_call_in_an_it_block_is_a_call():
    """``it ne; blne f`` is printed ``blne``: still a call, not an ordinary instruction."""
    _it, blne = _thumb("18bf 00f006f8")
    assert blne.mnemonic == "blne"
    assert _classify(blne)[0] == "call"


@pytest.mark.parametrize("code", ["00d1", "00d9", "00dd", "00db"])  # bne bls ble blt
def test_conditional_branch_is_still_a_branch(code):
    assert _classify(_thumb(code)[0])[0] == "cjump"


def _elf_with(*sections, entry=0x100):
    elf = ElfInfo.__new__(ElfInfo)
    elf.sections = list(sections)
    elf.entry = entry
    return elf


def _sec(name, words):
    return Section(name, 0, struct.pack(f"<{len(words)}I", *words), False, False, True)


def test_vector_table_found_under_the_stm32_name():
    vectors = _sec(".isr_vector", [0x20001000, 0x101, 0])
    text = _sec(".text", [0xB5104C02, 0x47984B01])
    assert _elf_with(text, vectors).vector_section() is vectors


def test_vector_table_found_by_its_reset_vector():
    text = _sec(".text", [0xB5104C02, 0x47984B01])
    vectors = _sec(".rom_start", [0x20001000, 0x101, 0])
    assert _elf_with(text, vectors).vector_section() is vectors


def test_no_vector_table_is_an_error():
    with pytest.raises(ValueError, match="vector table"):
        _elf_with(_sec(".text", [0xB5104C02, 0x47984B01])).vector_section()
