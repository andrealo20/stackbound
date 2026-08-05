"""Whole-program bounds, and the check that matters: the bound is never below
what the hardware actually used.
"""

import os
import re
import subprocess

import pytest

from stackbound import config as config_mod
from stackbound.analyze import Options, analyse
from stackbound.elfinfo import ElfInfo

from .conftest import CASES, needs_gcc, needs_qemu

MACHINE = os.environ.get("QEMU_MACHINE", "mps2-an385")
CPU = os.environ.get("QEMU_CPU", "cortex-m3")


def _measure(elf_path):
    proc = subprocess.run(
        [
            "qemu-system-arm",
            "-M",
            MACHINE,
            "-cpu",
            CPU,
            "-nographic",
            "-semihosting-config",
            "enable=on,target=native",
            "-kernel",
            elf_path,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    m = re.search(r"measured_stack_bytes=(\d+)", proc.stdout + proc.stderr)
    assert m, f"no measurement:\n{proc.stdout}\n{proc.stderr}"
    return int(m.group(1))


def _analyse(elf_path, cfg_path=None, **kw):
    opts = Options(**kw)
    if cfg_path and os.path.exists(cfg_path):
        opts = config_mod.to_options(config_mod.load(cfg_path), opts)
    return analyse(ElfInfo(elf_path), opts)


@needs_gcc
def test_bound_is_the_sum_along_the_worst_path(firmware, configs):
    """Hand-derived from the disassembly of direct.elf:

    Reset_Handler   8 at the call to app_run
    app_run         8 at the call to level_a
    level_a       136 at the call to level_b
    level_b       264 at the call to level_c
    level_c        72 at the call to sb_consume
    sb_consume      4 of its own

    8 + 8 + 136 + 264 + 72 + 4 = 492
    """
    r = _analyse(firmware["direct"], configs["direct"])
    assert r.thread_bound == 492
    assert r.worst_path == [
        "Reset_Handler",
        "app_run",
        "level_a",
        "level_b",
        "level_c",
        "sb_consume",
    ]


@needs_gcc
def test_recursion_without_a_stated_depth_is_unbounded(firmware):
    r = _analyse(firmware["recursion"])
    assert r.unbounded, "a cycle with no annotation must not produce a number"
    assert "descend" in r.unbounded


@needs_gcc
def test_recursion_with_a_stated_depth_is_bounded(firmware, configs):
    r = _analyse(firmware["recursion"], configs["recursion"])
    assert not r.unbounded
    assert r.total > 0


@needs_gcc
def test_deeper_recursion_costs_more(firmware, configs):
    cfg = config_mod.load(configs["recursion"])
    shallow = dict(cfg)
    shallow["recursion"] = {"descend": 2, "ping": 2, "pong": 2}
    deep = dict(cfg)
    deep["recursion"] = {"descend": 20, "ping": 2, "pong": 2}

    a = analyse(ElfInfo(firmware["recursion"]), config_mod.to_options(shallow, Options()))
    b = analyse(ElfInfo(firmware["recursion"]), config_mod.to_options(deep, Options()))
    assert b.total > a.total


@needs_gcc
def test_exception_bound_needs_the_configuration(firmware, configs):
    """Without a configuration every vector slot is assumed live, which is
    sound and pessimistic.  The configuration is what makes it tight."""
    loose = _analyse(firmware["isr_nesting"])
    tight = _analyse(firmware["isr_nesting"], configs["isr_nesting"])
    assert loose.exception_bound > tight.exception_bound


@needs_gcc
@needs_qemu
@pytest.mark.parametrize("case", CASES)
def test_bound_is_never_below_the_measured_watermark(case, firmware, configs):
    measured = _measure(firmware[case])
    r = _analyse(firmware[case], configs[case])
    assert not r.unbounded, f"{case} reported unbounded"
    assert r.total >= measured, (
        f"{case}: bound {r.total} is below the measured watermark {measured}"
    )


@needs_gcc
@needs_qemu
def test_ignoring_exceptions_under_reports_a_real_firmware(firmware, configs):
    """The claim the project exists to make, as an executable check."""
    measured = _measure(firmware["isr_nesting"])
    naive = _analyse(firmware["isr_nesting"], configs["isr_nesting"], exceptions=False)
    full = _analyse(firmware["isr_nesting"], configs["isr_nesting"])
    assert naive.total < measured, "the naive bound should be unsound here"
    assert full.total >= measured


@needs_gcc
@needs_qemu
@pytest.mark.parametrize("case", ["table", "global_fp"])
def test_ignoring_indirect_calls_under_reports(case, firmware, configs):
    measured = _measure(firmware[case])
    naive = _analyse(firmware[case], configs[case], indirect_mode="none")
    assert naive.total < measured
