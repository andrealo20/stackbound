#!/usr/bin/env python3
"""Measure every benchmark case and compare it with the static bound.

For each case this runs the firmware in QEMU, reads the stack watermark the
firmware measured for itself, and runs the analyser in four configurations:

    full            the analysis as intended
    no_exceptions   interrupts ignored, which is what every free tool does
    indirect_none   indirect calls ignored, also what free tools do
    indirect_any    indirect calls sound but unresolved: every site may reach
                    every address-taken function

The interesting column is not the bound.  It is ``bound - measured``: negative
means the tool told you a firmware fits when it does not.

Usage:  python3 tools/validate.py [--out results/results.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from stackbound import config as config_mod  # noqa: E402
from stackbound.analyze import Options, analyse  # noqa: E402
from stackbound.elfinfo import ElfInfo  # noqa: E402
from stackbound.report import to_dict  # noqa: E402

CASES = ["direct", "table", "global_fp", "param_fp", "recursion", "isr_nesting"]
QEMU = os.environ.get("QEMU", "qemu-system-arm")
MACHINE = os.environ.get("QEMU_MACHINE", "mps2-an385")
CPU = os.environ.get("QEMU_CPU", "cortex-m3")

MODES = {
    "full": dict(indirect_mode="full", exceptions=True),
    "no_exceptions": dict(indirect_mode="full", exceptions=False),
    "indirect_none": dict(indirect_mode="none", exceptions=True),
    "indirect_any": dict(indirect_mode="any", exceptions=True),
}


def build() -> None:
    subprocess.run(["make", "-s"], cwd=os.path.join(ROOT, "firmware"), check=True)


def measure(elf: str, timeout: int = 60) -> int:
    """Run the firmware and return the stack watermark it measured."""
    proc = subprocess.run(
        [
            QEMU,
            "-M",
            MACHINE,
            "-cpu",
            CPU,
            "-nographic",
            "-semihosting-config",
            "enable=on,target=native",
            "-kernel",
            elf,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = proc.stdout + proc.stderr
    m = re.search(r"measured_stack_bytes=(\d+)", out)
    if not m:
        raise RuntimeError(f"no measurement from {elf}:\n{out}")
    return int(m.group(1))


def analyse_mode(elf_path: str, cfg_path: str | None, mode: str) -> dict[str, Any]:
    opts = Options(**MODES[mode])
    if cfg_path and os.path.exists(cfg_path):
        opts = config_mod.to_options(config_mod.load(cfg_path), opts)
    elf = ElfInfo(elf_path)
    try:
        return to_dict(analyse(elf, opts))
    finally:
        elf.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "results.json"))
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args()

    if not args.skip_build:
        build()

    results: list[dict[str, Any]] = []
    for case in CASES:
        elf = os.path.join(ROOT, "firmware", "build", f"{case}.elf")
        cfg = os.path.join(ROOT, "firmware", "config", f"{case}.json")
        measured = measure(elf)
        entry: dict[str, Any] = {"case": case, "measured": measured, "modes": {}}
        for mode in MODES:
            entry["modes"][mode] = analyse_mode(elf, cfg, mode)
        full = entry["modes"]["full"]
        entry["sound"] = (not full["unbounded"]) and full["total"] >= measured
        entry["tightness"] = (full["total"] / measured) if measured else None
        results.append(entry)
        status = "sound" if entry["sound"] else ("UNBOUNDED" if full["unbounded"] else "UNSOUND")
        tightness = entry["tightness"]
        shown = "n/a" if tightness is None else f"{tightness:.3f}"
        print(
            f"{case:<14} measured {measured:5d}   bound {full['total']:5d}   "
            f"{status:<10} tightness {shown}"
        )

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "qemu": subprocess.run(
                    [QEMU, "--version"], capture_output=True, text=True
                ).stdout.splitlines()[0],
                "machine": MACHINE,
                "cpu": CPU,
                "cases": results,
            },
            fh,
            indent=2,
        )
    print(f"\nwritten to {args.out}")

    # An unbounded case is a failure too: a benchmark that lost its recursion
    # annotation produces no bound at all, which must not exit 0.
    bad = [r["case"] for r in results if not r["sound"]]
    if bad:
        print("not sound: " + ", ".join(bad))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
