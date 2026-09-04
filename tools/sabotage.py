#!/usr/bin/env python3
"""Break the analyser on purpose and check that the test suite notices.

A test that has never been seen to fail is not yet a test.  Each mutation below
is a plausible mistake, the kind a reviewer would have to spot by reading,
and for each one this script records which tests catch it.  A mutation that
nothing catches is a hole in the suite, and the run fails.

Usage:  python3 tools/sabotage.py [--out results/sabotage.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (description, file, exact text to replace, replacement)
MUTATIONS: list[tuple[str, str, str, str]] = [
    (
        "forget the hardware exception frame",
        "stackbound/nvic.py",
        "BASIC_FRAME = 32",
        "BASIC_FRAME = 0",
    ),
    (
        "assume interrupts cannot nest (take the largest handler instead of the chain)",
        "stackbound/nvic.py",
        "    return sum(chain_costs(handlers, prigroup, fpu).values())",
        "    return max(chain_costs(handlers, prigroup, fpu).values(), default=0)",
    ),
    (
        "ignore how much stack the caller already holds at a call site",
        "stackbound/analyze.py",
        (
            "                cost = depth + cb.bound\n"
            "                if cost > best:\n"
            "                    best, via = cost, (site_addr, callee)\n"
            "            fb.bound, fb.via = best, via"
        ),
        (
            "                cost = cb.bound\n"
            "                if cost > best:\n"
            "                    best, via = cost, (site_addr, callee)\n"
            "            fb.bound, fb.via = best, via"
        ),
    ),
    (
        "read only the first entry of a const dispatch table",
        "stackbound/indirect.py",
        "                targets = self._functions_in(gv.addr, gv.size)",
        "                targets = self._functions_in(gv.addr, gv.size)[:1]",
    ),
    (
        "decode literal pools as if they were instructions",
        "stackbound/thumb.py",
        "    insns, _pools, stable = _decode_stable(md, fn)",
        "    insns, _pools, stable = list(md.disasm(fn.code, fn.addr)), [], True",
    ),
    (
        "treat a recursive component as if it were called once",
        "stackbound/analyze.py",
        "            total = (k - 1) * back_depth + exit_cost",
        "            total = exit_cost",
    ),
]


def run_tests() -> tuple[bool, list[str]]:
    """Run the suite to the end: which tests catch a mutation is the record kept
    here, and stopping at the first failure would record only one of them."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "--no-header", "--tb=no"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    failures = [
        line.split()[1]
        for line in (proc.stdout + proc.stderr).splitlines()
        if line.startswith("FAILED") and len(line.split()) > 1
    ]
    if not failures and proc.returncode != 0:
        failures = ["<suite errored>"]
    return proc.returncode == 0, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "results", "sabotage.json"))
    args = ap.parse_args()

    ok, failures = run_tests()
    if not ok:
        print("the suite already fails before any mutation:", failures)
        return 1
    print("baseline: suite green\n")

    records: list[dict[str, object]] = []
    backup = tempfile.mkdtemp(prefix="stackbound-sabotage-")
    try:
        for desc, rel, old, new in MUTATIONS:
            path = os.path.join(ROOT, rel)
            shutil.copy2(path, os.path.join(backup, os.path.basename(rel)))
            src = open(path, encoding="utf-8").read()
            if old not in src:
                print(f"! mutation text not found in {rel}: {desc}")
                return 1
            open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
            try:
                passed, failed = run_tests()
            finally:
                shutil.copy2(os.path.join(backup, os.path.basename(rel)), path)

            caught = not passed
            records.append(
                {"mutation": desc, "file": rel, "caught": caught, "failing_tests": failed}
            )
            mark = "caught" if caught else "MISSED"
            print(f"  {mark:<7} {desc}")
            for f in failed[:3]:
                print(f"            {f}")
    finally:
        shutil.rmtree(backup, ignore_errors=True)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"mutations": records}, fh, indent=2)

    missed = [r for r in records if not r["caught"]]
    print(f"\n{len(records) - len(missed)}/{len(records)} mutations caught")
    if missed:
        print("uncaught mutations mean the suite has a hole:")
        for r in missed:
            print("  -", r["mutation"])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
