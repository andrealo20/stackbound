"""The documentation must not drift away from the measurements.

The README and the design notes both quote numbers.  Those numbers come from
``results/results.json``, which ``tools/validate.py`` writes after running every
benchmark in QEMU.  This test re-reads both and compares them, so a stale table
in the documentation is a failing test rather than something a reader discovers.
"""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results", "results.json")

CASES = ["direct", "table", "global_fp", "param_fp", "recursion", "isr_nesting"]


@pytest.fixture(scope="module")
def measured():
    if not os.path.exists(RESULTS):
        pytest.skip("run tools/validate.py first")
    with open(RESULTS, encoding="utf-8") as fh:
        data = json.load(fh)
    return {c["case"]: c for c in data["cases"]}


def _table_rows(path, ncols):
    """Rows of every markdown table in a file, as lists of cell strings."""
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("|") or set(line) <= set("|-: "):
                continue
            cells = [c.strip().strip("`*") for c in line.strip("|").split("|")]
            if len(cells) == ncols:
                rows.append(cells)
    return rows


def test_readme_table_matches_results(measured):
    rows = _table_rows(os.path.join(ROOT, "README.md"), 5)
    seen = set()
    for cells in rows:
        case = cells[0]
        if case not in CASES:
            continue
        seen.add(case)
        assert int(cells[2]) == measured[case]["measured"], case
        assert int(cells[3]) == measured[case]["modes"]["full"]["total"], case
    assert seen == set(CASES), f"README is missing cases: {set(CASES) - seen}"


def test_design_ablation_table_matches_results(measured):
    rows = _table_rows(os.path.join(ROOT, "docs", "design.md"), 6)
    seen = set()
    for cells in rows:
        case = cells[0]
        if case not in CASES:
            continue
        seen.add(case)
        modes = measured[case]["modes"]
        assert int(cells[1]) == measured[case]["measured"], case
        assert int(cells[2]) == modes["full"]["total"], case
        assert int(cells[3]) == modes["no_exceptions"]["total"], case
        assert int(cells[4]) == modes["indirect_none"]["total"], case
        assert int(cells[5]) == modes["indirect_any"]["total"], case
    assert seen == set(CASES), f"design.md is missing cases: {set(CASES) - seen}"


def test_headline_claim_is_still_true(measured):
    """The README's opening claim, checked against the data behind it."""
    isr = measured["isr_nesting"]
    assert isr["modes"]["no_exceptions"]["total"] == 276
    assert isr["measured"] == 684
    assert isr["modes"]["full"]["total"] >= isr["measured"]


def test_test_count_badge_is_honest():
    """The badge says how many tests there are; keep it true."""
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    m = re.search(r"tests-(\d+)-green", readme)
    assert m, "no test-count badge in the README"
    claimed = int(m.group(1))

    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q", "--no-header"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    tail = [ln for ln in proc.stdout.splitlines() if "test" in ln and "collected" in ln]
    if not tail:
        pytest.skip("could not count tests")
    actual = int(re.search(r"(\d+)", tail[-1]).group(1))
    assert actual == claimed, f"badge says {claimed}, suite has {actual}"
