"""The linear worst-chain formula is checked against brute-force enumeration.

The formula says: one handler per preemption level, take the most expensive at
each, sum them.  The brute force enumerates every admissible nesting order and
takes the maximum.  If the formula were wrong in either direction — missing a
chain, or allowing one the hardware forbids — these two disagree.
"""

import random

import pytest

from stackbound.nvic import (
    ALIGN_PAD,
    BASIC_FRAME,
    EXTENDED_FRAME,
    Handler,
    frame_size,
    worst_chain,
    worst_chain_bruteforce,
)


def h(name, stack, priority=None, enabled=True):
    return Handler(name=name, vector=16, stack=stack, priority=priority, enabled=enabled)


def test_frame_sizes():
    assert frame_size(False) == BASIC_FRAME + ALIGN_PAD == 36
    assert frame_size(True) == EXTENDED_FRAME + ALIGN_PAD == 108


def test_empty():
    assert worst_chain([]) == 0


def test_same_level_cannot_nest():
    hs = [h("a", 100, 0x40), h("b", 200, 0x40)]
    # both at the same preemption level: only the more expensive one can be on
    # the stack, not both
    assert worst_chain(hs) == frame_size(False) + 200


def test_distinct_levels_nest():
    hs = [h("a", 100, 0x40), h("b", 200, 0x80)]
    assert worst_chain(hs) == 2 * frame_size(False) + 300


def test_disabled_ignored():
    hs = [h("a", 100, 0x40), h("b", 9999, 0x80, enabled=False)]
    assert worst_chain(hs) == frame_size(False) + 100


def test_unknown_priority_is_conservative():
    # two handlers with unknown priority must be assumed able to nest
    hs = [h("a", 100), h("b", 200)]
    assert worst_chain(hs) == 2 * frame_size(False) + 300


def test_prigroup_merges_levels():
    # with prigroup=3, four low bits are subpriority: 0x40 and 0x48 collapse
    hs = [h("a", 100, 0x40), h("b", 200, 0x48)]
    assert worst_chain(hs, prigroup=3) == frame_size(False) + 200
    assert worst_chain(hs, prigroup=0) == 2 * frame_size(False) + 300


@pytest.mark.parametrize("seed", range(40))
def test_matches_bruteforce(seed):
    rng = random.Random(seed)
    n = rng.randint(0, 6)
    hs = []
    for i in range(n):
        prio = rng.choice([None, 0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0])
        hs.append(h(f"h{i}", rng.randrange(0, 512, 8), prio, rng.random() > 0.15))
    prigroup = rng.randint(0, 4)
    fpu = rng.random() > 0.5
    assert worst_chain(hs, prigroup, fpu) == worst_chain_bruteforce(hs, prigroup, fpu)
