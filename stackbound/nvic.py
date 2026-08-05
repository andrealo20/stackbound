"""The exception model.

A Cortex-M handler does not run on its own stack.  It runs on the stack of
whatever it interrupted, on top of a hardware-pushed exception frame, and it can
itself be interrupted by anything of higher priority.  The worst case is
therefore not "the largest handler" and not "the sum of all handlers", but the
most expensive *nesting chain* the priority configuration allows.

Two handlers at the same preemption priority can never nest — the second one is
tail-chained after the first returns — so a chain contains at most one handler
per preemption level.  The worst chain is obtained by taking the most expensive
handler at each level and stacking all of them:

$$ S_{\\mathrm{exc}} = \\sum_{\\ell \\in \\mathrm{levels}} \\max_{h \\in \\ell}
   \\big( F + \\mathrm{align} + S(h) \\big) $$

where $F$ is the hardware exception frame and $S(h)$ the handler's own bound.
``worst_chain`` computes this in linear time; ``worst_chain_bruteforce``
enumerates every admissible chain instead, and the two are checked against each
other in the test suite.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import permutations

#: Registers stacked by hardware on exception entry (ARMv7-M, no FP context):
#: r0-r3, r12, lr, pc, xPSR.
BASIC_FRAME = 32

#: With FP context active and lazy stacking disabled, hardware also stacks
#: s0-s15, FPSCR and one reserved word.
EXTENDED_FRAME = 104

#: STKALIGN forces 8-byte alignment on exception entry, which can cost one
#: padding word per exception.
ALIGN_PAD = 4


@dataclass
class Handler:
    name: str
    vector: int
    stack: int  # the handler's own bound, bytes
    priority: int | None = None  # raw 8-bit NVIC priority value
    enabled: bool = True


def frame_size(fpu: bool) -> int:
    return (EXTENDED_FRAME if fpu else BASIC_FRAME) + ALIGN_PAD


def preemption_level(priority: int | None, prigroup: int, index: int) -> tuple[int, int]:
    """Group two handlers together only when they provably cannot nest.

    A handler whose priority is not known statically gets a unique level, which
    is the conservative choice: it is then allowed to nest with everything.
    """
    if priority is None:
        return (1, index)  # unique, sorts after all known levels
    return (0, priority >> (prigroup + 1))


def chain_costs(
    handlers: Sequence[Handler], prigroup: int = 0, fpu: bool = False
) -> dict[tuple[int, int], int]:
    """Cost of the most expensive handler at each preemption level."""
    frame = frame_size(fpu)
    levels: dict[tuple[int, int], int] = {}
    for i, h in enumerate(handlers):
        if not h.enabled:
            continue
        lvl = preemption_level(h.priority, prigroup, i)
        levels[lvl] = max(levels.get(lvl, 0), frame + h.stack)
    return levels


def worst_chain(handlers: Sequence[Handler], prigroup: int = 0, fpu: bool = False) -> int:
    return sum(chain_costs(handlers, prigroup, fpu).values())


def worst_chain_bruteforce(
    handlers: Sequence[Handler], prigroup: int = 0, fpu: bool = False
) -> int:
    """Reference implementation: enumerate every admissible nesting chain.

    A chain is a sequence of handlers with strictly increasing priority (that
    is, strictly decreasing numeric priority value); handlers with unknown
    priority may appear anywhere.  Exponential, and only used to check
    ``worst_chain`` in the tests.
    """
    active = [h for h in handlers if h.enabled]
    frame = frame_size(fpu)
    best = 0
    n = len(active)
    for k in range(0, n + 1):
        for combo in permutations(range(n), k):
            ok = True
            prev: int | None = None
            for idx in combo:
                p = active[idx].priority
                if p is None:
                    continue
                lvl = p >> (prigroup + 1)
                if prev is not None and lvl >= prev:
                    ok = False
                    break
                prev = lvl
            if not ok:
                continue
            # A chain may not contain two handlers at the same known level.
            seen = set()
            dup = False
            for idx in combo:
                p = active[idx].priority
                if p is None:
                    continue
                lvl = p >> (prigroup + 1)
                if lvl in seen:
                    dup = True
                    break
                seen.add(lvl)
            if dup:
                continue
            cost = sum(frame + active[i].stack for i in combo)
            best = max(best, cost)
    return best
