"""Report rendering."""

from __future__ import annotations

from typing import Any

from .analyze import FunctionBound, Result
from .nvic import frame_size


def _function_keys(bounds: list[FunctionBound]) -> dict[str, FunctionBound]:
    """One key per function, even when two of them share a name.

    Two ``static`` functions with the same name in different translation units
    are different functions with different bounds.  Keying on the name alone
    would let one overwrite the other and disappear from the output, so a
    repeated name carries its address.
    """
    repeated = {fb.name for fb in bounds}
    repeated = {name for name in repeated if sum(1 for fb in bounds if fb.name == name) > 1}
    out: dict[str, FunctionBound] = {}
    for fb in bounds:
        key = f"{fb.name}@0x{fb.addr:08x}" if fb.name in repeated else fb.name
        out[key] = fb
    return out


def to_dict(result: Result) -> dict[str, Any]:
    return {
        "entry": result.entry_name,
        "thread_bound": result.thread_bound,
        "exception_bound": result.exception_bound,
        "total": result.total,
        "stack_size": result.stack_size,
        "headroom": result.headroom,
        "unbounded": result.unbounded,
        "worst_path": result.worst_path,
        "indirect_mode": result.options.indirect_mode,
        "exceptions_modelled": result.options.exceptions,
        "frame_size": frame_size(result.options.fpu),
        "tier_counts": result.tier_counts,
        "level_costs": result.level_costs,
        "handlers": [
            {
                "name": h.name,
                "vector": h.vector,
                "priority": h.priority,
                "enabled": h.enabled,
                "stack": h.stack,
            }
            for h in result.handlers
        ],
        "sites": [
            {
                "function": fname,
                "address": f"0x{r.site.addr:x}",
                "tier": r.tier,
                "candidates": len(r.targets),
                "detail": r.detail,
            }
            for fname, r in result.resolutions
        ],
        "flagged": result.flagged,
        "reachable_unbounded": result.reachable_unbounded,
        "unknown_callees": {
            name: [f"0x{a:08x}" for a in addrs]
            for name, addrs in sorted(result.unknown_callees.items())
        },
        "functions": {
            key: {
                "address": f"0x{fb.addr:08x}",
                "local": fb.local,
                "bound": fb.bound,
                "unbounded": fb.unbounded,
            }
            for key, fb in _function_keys(list(result.bounds.values())).items()
        },
    }


def render(result: Result, verbose: bool = False) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"entry point            {result.entry_name}")
    add(f"thread-mode bound      {result.thread_bound} bytes")
    if result.options.exceptions:
        add(
            f"exception chain        {result.exception_bound} bytes "
            f"(frame {frame_size(result.options.fpu)} bytes per level)"
        )
    else:
        add("exception chain        not modelled (--no-exceptions)")
    add(f"total bound            {result.total} bytes")

    size = result.stack_size
    if size is not None:
        pct = 100.0 * result.total / size if size else 0.0
        add(
            f"stack region           {size} bytes  ({pct:.1f}% used, "
            f"{result.headroom} bytes headroom)"
        )

    if result.unbounded:
        add("")
        add("UNBOUNDED: " + ", ".join(result.unbounded))
        add("  no finite bound exists without a recursion depth; see 'recursion' in the config")
        unreached = sorted(set(result.unbounded) - set(result.reachable_unbounded))
        if unreached:
            add("  no root reaches, so 'check' does not fail on: " + ", ".join(unreached))

    if result.unknown_callees:
        add("")
        add("UNRESOLVED CALLS: the bound does not cover these call sites")
        for name, addrs in sorted(result.unknown_callees.items()):
            add(f"  {name:<24} " + ", ".join(f"0x{a:08x}" for a in addrs))
        add("  a target with no function symbol, usually assembly with no .size directive")

    add("")
    add("worst path: " + " -> ".join(result.worst_path))

    if result.options.exceptions and result.level_costs:
        add("")
        add("preemption levels (one handler from each can be on the stack at once):")
        for name, cost in result.level_costs.items():
            add(f"  {name:>14}  {cost:6d} bytes")

    if result.resolutions:
        add("")
        add("indirect call sites:")
        for fname, r in result.resolutions:
            add(
                f"  0x{r.site.addr:08x} {fname:<20} {r.tier:<8} "
                f"{len(r.targets):3d} candidate(s)  {r.detail}"
            )
        total = sum(result.tier_counts.values())
        exact = result.tier_counts.get("literal", 0) + result.tier_counts.get("table", 0)
        add(f"  resolved exactly: {exact}/{total}")

    if result.flagged:
        add("")
        add("functions the analysis could not take at face value:")
        for name, flags in sorted(result.flagged.items()):
            add(f"  {name:<24} {', '.join(flags)}")

    if verbose:
        add("")
        add("per-function bounds (bytes):")
        for fb in sorted(result.bounds.values(), key=lambda b: -b.bound):
            mark = " UNBOUNDED" if fb.unbounded else ""
            add(f"  {fb.name:<24} local {fb.local:6d}   bound {fb.bound:6d}{mark}")

    return "\n".join(lines)
