"""Whole-program stack bound.

The bound for a function is

$$ S(f) = \\max\\Big( L(f),\\; \\max_{c \\in \\mathrm{calls}(f)} d(c) + \\max_{g \\in
   T(c)} S(g) \\Big) $$

where $L(f)$ is the deepest allocation inside $f$, $d(c)$ the stack already in
use at call site $c$, and $T(c)$ the set of possible callees.  Using $d(c)$
rather than $L(f)$ is what keeps the bound tight: a function that allocates a
large buffer after its calls have returned never holds both at the same time.

Cycles have no finite bound without extra information, so a recursive component
is reported as unbounded unless the user states how many activations are
possible.  With a stated bound $k$ the component costs

$$ (k-1)\\, \\max_{\\text{back edges}} d + \\max_{f \\in \\mathrm{SCC}} S_{\\mathrm{exit}}(f) $$

which is the depth reached by $k$ nested activations where each one recurses at
its deepest recursion site.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from .elfinfo import ElfInfo
from .indirect import IndirectResolver, Resolution
from .nvic import Handler, chain_costs, worst_chain
from .thumb import FunctionAnalysis, analyse_all

INDIRECT_MODES = ("full", "any", "none")


@dataclass
class Options:
    indirect_mode: str = "full"
    exceptions: bool = True
    prigroup: int = 0
    fpu: bool = False
    priorities: dict[str, int] = field(default_factory=dict)
    disabled: set[str] = field(default_factory=set)
    recursion: dict[str, int] = field(default_factory=dict)
    manual_targets: dict[int, list[str]] = field(default_factory=dict)
    stack_size: int | None = None
    entry: str | None = None
    any_includes_vectors: bool = False


@dataclass
class FunctionBound:
    name: str
    addr: int
    local: int
    bound: int
    unbounded: bool = False
    flags: list[str] = field(default_factory=list)
    via: tuple[int, int] | None = None  # (call site addr, callee addr) on the worst path


@dataclass
class Result:
    entry_name: str
    thread_bound: int
    exception_bound: int
    total: int
    handlers: list[Handler]
    level_costs: dict[str, int]
    bounds: dict[int, FunctionBound]
    resolutions: list[tuple[str, Resolution]]
    tier_counts: dict[str, int]
    unbounded: list[str]
    flagged: dict[str, list[str]]
    worst_path: list[str]
    stack_region: tuple[int, int] | None
    options: Options

    @property
    def stack_size(self) -> int | None:
        if self.options.stack_size is not None:
            return self.options.stack_size
        if self.stack_region is not None:
            return self.stack_region[1] - self.stack_region[0]
        return None

    @property
    def headroom(self) -> int | None:
        size = self.stack_size
        return None if size is None else size - self.total


def _targets(site_res: Resolution | None, mode: str, all_taken: Sequence[int]) -> list[int]:
    if site_res is None:
        return []
    if mode == "none":
        return []
    if mode == "any":
        return list(all_taken)
    return site_res.targets


def _tarjan(nodes: Sequence[int], edges: dict[int, list[int]]) -> list[list[int]]:
    """Iterative Tarjan, so that deep call graphs cannot blow the Python stack."""
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on: dict[int, bool] = {}
    stack: list[int] = []
    out: list[list[int]] = []
    counter = 0

    for root in nodes:
        if root in index:
            continue
        work: list[tuple[int, int]] = [(root, 0)]
        while work:
            v, pi = work[-1]
            if pi == 0:
                index[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on[v] = True
            succs = edges.get(v, [])
            if pi < len(succs):
                work[-1] = (v, pi + 1)
                w = succs[pi]
                if w not in index:
                    work.append((w, 0))
                elif on.get(w):
                    low[v] = min(low[v], index[w])
            else:
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[v])
                if low[v] == index[v]:
                    comp = []
                    while True:
                        w = stack.pop()
                        on[w] = False
                        comp.append(w)
                        if w == v:
                            break
                    out.append(comp)
    return out


def analyse(elf: ElfInfo, opts: Options) -> Result:
    fas: dict[int, FunctionAnalysis] = analyse_all(elf)
    resolver = IndirectResolver(elf, opts.manual_targets, opts.any_includes_vectors)
    all_taken = list(resolver.candidates)

    # ---- edges ----------------------------------------------------------
    # edge = (call site address, stack depth at the site, callee address)
    edges: dict[int, list[tuple[int, int, int]]] = {}
    resolutions: list[tuple[str, Resolution]] = []
    tier_counts: dict[str, int] = {}

    for addr, fa in fas.items():
        out: list[tuple[int, int, int]] = []
        res_by_site = {r.site.addr: r for r in resolver.resolve(fa)}
        for site in fa.calls:
            if site.is_indirect:
                r = res_by_site.get(site.addr)
                if r is not None:
                    resolutions.append((fa.fn.name, r))
                    tier_counts[r.tier] = tier_counts.get(r.tier, 0) + 1
                for tgt in _targets(r, opts.indirect_mode, all_taken):
                    if tgt in fas:
                        out.append((site.addr, site.sp_depth, tgt))
            elif site.target is not None:
                callee = elf.function_at(site.target)
                if callee is not None and callee.addr in fas:
                    out.append((site.addr, site.sp_depth, callee.addr))
        edges[addr] = out

    succ = {a: [t for (_, _, t) in e] for a, e in edges.items()}

    # ---- costs ----------------------------------------------------------
    bounds: dict[int, FunctionBound] = {}
    for addr, fa in fas.items():
        bounds[addr] = FunctionBound(
            name=fa.fn.name,
            addr=addr,
            local=fa.local_max,
            bound=fa.local_max,
            unbounded=fa.unbounded,
            flags=sorted(fa.flags),
        )

    comps = _tarjan(list(fas.keys()), succ)  # already in reverse topological order
    for comp in comps:
        members = set(comp)
        cyclic = len(comp) > 1 or any(t in members for (_, _, t) in edges.get(comp[0], []))

        if not cyclic:
            addr = comp[0]
            fb = bounds[addr]
            best = fb.local
            via = None
            for site_addr, depth, callee in edges.get(addr, []):
                cb = bounds[callee]
                if cb.unbounded:
                    fb.unbounded = True
                cost = depth + cb.bound
                if cost > best:
                    best, via = cost, (site_addr, callee)
            fb.bound, fb.via = best, via
            continue

        # recursive component
        k = None
        for addr in comp:
            name = bounds[addr].name
            if name in opts.recursion:
                k = opts.recursion[name] if k is None else max(k, opts.recursion[name])

        exit_cost = 0
        back_depth = 0
        via_by_addr: dict[int, tuple[int, int] | None] = {}
        for addr in comp:
            fb = bounds[addr]
            best = fb.local
            via = None
            for site_addr, depth, callee in edges.get(addr, []):
                if callee in members:
                    back_depth = max(back_depth, depth)
                    continue
                cb = bounds[callee]
                if cb.unbounded:
                    fb.unbounded = True
                cost = depth + cb.bound
                if cost > best:
                    best, via = cost, (site_addr, callee)
            exit_cost = max(exit_cost, best)
            via_by_addr[addr] = via

        if k is None:
            for addr in comp:
                bounds[addr].unbounded = True
                bounds[addr].bound = exit_cost
                bounds[addr].flags = sorted(set(bounds[addr].flags) | {"recursive"})
                bounds[addr].via = via_by_addr[addr]
        else:
            total = (k - 1) * back_depth + exit_cost
            for addr in comp:
                bounds[addr].bound = total
                bounds[addr].flags = sorted(set(bounds[addr].flags) | {"recursive"})
                bounds[addr].via = via_by_addr[addr]

    # ---- roots ----------------------------------------------------------
    initial_sp, vectors = elf.vector_table()
    entry_name = opts.entry or "Reset_Handler"
    entry_fn = elf.by_name.get(entry_name)
    if entry_fn is None:
        for idx, fn in vectors:
            if idx == 1 and fn is not None:
                entry_fn = fn
                entry_name = fn.name
                break
    if entry_fn is None:
        raise ValueError("cannot find the reset entry point")

    thread_bound = bounds[entry_fn.addr].bound

    handlers: list[Handler] = []
    for idx, fn in vectors:
        if idx == 1 or fn is None:
            continue
        name = fn.name
        handlers.append(
            Handler(
                name=name,
                vector=idx,
                stack=bounds[fn.addr].bound if fn.addr in bounds else 0,
                priority=opts.priorities.get(name),
                enabled=name not in opts.disabled,
            )
        )

    exception_bound = worst_chain(handlers, opts.prigroup, opts.fpu) if opts.exceptions else 0
    level_costs: dict[str, int] = {}
    if opts.exceptions:
        for lvl, cost in sorted(chain_costs(handlers, opts.prigroup, opts.fpu).items()):
            key = f"unknown #{lvl[1]}" if lvl[0] else f"level {lvl[1]}"
            level_costs[key] = cost

    # ---- worst path for the report --------------------------------------
    path: list[str] = []
    cur: int | None = entry_fn.addr
    seen: set[int] = set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        fb = bounds[cur]
        path.append(fb.name)
        cur = fb.via[1] if fb.via else None

    unbounded = sorted({fb.name for fb in bounds.values() if fb.unbounded})
    flagged = {fb.name: fb.flags for fb in bounds.values() if fb.flags}

    return Result(
        entry_name=entry_name,
        thread_bound=thread_bound,
        exception_bound=exception_bound,
        total=thread_bound + exception_bound,
        handlers=handlers,
        level_costs=level_costs,
        bounds=bounds,
        resolutions=resolutions,
        tier_counts=tier_counts,
        unbounded=unbounded,
        flagged=flagged,
        worst_path=path,
        stack_region=elf.stack_region(),
        options=opts,
    )
