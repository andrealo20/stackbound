"""Configuration.

Two things about a firmware image cannot be read from the binary: which
interrupts are actually enabled and at what priority (both are set by code at
run time), and how deep a recursion can go.  stackbound never guesses either.

Without a configuration it assumes the worst that the hardware allows — every
vector slot enabled, every priority distinct, so everything can nest — and
reports recursion as unbounded.  A configuration file replaces those worst cases
with what the firmware actually does.
"""

from __future__ import annotations

import json
from typing import Any

from .analyze import Options


def load(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in configuration file {path}: {e}") from e
    except FileNotFoundError as e:
        raise ValueError(f"Configuration file not found: {path}") from e


def to_options(cfg: dict[str, Any], base: Options) -> Options:
    opts = Options(
        indirect_mode=base.indirect_mode,
        exceptions=base.exceptions,
        prigroup=int(cfg.get("prigroup", base.prigroup)),
        fpu=bool(cfg.get("fpu", base.fpu)),
        stack_size=base.stack_size,
        entry=cfg.get("entry", base.entry),
        any_includes_vectors=bool(cfg.get("any_includes_vectors", base.any_includes_vectors)),
    )

    handlers: dict[str, Any] = cfg.get("handlers", {})
    for name, spec in handlers.items():
        if isinstance(spec, int):
            opts.priorities[name] = spec
            continue
        if spec.get("enabled", True) is False:
            opts.disabled.add(name)
        if "priority" in spec:
            opts.priorities[name] = int(spec["priority"])

    for name, depth in cfg.get("recursion", {}).items():
        opts.recursion[name] = int(depth)

    for site, names in cfg.get("indirect_targets", {}).items():
        addr = int(site, 0) if isinstance(site, str) else int(site)
        opts.manual_targets[addr] = list(names)

    return opts
