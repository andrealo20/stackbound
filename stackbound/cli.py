"""Command line interface.

    stackbound report fw.elf --config fw.json
    stackbound check  fw.elf --config fw.json     # exits non-zero if it does not fit

``check`` is the form meant for CI: it compares the bound against the stack
region declared by the linker script and fails the build if the firmware cannot
be shown to fit.  It only ever exits 0 when the number it compared is a bound;
when it is merely a lower bound, or when there is nothing to compare against, it
says so and exits non-zero.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import config as config_mod
from .analyze import INDIRECT_MODES, Options, Result, analyse
from .elfinfo import ElfInfo
from .report import render, to_dict

EXIT_OK = 0
EXIT_OVERFLOW = 1
EXIT_UNBOUNDED = 2
EXIT_INCOMPLETE = 3  # no bound was established: nothing to compare, or a lower bound


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stackbound", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    for name in ("report", "check"):
        sp = sub.add_parser(name)
        sp.add_argument("elf")
        sp.add_argument("--config", help="JSON configuration file")
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.add_argument("--verbose", action="store_true")
        sp.add_argument(
            "--indirect-mode",
            choices=INDIRECT_MODES,
            default="full",
            help="full: resolve indirect calls; any: every site may reach every "
            "address-taken function; none: ignore indirect calls (unsound, for "
            "comparison with tools that do this)",
        )
        sp.add_argument(
            "--no-exceptions",
            action="store_true",
            help="ignore interrupts entirely (unsound, for comparison)",
        )
        sp.add_argument("--fpu", action="store_true", help="assume an extended FP frame")
        sp.add_argument("--prigroup", type=int, default=None)
        sp.add_argument("--stack-size", type=int, default=None)
        sp.add_argument("--entry", default=None)
        if name == "check":
            sp.add_argument(
                "--allow-unbounded",
                action="store_true",
                help="report an unbounded component as a lower bound (exit 3) instead "
                "of failing outright (exit 2); it can still exit 1 if even the lower "
                "bound does not fit",
            )
    return p


def check(result: Result, allow_unbounded: bool = False, quiet: bool = False) -> int:
    """Exit code for ``stackbound check``, and the reasons behind it on stderr."""

    def say(message: str) -> None:
        if not quiet:
            print(message, file=sys.stderr)

    reasons: list[str] = []
    if result.reachable_unbounded:
        reasons.append("unbounded stack usage: " + ", ".join(result.reachable_unbounded))
    if result.reachable_unknown_callees:
        reasons.append(
            "calls a target that is not in the call graph: "
            + ", ".join(result.reachable_unknown_callees)
        )

    if reasons and not allow_unbounded:
        for reason in reasons:
            say(f"\nFAIL: {reason}")
        return EXIT_UNBOUNDED

    size = result.stack_size
    if size is None:
        say("\nFAIL: no stack size (give --stack-size or _stack_top/_stack_bottom)")
        return EXIT_INCOMPLETE

    # With --allow-unbounded the total is the depth of a single activation of
    # each unbounded component, so it is a lower bound.  Exceeding the region is
    # still conclusive; fitting inside it is not.
    if result.total > size:
        say(
            f"\nFAIL: bound {result.total} exceeds stack region {size} by "
            f"{result.total - size} bytes"
        )
        return EXIT_OVERFLOW

    if reasons:
        for reason in reasons:
            say(f"\nINCOMPLETE: {reason}")
        say(f"INCOMPLETE: {result.total} bytes is a lower bound, not a bound")
        return EXIT_INCOMPLETE
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    opts = Options(
        indirect_mode=args.indirect_mode,
        exceptions=not args.no_exceptions,
        stack_size=args.stack_size,
        entry=args.entry,
    )
    if args.prigroup is not None:
        opts.prigroup = args.prigroup
    opts.fpu = args.fpu

    if args.config:
        opts = config_mod.to_options(config_mod.load(args.config), opts)
        if args.prigroup is not None:
            opts.prigroup = args.prigroup
        if args.fpu:
            opts.fpu = True

    elf = ElfInfo(args.elf)
    result = analyse(elf, opts)

    try:
        if args.json:
            print(json.dumps(to_dict(result), indent=2))
        else:
            print(render(result, verbose=args.verbose))
    except BrokenPipeError:  # piped into head, or similar
        return EXIT_OK

    if args.cmd == "check":
        return check(result, allow_unbounded=args.allow_unbounded, quiet=args.json)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
