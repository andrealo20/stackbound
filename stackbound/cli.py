"""Command line interface.

    stackbound report fw.elf --config fw.json
    stackbound check  fw.elf --config fw.json     # exits non-zero if it does not fit

``check`` is the form meant for CI: it compares the bound against the stack
region declared by the linker script and fails the build if the firmware cannot
be shown to fit.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import config as config_mod
from .analyze import INDIRECT_MODES, Options, analyse
from .elfinfo import ElfInfo
from .report import render, to_dict

EXIT_OK = 0
EXIT_OVERFLOW = 1
EXIT_UNBOUNDED = 2


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
                help="do not fail when a recursive component has no stated depth",
            )
    return p


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
        if result.unbounded and not args.allow_unbounded:
            if not args.json:
                print("\nFAIL: unbounded stack usage", file=sys.stderr)
            return EXIT_UNBOUNDED
        size = result.stack_size
        if size is None:
            print(
                "\nFAIL: no stack size (give --stack-size or _stack_top/_stack_bottom)",
                file=sys.stderr,
            )
            return EXIT_OVERFLOW
        if result.total > size:
            if not args.json:
                print(
                    f"\nFAIL: bound {result.total} exceeds stack region {size} by "
                    f"{result.total - size} bytes",
                    file=sys.stderr,
                )
            return EXIT_OVERFLOW
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
