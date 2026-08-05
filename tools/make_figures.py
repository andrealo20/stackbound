#!/usr/bin/env python3
"""Draw the figures from results/results.json.

Nothing here invents a number: every bar is read from the JSON that
tools/validate.py wrote after running the firmware.  Regenerate with

    python3 tools/validate.py && python3 tools/make_figures.py
"""

from __future__ import annotations

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INK = "#1b1b1b"
MEASURED = "#444444"
BOUND = "#1f6feb"
NAIVE = "#d1242f"
BLIND = "#bf8700"


def _style(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#cccccc")
    ax.spines["bottom"].set_color("#cccccc")
    ax.tick_params(colors=INK, labelsize=9)
    ax.yaxis.grid(True, color="#eeeeee", zorder=0)
    ax.set_axisbelow(True)


def _footnote(fig, data):
    fig.text(
        0.01,
        0.005,
        f"measured on {data['qemu']}, machine {data['machine']}, cpu {data['cpu']}",
        fontsize=7.5,
        color="#777777",
    )


def figure_soundness(data, out):
    cases = [c["case"] for c in data["cases"]]
    measured = [c["measured"] for c in data["cases"]]
    full = [c["modes"]["full"]["total"] for c in data["cases"]]
    no_exc = [c["modes"]["no_exceptions"]["total"] for c in data["cases"]]
    no_ind = [c["modes"]["indirect_none"]["total"] for c in data["cases"]]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 7.0))
    x = range(len(cases))
    w = 0.38

    ax1.bar([i - w / 2 for i in x], measured, w, label="measured in QEMU", color=MEASURED, zorder=3)
    ax1.bar([i + w / 2 for i in x], full, w, label="stackbound", color=BOUND, zorder=3)
    for i, (m, b) in enumerate(zip(measured, full, strict=True)):
        ax1.text(i + w / 2, b + 20, f"{b / m:.2f}x", ha="center", fontsize=8, color=BOUND)
    ax1.set_ylabel("stack, bytes")
    ax1.set_title(
        "Sound in every case, and tight in five of six", fontsize=11, color=INK, loc="left"
    )
    ax1.legend(frameon=False, fontsize=9)
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(cases, fontsize=9)
    _style(ax1)

    # Panel 2: only the cases where a naive bound lands below the measurement.
    labels, short, kinds = [], [], []
    for c, m, a, b in zip(cases, measured, no_exc, no_ind, strict=True):
        if a < m:
            labels.append(f"{c}\ninterrupts ignored")
            short.append(m - a)
            kinds.append(NAIVE)
        if b < m:
            labels.append(f"{c}\nindirect calls ignored")
            short.append(m - b)
            kinds.append(BLIND)

    ax2.bar(range(len(short)), short, 0.5, color=kinds, zorder=3)
    for i, v in enumerate(short):
        ax2.text(i, v + 8, f"{v} B", ha="center", fontsize=9, color=INK)
    ax2.set_xticks(range(len(short)))
    ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylabel("bytes the bound is short by")
    ax2.set_title(
        "Where a bound that ignores interrupts or indirect calls falls below the hardware",
        fontsize=11,
        color=INK,
        loc="left",
    )
    _style(ax2)

    fig.tight_layout(rect=(0, 0.02, 1, 1))
    _footnote(fig, data)
    fig.savefig(out, dpi=160)
    plt.close(fig)


def figure_precision(data, out):
    rows = [c for c in data["cases"] if c["modes"]["full"]["sites"]]
    cases = [c["case"] for c in rows]
    full = [c["modes"]["full"]["total"] for c in rows]
    blind = [c["modes"]["indirect_any"]["total"] for c in rows]
    tiers = [",".join(sorted(c["modes"]["full"]["tier_counts"])) for c in rows]

    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    x = range(len(cases))
    w = 0.38
    ax.bar(
        [i - w / 2 for i in x],
        blind,
        w,
        label="every address-taken function",
        color=BLIND,
        zorder=3,
    )
    ax.bar([i + w / 2 for i in x], full, w, label="resolved", color=BOUND, zorder=3)
    for i, (a, b) in enumerate(zip(blind, full, strict=True)):
        if a > b:
            ax.text(i, a + 30, f"-{a - b} B", ha="center", fontsize=9, color=BOUND)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{c}\n({t})" for c, t in zip(cases, tiers, strict=True)], fontsize=9)
    ax.set_ylabel("bound, bytes")
    ax.set_title("What resolving an indirect call is worth", fontsize=11, color=INK, loc="left")
    ax.legend(frameon=False, fontsize=9)
    _style(ax)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    _footnote(fig, data)
    fig.savefig(out, dpi=160)
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(ROOT, "results", "results.json"))
    ap.add_argument("--outdir", default=os.path.join(ROOT, "results"))
    args = ap.parse_args()

    with open(args.results, encoding="utf-8") as fh:
        data = json.load(fh)

    os.makedirs(args.outdir, exist_ok=True)
    figure_soundness(data, os.path.join(args.outdir, "bound_vs_measured.png"))
    figure_precision(data, os.path.join(args.outdir, "indirect_precision.png"))
    print("figures written to", args.outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
