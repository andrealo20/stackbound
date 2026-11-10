#!/usr/bin/env python3
"""Draw the README figures from results/results.json.

Nothing here invents a number: every point is read from the JSON that
tools/validate.py wrote after running the firmware in QEMU, and a missing input
is an error rather than a fallback.  Regenerate with

    python3 tools/validate.py && python3 tools/make_figures.py

The figures are SVG with the text converted to outlines, so they render the same
everywhere without a font installed.  The typeface is STIX, which ships with
matplotlib, and the ids are salted with a fixed string, so regenerating an
unchanged figure gives an unchanged file.

Before a figure is written, every piece of text is checked against every other
piece of text and against every plotted line and marker; an overlap stops the
script instead of producing a figure with a collision in it.
"""

from __future__ import annotations

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.text import Text  # noqa: E402
from matplotlib.ticker import FixedLocator, NullLocator  # noqa: E402
from matplotlib.transforms import ScaledTranslation  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PAPER = "#ffffff"
INK = "#1d2330"
SOFT = "#5b6474"  # secondary text, the measurement
RULE = "#e6e8ec"  # gridlines and leader lines
BLUE = "#2a6496"  # the stackbound bound
RED = "#c8502e"  # a bound that falls below the hardware
AMBER = "#a87a12"  # the sound but blind fallback for indirect calls

plt.rcParams.update(
    {
        "font.family": "STIXGeneral",
        "mathtext.fontset": "stix",
        "font.size": 10,
        "text.color": INK,
        "axes.labelcolor": SOFT,
        "axes.labelsize": 9.5,
        "xtick.color": SOFT,
        "xtick.labelsize": 9,
        "axes.edgecolor": "#a3a9b4",
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6,
        "xtick.major.size": 3,
        "svg.fonttype": "path",
        "svg.hashsalt": "stackbound",
    }
)

TICKS = (50, 100, 200, 500, 1000, 2000)
RING = dict(marker="o", markersize=10, markerfacecolor="none", markeredgecolor=SOFT, mew=1.1)


def dot(colour):
    return dict(marker="o", markersize=5.5, color=colour, markeredgecolor=PAPER, mew=1.0)


def bytes_axis(ax, lo, hi, nrows):
    """Log x axis in bytes; rows carry their own labels in the left margin."""
    ax.set_xscale("log")
    ax.set_xlim(lo, hi)
    ax.set_ylim(nrows - 0.5, -0.7)
    ticks = [t for t in TICKS if lo <= t <= hi]
    ax.xaxis.set_major_locator(FixedLocator(ticks))
    ax.xaxis.set_minor_locator(NullLocator())
    ax.set_xticklabels([f"{t:g}" for t in ticks])
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.set_yticks([])
    for t in ticks:
        ax.axvline(t, color=RULE, linewidth=0.6, zorder=0)


def row_label(ax, y, text):
    ax.text(
        -0.015, y, text, transform=ax.get_yaxis_transform(), fontsize=9.5, ha="right", va="center"
    )


def note(ax, x, y, text, **kw):
    """In-plot text on a paper patch, so gridlines pass behind it."""
    kw.setdefault("fontsize", 9)
    kw.setdefault("color", INK)
    return ax.text(
        x,
        y,
        text,
        ha="left",
        va="center",
        zorder=5,
        bbox=dict(facecolor=PAPER, edgecolor="none", pad=1.0),
        **kw,
    )


def above(ax, points):
    """Axes coordinates in x, the top edge raised by a fixed distance in y."""
    return ax.transAxes + ScaledTranslation(0, points / 72, ax.figure.dpi_scale_trans)


def panel_title(ax, letter, text, points=26):
    tr = above(ax, points)
    ax.text(0, 1, letter, transform=tr, fontsize=11, fontweight="bold", va="bottom")
    ax.text(0.035, 1, text, transform=tr, fontsize=10.5, va="bottom")


def key(ax, entries, points=12):
    """A one-line key above the plot, written out rather than boxed inside it."""
    tr = above(ax, points)
    x = 0.0
    for style, label in entries:
        ax.plot(x + 0.008, 1, clip_on=False, transform=tr, linestyle="none", **style)
        t = ax.text(x + 0.04, 1, label, transform=tr, fontsize=9, color=SOFT, va="center")
        ax.figure.canvas.draw()
        box = t.get_window_extent().transformed(ax.transAxes.inverted())
        x = box.x1 + 0.05


def check_overlaps(fig, name):
    """Stop if any text touches other text or a plotted line or marker.

    Gridlines and leader lines (drawn in RULE) may pass behind text that sits
    on a paper patch, and nothing else may.
    """
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    texts = [
        (t, t.get_window_extent(r).padded(1))
        for t in fig.findobj(Text)
        if t.get_visible() and t.get_text().strip()
    ]
    problems = []
    for i, (a, ba) in enumerate(texts):
        for b, bb in texts[i + 1 :]:
            if ba.overlaps(bb):
                problems.append(f"'{a.get_text()}' / '{b.get_text()}'")
    for ax in fig.axes:
        for ln in ax.lines:
            masked = ln.get_color() == RULE
            path = ln.get_transform().transform_path(ln.get_path())
            radius = r.points_to_pixels(ln.get_markersize()) / 2
            for t, box in texts:
                if masked and t.get_bbox_patch() is not None:
                    continue
                hit = False
                if ln.get_linestyle() not in ("None", "none", ""):
                    hit = path.intersects_bbox(box, filled=False)
                if not hit and ln.get_marker() not in (None, "None", "none", ""):
                    grown = box.padded(radius)
                    hit = any(grown.contains(x, y) for x, y in path.vertices)
                if hit:
                    problems.append(f"'{t.get_text()}' / a plotted line or marker")
    if problems:
        raise SystemExit(f"{name}: overlapping elements:\n  " + "\n  ".join(problems))


def save(fig, outdir, name):
    check_overlaps(fig, name)
    path = os.path.join(outdir, name)
    fig.savefig(
        path, bbox_inches="tight", pad_inches=0.12, facecolor=PAPER, metadata={"Date": None}
    )
    plt.close(fig)
    return path


def ratio(bound, measured):
    if bound == measured:
        return "exact"
    return f"{bound / measured:.2f}× the measurement"


def figure_soundness(data, outdir):
    """a: the bound against the measured stack; b: what a blind bound misses."""
    cases = data["cases"]
    short = []
    for c in cases:
        m = c["measured"]
        for mode, what in (("no_exceptions", "interrupts"), ("indirect_none", "indirect calls")):
            v = c["modes"][mode]["total"]
            if v < m:
                short.append((f"{c['case']}, {what} ignored", v, m))
    if not short:
        raise SystemExit("no blind bound falls below a measurement; panel b has nothing to show")

    lo, hi = 32, 2600
    fig, (ax1, ax2) = plt.subplots(
        2,
        1,
        figsize=(6.4, 0.3 * (len(cases) + len(short)) + 2.4),
        gridspec_kw=dict(height_ratios=[len(cases) + 1.2, len(short) + 1.2], hspace=0.55),
    )

    bytes_axis(ax1, lo, hi, len(cases))
    for y, c in enumerate(cases):
        m, b = c["measured"], c["modes"]["full"]["total"]
        if b < m:
            raise SystemExit(f"{c['case']}: bound {b} is below the measurement {m}")
        ax1.plot([lo, m], [y, y], color=RULE, linewidth=0.6, zorder=1)
        if b > m:
            ax1.plot([m, b], [y, y], color=SOFT, linewidth=0.8, zorder=2)
        ax1.plot(m, y, zorder=2, **RING)
        ax1.plot(b, y, zorder=3, **dot(BLUE))
        note(ax1, max(m, b) * 1.22, y, ratio(b, m), color=SOFT if b == m else INK)
        row_label(ax1, y, c["case"])
    panel_title(ax1, "a", "The bound never falls below the measured stack")
    key(ax1, [(RING, "measured in QEMU"), (dot(BLUE), "stackbound bound")])

    bytes_axis(ax2, lo, hi, len(short))
    for y, (label, v, m) in enumerate(short):
        ax2.plot([lo, v], [y, y], color=RULE, linewidth=0.6, zorder=1)
        ax2.plot([v, m], [y, y], color=RED, linewidth=0.9, zorder=2)
        ax2.plot(m, y, zorder=2, **RING)
        ax2.plot(v, y, zorder=3, **dot(RED))
        note(ax2, m * 1.22, y, f"short by {m - v} B")
        row_label(ax2, y, label)
    panel_title(ax2, "b", "Bounds that ignore interrupts or indirect calls fall below it", points=8)
    ax2.set_xlabel("stack, bytes (log scale)")
    return save(fig, outdir, "bound_vs_measured.svg")


def figure_precision(data, outdir):
    """The resolved bound against the every-address-taken-function fallback."""
    rows = [c for c in data["cases"] if c["modes"]["full"]["sites"]]
    if not rows:
        raise SystemExit("no case has an indirect call site")

    lo, hi = 50, 2600
    fig, ax = plt.subplots(figsize=(6.4, 0.36 * len(rows) + 1.0))
    bytes_axis(ax, lo, hi, len(rows))
    for y, c in enumerate(rows):
        m = c["measured"]
        full = c["modes"]["full"]["total"]
        blind = c["modes"]["indirect_any"]["total"]
        tiers = ", ".join(sorted(c["modes"]["full"]["tier_counts"]))
        ax.plot([lo, m], [y, y], color=RULE, linewidth=0.6, zorder=1)
        if blind > full:
            ax.plot([full, blind], [y, y], color=SOFT, linewidth=0.8, zorder=2)
            text = f"{blind - full} B tighter"
        else:
            text = f"both {full} B, nothing to narrow"
        ax.plot(m, y, zorder=2, **RING)
        ax.plot(blind, y, zorder=3, **dot(AMBER))
        ax.plot(full, y, zorder=4, **dot(BLUE))
        note(ax, max(blind, full) * 1.22, y, text)
        row_label(ax, y, f"{c['case']} (tier: {tiers})")
    key(
        ax,
        [
            (RING, "measured"),
            (dot(BLUE), "resolved"),
            (dot(AMBER), "every address-taken function"),
        ],
    )
    ax.set_xlabel("bound, bytes (log scale)")
    return save(fig, outdir, "indirect_precision.svg")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(ROOT, "results", "results.json"))
    ap.add_argument("--outdir", default=os.path.join(ROOT, "results"))
    args = ap.parse_args()

    if not os.path.exists(args.results):
        raise SystemExit(f"{args.results} not found: run tools/validate.py first")
    with open(args.results, encoding="utf-8") as fh:
        data = json.load(fh)

    os.makedirs(args.outdir, exist_ok=True)
    print("wrote", figure_soundness(data, args.outdir))
    print("wrote", figure_precision(data, args.outdir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
