#!/usr/bin/env python3
"""Regenerate Images/vt_threshold_sensitivity.pdf with a cleaner layout.

The primary-threshold label in the prior figure overlapped the curve at
t=20, making it hard to read. This version places the label in a fixed
corner box with a leader line, and offsets per-point annotations away
from the curve.
"""
from pathlib import Path

import matplotlib.pyplot as plt

THRESHOLDS = [2, 5, 10, 20, 39]
ODDS = [1.38, 1.31, 1.24, 1.35, 2.67]
PRIMARY = 20
OUT = Path(__file__).resolve().parent / "Images" / "vt_threshold_sensitivity.pdf"


def main() -> None:
    fig, ax = plt.subplots(figsize=(4.6, 2.8))

    ax.plot(THRESHOLDS, ODDS, marker="o", color="#1f4e79", linewidth=1.8,
            markersize=6, markerfacecolor="white",
            markeredgecolor="#1f4e79", markeredgewidth=1.5, zorder=3)

    ax.axhline(1.0, color="grey", linestyle=":", linewidth=1.0, zorder=1)
    ax.text(39.3, 1.02, "OR = 1 (no association)", fontsize=7,
            color="grey", ha="right", va="bottom")

    # Highlight primary threshold with a vertical guide rather than a
    # label-on-the-curve, so nothing overlaps the data line.
    primary_or = ODDS[THRESHOLDS.index(PRIMARY)]
    ax.axvline(PRIMARY, color="#c0392b", linestyle="--",
               linewidth=1.0, alpha=0.7, zorder=2)
    ax.scatter([PRIMARY], [primary_or], s=90,
               facecolor="#c0392b", edgecolor="#c0392b", zorder=4)

    ax.annotate(
        f"primary threshold\n$t={PRIMARY}$\nOR\u00a0=\u00a0{primary_or:.2f}",
        xy=(PRIMARY, primary_or),
        xytext=(PRIMARY, 2.70),
        textcoords="data",
        fontsize=8, ha="center", va="bottom",
        color="#c0392b",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                  edgecolor="#c0392b", linewidth=0.8),
        arrowprops=dict(arrowstyle="-", color="#c0392b", linewidth=0.8,
                        shrinkA=0, shrinkB=4),
    )

    offsets = {2: (0, 10), 5: (0, -14), 10: (0, -14), 39: (-6, -14)}
    for t, orv in zip(THRESHOLDS, ODDS):
        if t == PRIMARY:
            continue
        dx, dy = offsets[t]
        ax.annotate(f"{orv:.2f}", xy=(t, orv),
                    xytext=(dx, dy), textcoords="offset points",
                    fontsize=8, ha="center", color="#1f4e79")

    ax.set_xlabel("VirusTotal detection threshold $t$ (engines)", fontsize=9)
    ax.set_ylabel("Malware--expansion odds ratio", fontsize=9)
    ax.set_xticks(THRESHOLDS)
    ax.set_xlim(0, 42)
    ax.set_ylim(0.9, 3.3)
    ax.tick_params(axis="both", labelsize=8)
    ax.grid(True, axis="y", linestyle=":", linewidth=0.5, alpha=0.5)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)

    fig.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, bbox_inches="tight")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
