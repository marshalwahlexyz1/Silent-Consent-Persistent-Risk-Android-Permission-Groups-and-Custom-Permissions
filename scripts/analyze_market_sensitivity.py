import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from paths import DATA_DIR, OUTPUT_DIR, ensure_parent


def read_set(path: Path) -> set[str]:
    with path.open(encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def normalize_markets(raw: str) -> set[str]:
    raw = raw.strip()
    if not raw:
        return {"unknown"}
    items = set()
    for part in raw.split(";"):
        part = part.strip().lower()
        if part:
            items.add(part)
    return items or {"unknown"}


def bucket(markets: set[str]) -> str:
    if not markets or markets == {"unknown"}:
        return "unknown_only"
    if len(markets) == 1:
        only = next(iter(markets))
        if only == "play.google.com":
            return "single_google_play"
        return "single_non_play"
    if "play.google.com" in markets:
        return "mixed_google_and_other"
    return "multi_non_play"


def pct(part: int, whole: int) -> float:
    return (100.0 * part / whole) if whole else 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AndroZoo market sensitivity check for permission-group expansion.")
    parser.add_argument("--sorted-androzoo", type=Path, default=DATA_DIR / "sortedandrozoo.csv",
                        help="AndroZoo CSV with pkg_name and markets columns.")
    parser.add_argument("--multi-version", type=Path, default=DATA_DIR / "multi_version_packages.txt",
                        help="Newline-separated list of multi-version packages.")
    parser.add_argument("--expanding", type=Path, default=DATA_DIR / "expanding_packages.txt",
                        help="Newline-separated list of expanding packages.")
    parser.add_argument("--output-csv", type=Path, default=OUTPUT_DIR / "market_sensitivity_summary.csv",
                        help="Output CSV path.")
    parser.add_argument("--output-md", type=Path, default=OUTPUT_DIR / "MARKET_SENSITIVITY_RESPONSE.md",
                        help="Output Markdown path.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    multi_version = read_set(args.multi_version)
    expanding = read_set(args.expanding)

    package_markets: dict[str, set[str]] = defaultdict(set)

    with args.sorted_androzoo.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        pkg_idx = header.index("pkg_name")
        markets_idx = header.index("markets")
        for row in reader:
            if len(row) <= markets_idx:
                continue
            package = row[pkg_idx].strip()
            if package not in multi_version:
                continue
            package_markets[package].update(normalize_markets(row[markets_idx]))

    baseline_counter = Counter()
    expanding_counter = Counter()
    market_count_counter = Counter()
    expanding_market_count_counter = Counter()

    for package in multi_version:
        markets = package_markets.get(package, {"unknown"})
        baseline_counter[bucket(markets)] += 1
        market_count_counter[min(len(markets), 5)] += 1
        if package in expanding:
            expanding_counter[bucket(markets)] += 1
            expanding_market_count_counter[min(len(markets), 5)] += 1

    rows = []
    for key in ["single_google_play", "single_non_play", "mixed_google_and_other", "multi_non_play", "unknown_only"]:
        rows.append(
            {
                "bucket": key,
                "baseline_apps": baseline_counter[key],
                "baseline_pct": f"{pct(baseline_counter[key], len(multi_version)):.2f}",
                "expanding_apps": expanding_counter[key],
                "expanding_pct": f"{pct(expanding_counter[key], len(expanding)):.2f}",
                "expansion_prevalence_within_bucket": f"{pct(expanding_counter[key], baseline_counter[key]):.2f}",
            }
        )

    with ensure_parent(args.output_csv).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# AndroZoo Market Sensitivity",
        "",
        "This note checks whether the permission-group expansion result is heavily",
        "dependent on package histories spanning multiple app markets.",
        "",
        f"- multi-version apps analyzed: `{len(multi_version):,}`",
        f"- expanding apps: `{len(expanding):,}`",
        "",
        "## Package-level market buckets",
        "",
        "| Bucket | Multi-version apps | Multi-version % | Expanding apps | Expanding % | Expansion prevalence within bucket |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    label_map = {
        "single_google_play": "Observed only on Google Play",
        "single_non_play": "Observed only on non-Play markets",
        "mixed_google_and_other": "Observed on Google Play and other markets",
        "multi_non_play": "Observed on multiple non-Play markets only",
        "unknown_only": "No market metadata",
    }
    for row in rows:
        lines.append(
            f"| {label_map[row['bucket']]} | {int(row['baseline_apps']):,} | {row['baseline_pct']}% | "
            f"{int(row['expanding_apps']):,} | {row['expanding_pct']}% | "
            f"{row['expansion_prevalence_within_bucket']}% |"
        )

    lines.extend(
        [
            "",
            "## Market-diversity counts",
            "",
            "| Distinct observed markets per package | Multi-version apps | Expanding apps |",
            "|---|---:|---:|",
        ]
    )
    for count in sorted(market_count_counter):
        label = "5+" if count == 5 else str(count)
        lines.append(
            f"| {label} | {market_count_counter[count]:,} | {expanding_market_count_counter[count]:,} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- This is a package-level sensitivity check, not a full market-isolated rerun.",
            "- It tells us whether the headline expansion result is dominated by packages whose observed version histories span multiple markets.",
            "- If the expanding set is still largely concentrated in single-market histories, then the review concern can be answered with a concrete statement rather than only a limitation.",
        ]
    )

    ensure_parent(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output_csv}")
    print(f"wrote {args.output_md}")
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
