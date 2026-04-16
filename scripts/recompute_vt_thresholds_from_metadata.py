import csv
import math
import sys
from collections import Counter
from pathlib import Path


CSV_LIMIT = sys.maxsize
THRESHOLDS = (2, 5, 10)
BASE_DIR = Path("/data/olawalea/Permission/Custom-Permission")
META_PATH = Path("/data/olawalea/ProjectCusPerm/metadata.csv")
EXPANDING_PATH = Path("/tmp/expanding_packages.txt")
MULTI_PATH = Path("/tmp/multi_version_packages.txt")
OUT_CSV = BASE_DIR / "vt_threshold_recomputed_current.csv"
OUT_MD = BASE_DIR / "VT_THRESHOLD_RESPONSE.md"
OUT_CLASS_MD = BASE_DIR / "VT_CLASSIFICATION_SUMMARY.md"


def read_set(path: Path) -> set[str]:
    with path.open(encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def chi_square_2x2(a: int, b: int, c: int, d: int) -> float:
    total = a + b + c + d
    row1 = a + b
    row2 = c + d
    col1 = a + c
    col2 = b + d
    expected = (
        row1 * col1 / total,
        row1 * col2 / total,
        row2 * col1 / total,
        row2 * col2 / total,
    )
    observed = (a, b, c, d)
    return sum((obs - exp) ** 2 / exp for obs, exp in zip(observed, expected) if exp > 0)


def p_value_df1(chi2: float) -> float:
    return math.erfc(math.sqrt(max(chi2, 0.0) / 2.0))


def odds_ratio(a: int, b: int, c: int, d: int) -> float:
    if b == 0 or c == 0:
        return float("inf")
    return (a * d) / (b * c)


def top_rows(counter: Counter, limit: int = 12) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:limit]


def main() -> None:
    csv.field_size_limit(CSV_LIMIT)

    expanding = read_set(EXPANDING_PATH)
    multi = read_set(MULTI_PATH)

    max_vt_by_pkg: dict[str, int] = {}
    class_at_max_vt: dict[str, str] = {}

    with META_PATH.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        pkg_idx = header.index("package_name")
        vt_idx = header.index("vt_detection")
        class_idx = header.index("classification")

        for row in reader:
            if len(row) <= class_idx:
                continue
            pkg = row[pkg_idx].strip()
            if pkg not in multi:
                continue

            vt_raw = row[vt_idx].strip()
            try:
                vt = int(vt_raw) if vt_raw else 0
            except ValueError:
                vt = 0

            classification = row[class_idx].strip() or "Unknown"
            prev_vt = max_vt_by_pkg.get(pkg)
            prev_class = class_at_max_vt.get(pkg, "Unknown")

            if prev_vt is None or vt > prev_vt:
                max_vt_by_pkg[pkg] = vt
                class_at_max_vt[pkg] = classification
            elif vt == prev_vt and prev_class == "Unknown" and classification != "Unknown":
                class_at_max_vt[pkg] = classification

    rows = []
    expanding_counter = Counter()
    baseline_counter = Counter()

    for threshold in THRESHOLDS:
        malware_exp = sum(1 for pkg in expanding if max_vt_by_pkg.get(pkg, 0) >= threshold)
        benign_exp = len(expanding) - malware_exp
        malware_base = sum(1 for pkg in multi if max_vt_by_pkg.get(pkg, 0) >= threshold)
        benign_base = len(multi) - malware_base
        malware_nonexp = malware_base - malware_exp
        benign_nonexp = (len(multi) - len(expanding)) - malware_nonexp
        chi2 = chi_square_2x2(malware_exp, malware_nonexp, benign_exp, benign_nonexp)

        row = {
            "threshold": threshold,
            "multi_version_total": len(multi),
            "expanding_total": len(expanding),
            "malware_expanding": malware_exp,
            "benign_expanding": benign_exp,
            "malware_baseline": malware_base,
            "benign_baseline": benign_base,
            "malware_pct_expanding": 100 * malware_exp / len(expanding),
            "malware_pct_baseline": 100 * malware_base / len(multi),
            "enrichment_ratio": (100 * malware_exp / len(expanding)) / (100 * malware_base / len(multi)) if malware_base else 0,
            "odds_ratio": odds_ratio(malware_exp, malware_nonexp, benign_exp, benign_nonexp),
            "chi2": chi2,
            "p_value": p_value_df1(chi2),
        }
        rows.append(row)

    for pkg in multi:
        vt = max_vt_by_pkg.get(pkg, 0)
        classification = class_at_max_vt.get(pkg, "Unknown")
        if vt >= 2:
            baseline_counter[classification] += 1
            if pkg in expanding:
                expanding_counter[classification] += 1

    with OUT_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# VT Threshold Response",
        "",
        "## Threshold sensitivity",
        "",
        "| VT threshold | Expanding apps | Malware expanding | Malware expanding % | Baseline apps | Malware baseline | Malware baseline % | Enrichment | Odds ratio | Chi-squared | p-value |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| >= {row['threshold']} | {row['expanding_total']:,} | {row['malware_expanding']:,} | "
            f"{row['malware_pct_expanding']:.2f}% | {row['multi_version_total']:,} | "
            f"{row['malware_baseline']:,} | {row['malware_pct_baseline']:.2f}% | "
            f"{row['enrichment_ratio']:.3f}x | {row['odds_ratio']:.3f} | {row['chi2']:.1f} | {row['p_value']:.3e} |"
        )

    lines.extend(
        [
            "",
            "## Reviewer-facing interpretation",
            "",
            "- `VT >= 2` remains the primary threshold because low multi-engine agreement has precedent in Android malware research, but it is treated as a proxy rather than ground truth.",
            "- We now report sensitivity at `VT >= 2`, `VT >= 5`, and `VT >= 10`, exactly as suggested by Reviewer 33B.",
            "- The key issue for the revision is whether the malware-comparison claim stays directionally stable across stricter thresholds.",
        ]
    )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")

    class_lines = [
        "# VT Classification Summary",
        "",
        "These counts use the `classification` label associated with each app's highest-VT version in `metadata.csv`.",
        "",
        "## Expanding apps with `VT >= 2`",
        "",
        "| Classification | Count |",
        "|---|---:|",
    ]
    for label, count in top_rows(expanding_counter):
        class_lines.append(f"| {label} | {count:,} |")

    class_lines.extend(
        [
            "",
            "## All multi-version apps with `VT >= 2`",
            "",
            "| Classification | Count |",
            "|---|---:|",
        ]
    )
    for label, count in top_rows(baseline_counter):
        class_lines.append(f"| {label} | {count:,} |")

    class_lines.extend(
        [
            "",
            "## Recommended framing",
            "",
            "- The VT-positive bucket should be described as apps flagged by multiple engines as malicious or unwanted, not as a manually verified malware-family ground truth.",
            "- The `classification` metadata can provide a coarse composition summary, but it should not be overclaimed as an exact malware-family taxonomy.",
        ]
    )
    OUT_CLASS_MD.write_text("\n".join(class_lines) + "\n", encoding="utf-8")

    print(f"wrote {OUT_CSV}")
    print(f"wrote {OUT_MD}")
    print(f"wrote {OUT_CLASS_MD}")
    for row in rows:
        print(row)
    print("top_expanding", top_rows(expanding_counter))
    print("top_baseline", top_rows(baseline_counter))


if __name__ == "__main__":
    main()
