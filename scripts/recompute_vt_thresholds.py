#!/usr/bin/env python3
import argparse
import csv
import math
import sqlite3
import sys
from pathlib import Path

from paths import DATA_DIR, OUTPUT_DIR, ensure_parent

THRESHOLDS = [2, 5, 10]
BATCH = 20000

csv.field_size_limit(sys.maxsize)


def chi_square_2x2(a: int, b: int, c: int, d: int) -> float:
    total = a + b + c + d
    if total == 0:
        return 0.0
    row1 = a + b
    row2 = c + d
    col1 = a + c
    col2 = b + d
    expected = [
        row1 * col1 / total,
        row1 * col2 / total,
        row2 * col1 / total,
        row2 * col2 / total,
    ]
    observed = [a, b, c, d]
    chi2 = 0.0
    for obs, exp in zip(observed, expected):
        if exp > 0:
            chi2 += (obs - exp) ** 2 / exp
    return chi2


def chi_square_p_df1(chi2: float) -> float:
    return math.erfc(math.sqrt(max(chi2, 0.0) / 2.0))


def odds_ratio(a: int, b: int, c: int, d: int) -> float:
    if b == 0 or c == 0:
        return float("inf")
    return (a * d) / (b * c)


def ensure_db(db_path: Path) -> sqlite3.Connection:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(ensure_parent(db_path))
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-200000")
    conn.execute(
        """
        CREATE TABLE packages (
            package_name TEXT PRIMARY KEY,
            version_count INTEGER NOT NULL DEFAULT 0,
            max_vt INTEGER NOT NULL DEFAULT 0,
            expanding INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    return conn


def load_metadata(conn: sqlite3.Connection, metadata_csv: Path) -> None:
    sql = """
        INSERT INTO packages(package_name, version_count)
        VALUES (?, 1)
        ON CONFLICT(package_name) DO UPDATE SET version_count = version_count + 1
    """
    batch = []
    with metadata_csv.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = (row.get("package_name") or "").strip()
            if not pkg:
                continue
            batch.append((pkg,))
            if len(batch) >= BATCH:
                conn.executemany(sql, batch)
                batch.clear()
        if batch:
            conn.executemany(sql, batch)
    conn.commit()


def load_expanding(conn: sqlite3.Connection, flows_csv: Path) -> None:
    sql = """
        INSERT INTO packages(package_name, expanding)
        VALUES (?, 1)
        ON CONFLICT(package_name) DO UPDATE SET expanding = 1
    """
    seen = set()
    batch = []
    with flows_csv.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = (row.get("package_name") or "").strip()
            if not pkg or pkg in seen:
                continue
            seen.add(pkg)
            batch.append((pkg,))
            if len(batch) >= BATCH:
                conn.executemany(sql, batch)
                batch.clear()
        if batch:
            conn.executemany(sql, batch)
    conn.commit()


def load_vt(conn: sqlite3.Connection, sorted_androzoo_csv: Path) -> None:
    sql = """
        INSERT INTO packages(package_name, max_vt)
        VALUES (?, ?)
        ON CONFLICT(package_name) DO UPDATE SET
            max_vt = CASE
                WHEN excluded.max_vt > packages.max_vt THEN excluded.max_vt
                ELSE packages.max_vt
            END
    """
    batch = []
    with sorted_androzoo_csv.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pkg = (row.get("pkg_name") or "").strip()
            if not pkg:
                continue
            vt_raw = (row.get("vt_detection") or "").strip()
            try:
                vt = int(vt_raw) if vt_raw else 0
            except ValueError:
                vt = 0
            batch.append((pkg, vt))
            if len(batch) >= BATCH:
                conn.executemany(sql, batch)
                batch.clear()
        if batch:
            conn.executemany(sql, batch)
    conn.commit()


def fetch_scalar(conn: sqlite3.Connection, sql: str) -> int:
    return int(conn.execute(sql).fetchone()[0])


def compute_threshold_rows(conn: sqlite3.Connection):
    rows = []
    multi_version_total = fetch_scalar(
        conn,
        "SELECT COUNT(*) FROM packages WHERE version_count > 1"
    )
    expanding_total = fetch_scalar(
        conn,
        "SELECT COUNT(*) FROM packages WHERE version_count > 1 AND expanding = 1"
    )

    for threshold in THRESHOLDS:
        malware_expanding = fetch_scalar(
            conn,
            f"""
            SELECT COUNT(*) FROM packages
            WHERE version_count > 1 AND expanding = 1 AND max_vt >= {threshold}
            """
        )
        benign_expanding = expanding_total - malware_expanding
        malware_baseline = fetch_scalar(
            conn,
            f"""
            SELECT COUNT(*) FROM packages
            WHERE version_count > 1 AND max_vt >= {threshold}
            """
        )
        benign_baseline = multi_version_total - malware_baseline

        malware_nonexp = malware_baseline - malware_expanding
        benign_nonexp = benign_baseline - benign_expanding

        chi2 = chi_square_2x2(malware_expanding, malware_nonexp, benign_expanding, benign_nonexp)
        p = chi_square_p_df1(chi2)
        or_value = odds_ratio(malware_expanding, malware_nonexp, benign_expanding, benign_nonexp)

        malware_pct_expanding = (100.0 * malware_expanding / expanding_total) if expanding_total else 0.0
        malware_pct_baseline = (100.0 * malware_baseline / multi_version_total) if multi_version_total else 0.0
        enrichment = (malware_pct_expanding / malware_pct_baseline) if malware_pct_baseline else 0.0

        rows.append(
            {
                "threshold": threshold,
                "multi_version_total": multi_version_total,
                "expanding_total": expanding_total,
                "malware_expanding": malware_expanding,
                "benign_expanding": benign_expanding,
                "malware_baseline": malware_baseline,
                "benign_baseline": benign_baseline,
                "malware_pct_expanding": malware_pct_expanding,
                "malware_pct_baseline": malware_pct_baseline,
                "enrichment_ratio": enrichment,
                "odds_ratio": or_value,
                "chi2": chi2,
                "p_value": p,
            }
        )
    return rows


def write_csv(rows, out_csv: Path) -> None:
    with ensure_parent(out_csv).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "threshold",
                "multi_version_total",
                "expanding_total",
                "malware_expanding",
                "benign_expanding",
                "malware_baseline",
                "benign_baseline",
                "malware_pct_expanding",
                "malware_pct_baseline",
                "enrichment_ratio",
                "odds_ratio",
                "chi2",
                "p_value",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_md(rows, args: argparse.Namespace) -> None:
    lines = [
        "# VT Threshold Response",
        "",
        "This note answers the DIMVA review request to justify the VirusTotal threshold and to report sensitivity across multiple thresholds.",
        "",
        "## Current recomputation setup",
        "",
        f"- Expansion set: `{args.flows_csv}`",
        f"- Baseline denominator: multi-version apps from `{args.metadata_csv}`",
        f"- Malware proxy: maximum `vt_detection` across all versions from `{args.sorted_androzoo}`",
        "- Missing VT values treated as `0` detections",
        "",
        "## Threshold sensitivity",
        "",
        "| VT threshold | Expanding apps | Malware expanding | Malware expanding % | Baseline apps | Malware baseline | Malware baseline % | Enrichment | Odds ratio | Chi-squared |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| >= {row['threshold']} | {row['expanding_total']:,} | {row['malware_expanding']:,} | "
            f"{row['malware_pct_expanding']:.2f}% | {row['multi_version_total']:,} | {row['malware_baseline']:,} | "
            f"{row['malware_pct_baseline']:.2f}% | {row['enrichment_ratio']:.3f}x | {row['odds_ratio']:.3f} | {row['chi2']:.1f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- The primary paper threshold can remain `VT >= 2`, but the revision should add the table above.",
            "- The text should explicitly say that the qualitative association remains stable or changes across stricter thresholds, based on the recomputed table.",
            "- VT should be described as a malware/unwanted-app proxy rather than ground truth.",
        ]
    )
    ensure_parent(args.output_md).write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recompute malware/expansion association across VT thresholds.")
    parser.add_argument("--metadata-csv", type=Path, default=DATA_DIR / "metadata.csv",
                        help="AndroZoo metadata CSV (package_name per version).")
    parser.add_argument("--sorted-androzoo", type=Path, default=DATA_DIR / "sortedandrozoo.csv",
                        help="AndroZoo CSV with pkg_name and vt_detection columns.")
    parser.add_argument("--flows-csv", type=Path, default=DATA_DIR / "permission_autogrant_flows.csv",
                        help="CSV of permission auto-grant flows (package_name column).")
    parser.add_argument("--db-path", type=Path, default=OUTPUT_DIR / "vt_threshold_recompute.sqlite3",
                        help="Scratch SQLite database (recreated on each run).")
    parser.add_argument("--output-csv", type=Path, default=OUTPUT_DIR / "vt_threshold_recomputed_current.csv",
                        help="Output CSV path.")
    parser.add_argument("--output-md", type=Path, default=OUTPUT_DIR / "VT_THRESHOLD_RESPONSE.md",
                        help="Output Markdown path.")
    return parser.parse_args()


def main():
    args = parse_args()
    conn = ensure_db(args.db_path)
    try:
        print("1. Loading metadata version counts...")
        load_metadata(conn, args.metadata_csv)
        print("2. Loading expanding-app markers...")
        load_expanding(conn, args.flows_csv)
        print("3. Loading max VT per package...")
        load_vt(conn, args.sorted_androzoo)
        print("4. Computing thresholds...")
        rows = compute_threshold_rows(conn)
        write_csv(rows, args.output_csv)
        write_md(rows, args)
        print(f"wrote {args.output_csv}")
        print(f"wrote {args.output_md}")
        for row in rows:
            print(
                f"VT>={row['threshold']}: "
                f"expanding malware {row['malware_expanding']:,}/{row['expanding_total']:,} "
                f"({row['malware_pct_expanding']:.2f}%), "
                f"baseline {row['malware_baseline']:,}/{row['multi_version_total']:,} "
                f"({row['malware_pct_baseline']:.2f}%), "
                f"OR={row['odds_ratio']:.3f}, enrich={row['enrichment_ratio']:.3f}x"
            )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
