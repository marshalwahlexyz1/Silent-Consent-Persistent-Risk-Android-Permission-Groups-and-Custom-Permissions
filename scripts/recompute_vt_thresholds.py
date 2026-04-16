#!/usr/bin/env python3
import csv
import math
import os
import sqlite3
import sys
from pathlib import Path


METADATA_CSV = Path("/data/olawalea/ProjectCusPerm/metadata.csv")
SORTED_ANDROZOO_CSV = Path("/data/olawalea/ProjectCusPerm/sortedandrozoo.csv")
FLOWS_CSV = Path("/data/olawalea/ProjectCusPerm/permission_autogrant_flows.csv")

DB_PATH = Path("/tmp/vt_threshold_recompute.sqlite3")
OUT_CSV = Path("/data/olawalea/Permission/Custom-Permission/vt_threshold_recomputed_current.csv")
OUT_MD = Path("/data/olawalea/Permission/Custom-Permission/VT_THRESHOLD_RESPONSE.md")

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


def ensure_db() -> sqlite3.Connection:
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
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


def load_metadata(conn: sqlite3.Connection) -> None:
    sql = """
        INSERT INTO packages(package_name, version_count)
        VALUES (?, 1)
        ON CONFLICT(package_name) DO UPDATE SET version_count = version_count + 1
    """
    batch = []
    with METADATA_CSV.open(newline="", encoding="utf-8") as f:
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


def load_expanding(conn: sqlite3.Connection) -> None:
    sql = """
        INSERT INTO packages(package_name, expanding)
        VALUES (?, 1)
        ON CONFLICT(package_name) DO UPDATE SET expanding = 1
    """
    seen = set()
    batch = []
    with FLOWS_CSV.open(newline="", encoding="utf-8") as f:
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


def load_vt(conn: sqlite3.Connection) -> None:
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
    with SORTED_ANDROZOO_CSV.open(newline="", encoding="utf-8") as f:
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


def write_csv(rows) -> None:
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
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


def write_md(rows) -> None:
    lines = [
        "# VT Threshold Response",
        "",
        "This note answers the DIMVA review request to justify the VirusTotal threshold and to report sensitivity across multiple thresholds.",
        "",
        "## Current recomputation setup",
        "",
        "- Expansion set: `/data/olawalea/ProjectCusPerm/permission_autogrant_flows.csv`",
        "- Baseline denominator: multi-version apps from `/data/olawalea/ProjectCusPerm/metadata.csv`",
        "- Malware proxy: maximum `vt_detection` across all versions from `/data/olawalea/ProjectCusPerm/sortedandrozoo.csv`",
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
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    conn = ensure_db()
    try:
        print("1. Loading metadata version counts...")
        load_metadata(conn)
        print("2. Loading expanding-app markers...")
        load_expanding(conn)
        print("3. Loading max VT per package...")
        load_vt(conn)
        print("4. Computing thresholds...")
        rows = compute_threshold_rows(conn)
        write_csv(rows)
        write_md(rows)
        print(f"wrote {OUT_CSV}")
        print(f"wrote {OUT_MD}")
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
