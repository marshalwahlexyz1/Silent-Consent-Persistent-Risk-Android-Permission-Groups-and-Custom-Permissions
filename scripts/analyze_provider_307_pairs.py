#!/usr/bin/env python3
"""
Build a review-facing evidence table for the 307 provider custom-permission pairs.

The script consumes the existing provider pair CSV and the JSON reports emitted by
`cptainterupdated.py`, then produces:
  1. a per-pair CSV with defining-side and requesting-side evidence
  2. a compact JSON summary for paper-writing / review responses

This is intentionally conservative:
- it keeps the existing 307-row pair source as-is
- it does not try to re-derive signer identity
- it reports strict and loose evidence separately instead of conflating them

The core-vs-library split is heuristic. "Core" means the call-site class belongs
to the requesting app's package namespace. "Third-party" means the class belongs
to a known library / framework namespace. Everything else is left as "unknown".
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from paths import DATA_DIR, OUTPUT_DIR, ensure_parent


csv.field_size_limit(sys.maxsize)

LIBRARY_PREFIXES = (
    "android.",
    "androidx.",
    "com.android.",
    "com.google.",
    "com.facebook.",
    "com.flurry.",
    "com.adjust.",
    "com.appsflyer.",
    "com.amplitude.",
    "com.mixpanel.",
    "com.segment.",
    "com.crashlytics.",
    "com.google.firebase.",
    "com.google.android.gms.",
    "com.squareup.",
    "com.bumptech.",
    "com.unity3d.",
    "com.airbnb.",
    "com.paypal.",
    "com.branch.",
    "com.onesignal.",
    "com.revenuecat.",
    "dagger.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "okhttp3.",
    "okio.",
    "org.apache.",
    "org.bouncycastle.",
    "org.chromium.",
    "org.greenrobot.",
    "org.intellij.",
    "org.jetbrains.",
    "org.json.",
    "org.slf4j.",
    "retrofit2.",
    "rx.",
    "io.flutter.",
    "io.reactivex.",
)


def split_multi(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]


def split_shas(value: Optional[str]) -> List[str]:
    return [part for part in split_multi(value) if re.fullmatch(r"[0-9A-Fa-f]{64}", part)]


def normalize_report_obj(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                return item
        return {}
    return obj if isinstance(obj, dict) else {}


def load_report(report_dir: Path, sha256: str, cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    key = (str(report_dir), sha256)
    if key in cache:
        return cache[key]
    path = report_dir / f"{sha256}.json"
    if not path.exists():
        cache[key] = None
        return None
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            report = normalize_report_obj(json.load(handle))
    except Exception:
        cache[key] = None
        return None
    cache[key] = report or None
    return cache[key]


def pick_sha_and_report(
    shas: Sequence[str],
    report_dir: Path,
    cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]],
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    for sha in shas:
        report = load_report(report_dir, sha, cache)
        if report:
            return sha, report
    return (shas[0] if shas else None), None


def dotted_class_name(raw_name: Optional[str]) -> str:
    if not raw_name:
        return ""
    name = raw_name.strip()
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1].replace("/", ".")
    return name


def classify_callsite(class_name: str, app_packages: Iterable[str]) -> str:
    dotted = dotted_class_name(class_name)
    if not dotted:
        return "unknown"
    package_candidates = {pkg for pkg in app_packages if pkg}
    for pkg in package_candidates:
        if dotted == pkg or dotted.startswith(pkg + "."):
            return "core"
    if dotted.startswith(LIBRARY_PREFIXES):
        return "third_party"
    return "unknown"


def dominant_access_profile(counter: Counter) -> str:
    core = counter.get("core", 0)
    third = counter.get("third_party", 0)
    unknown = counter.get("unknown", 0)
    if core and third:
        return "mixed"
    if core:
        return "core_only"
    if third:
        return "third_party_only"
    if unknown:
        return "unknown_only"
    return "no_provider_access"


def short_list(values: Iterable[str], limit: int = 5) -> str:
    deduped: List[str] = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
        if len(deduped) >= limit:
            break
    return ";".join(deduped)


def pairwise_provider_evidence(
    custom_permission: str,
    defining_report: Optional[Dict[str, Any]],
    requesting_report: Optional[Dict[str, Any]],
    requesting_app_packages: Sequence[str],
) -> Dict[str, Any]:
    defining_perm = (defining_report or {}).get("permissions", {}).get(custom_permission, {})
    requesting_perm = (requesting_report or {}).get("permissions", {}).get(custom_permission, {})

    attached_components = defining_perm.get("attached_components", []) if isinstance(defining_perm, dict) else []
    attached_providers = [c for c in attached_components if c.get("type") == "provider"]
    provider_names = [c.get("name", "") for c in attached_providers if c.get("name")]
    attachment_via = sorted({c.get("via", "") for c in attached_providers if c.get("via")})

    providers = (defining_report or {}).get("providers", {}) if isinstance((defining_report or {}).get("providers", {}), dict) else {}
    storage_types = []
    exported_count = 0
    provider_vulns: List[str] = []
    total_data_fields = 0
    total_mime_types = 0
    total_provider_taint_flows = 0
    total_aosp_api_refs = 0
    for provider_name in provider_names:
        provider_data = providers.get(provider_name, {})
        storage_type = provider_data.get("storage_type")
        if storage_type:
            storage_types.append(storage_type)
        if provider_data.get("exported"):
            exported_count += 1
        provider_vulns.extend(provider_data.get("vulnerabilities", []) or [])
        total_data_fields += len(provider_data.get("data_fields", []) or [])
        total_mime_types += len(provider_data.get("mime_types", []) or [])
        total_provider_taint_flows += len(provider_data.get("taint_flows", []) or [])
        total_aosp_api_refs += len(provider_data.get("aosp_protected_apis", []) or [])

    provider_accesses = (requesting_report or {}).get("provider_accesses", []) or []
    requester_access_profile = Counter()
    strict_matches = []
    loose_uri_matches = []
    for access in provider_accesses:
        classification = classify_callsite(access.get("class", ""), requesting_app_packages)
        requester_access_profile[classification] += 1
        access_provider = access.get("provider")
        if access_provider and access_provider in provider_names:
            strict_matches.append(access)
        uri = access.get("uri") or ""
        defining_pkg = (defining_report or {}).get("package", "")
        if uri and defining_pkg and defining_pkg in uri:
            loose_uri_matches.append(access)

    strict_profile = Counter(classify_callsite(access.get("class", ""), requesting_app_packages) for access in strict_matches)
    loose_profile = Counter(classify_callsite(access.get("class", ""), requesting_app_packages) for access in loose_uri_matches)

    return {
        "defining_permission_present": bool(defining_perm),
        "requesting_permission_present": bool(requesting_perm),
        "requesting_permission_used_in_manifest": bool(requesting_perm.get("used_in_manifest")) if isinstance(requesting_perm, dict) else False,
        "requesting_permission_used_in_components": bool(requesting_perm.get("used_in_components")) if isinstance(requesting_perm, dict) else False,
        "provider_attachment_count": len(provider_names),
        "provider_attachment_via": ";".join(attachment_via),
        "provider_names": ";".join(provider_names),
        "provider_exported_count": exported_count,
        "provider_storage_types": ";".join(sorted(set(storage_types))),
        "provider_vulnerabilities": short_list(provider_vulns, limit=10),
        "provider_protects_data_count": len(defining_perm.get("protects_data", []) or []) if isinstance(defining_perm, dict) else 0,
        "provider_data_fields_count": total_data_fields,
        "provider_mime_types_count": total_mime_types,
        "provider_taint_flow_count": total_provider_taint_flows,
        "provider_aosp_api_count": total_aosp_api_refs,
        "requester_provider_access_count": len(provider_accesses),
        "strict_matched_access_count": len(strict_matches),
        "strict_matched_access_profile": dominant_access_profile(strict_profile),
        "loose_uri_match_count": len(loose_uri_matches),
        "loose_uri_match_profile": dominant_access_profile(loose_profile),
        "requester_access_core_count": requester_access_profile.get("core", 0),
        "requester_access_third_party_count": requester_access_profile.get("third_party", 0),
        "requester_access_unknown_count": requester_access_profile.get("unknown", 0),
        "requester_access_profile": dominant_access_profile(requester_access_profile),
        "sample_requester_access_classes": short_list(
            dotted_class_name(access.get("class", "")) for access in provider_accesses
        ),
        "sample_requester_access_uris": short_list((access.get("uri") or "") for access in provider_accesses),
    }


def build_rows(
    pairs_csv: Path,
    defining_reports: Path,
    requesting_reports: Path,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}
    rows: List[Dict[str, Any]] = []

    with pairs_csv.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for source_row in reader:
            defining_shas = split_shas(source_row.get("defining_sha256s"))
            requesting_shas = split_shas(source_row.get("requesting_sha256s"))
            if not defining_shas or not requesting_shas:
                continue

            custom_permission = (source_row.get("custom_permission") or "").strip()
            defining_packages = split_multi(source_row.get("defining_package_names"))
            requesting_packages = split_multi(source_row.get("requesting_package_names"))

            defining_sha, defining_report = pick_sha_and_report(defining_shas, defining_reports, cache)
            requesting_sha, requesting_report = pick_sha_and_report(requesting_shas, requesting_reports, cache)

            requesting_app_packages = list(dict.fromkeys(
                requesting_packages + [((requesting_report or {}).get("package") or "").strip()]
            ))

            evidence = pairwise_provider_evidence(
                custom_permission=custom_permission,
                defining_report=defining_report,
                requesting_report=requesting_report,
                requesting_app_packages=requesting_app_packages,
            )

            rows.append({
                "custom_permission": custom_permission,
                "defining_sha256": defining_sha or "",
                "requesting_sha256": requesting_sha or "",
                "defining_sha_count": len(defining_shas),
                "requesting_sha_count": len(requesting_shas),
                "defining_package_names": ";".join(defining_packages),
                "requesting_package_names": ";".join(requesting_packages),
                "defining_report_package": ((defining_report or {}).get("package") or "").strip(),
                "requesting_report_package": ((requesting_report or {}).get("package") or "").strip(),
                "defining_report_found": bool(defining_report),
                "requesting_report_found": bool(requesting_report),
                "package_sets_disjoint": bool(set(defining_packages).isdisjoint(set(requesting_packages))) if defining_packages and requesting_packages else False,
                **evidence,
            })

    summary = summarize(rows)
    return rows, summary


def summarize(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    access_profiles = Counter(row["requester_access_profile"] for row in rows)
    strict_profiles = Counter(row["strict_matched_access_profile"] for row in rows)
    storage_types = Counter()
    for row in rows:
        for storage_type in split_multi(row.get("provider_storage_types", "")):
            storage_types[storage_type] += 1

    return {
        "total_pairs": len(rows),
        "pairs_with_defining_report": sum(1 for row in rows if row["defining_report_found"]),
        "pairs_with_requesting_report": sum(1 for row in rows if row["requesting_report_found"]),
        "pairs_with_provider_attachment": sum(1 for row in rows if row["provider_attachment_count"] > 0),
        "pairs_with_exported_provider": sum(1 for row in rows if row["provider_exported_count"] > 0),
        "pairs_with_requesting_permission_entry": sum(1 for row in rows if row["requesting_permission_present"]),
        "pairs_with_requesting_permission_manifest_use": sum(1 for row in rows if row["requesting_permission_used_in_manifest"]),
        "pairs_with_any_requester_provider_access": sum(1 for row in rows if row["requester_provider_access_count"] > 0),
        "pairs_with_strict_matched_access": sum(1 for row in rows if row["strict_matched_access_count"] > 0),
        "pairs_with_loose_uri_match": sum(1 for row in rows if row["loose_uri_match_count"] > 0),
        "pairs_with_protects_data_signal": sum(1 for row in rows if row["provider_protects_data_count"] > 0),
        "pairs_package_sets_disjoint": sum(1 for row in rows if row["package_sets_disjoint"]),
        "requester_access_profiles": dict(access_profiles),
        "strict_match_profiles": dict(strict_profiles),
        "provider_storage_types": dict(storage_types),
    }


def write_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    if not rows:
        raise ValueError("No rows to write")
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, sort_keys=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze the 307 provider custom-permission pairs.")
    parser.add_argument(
        "--pairs-csv",
        default=DATA_DIR / "custom_permissions_provider_normal_2plusnew.csv",
        help="CSV containing the provider custom-permission pairs.",
    )
    parser.add_argument(
        "--defining-reports",
        default=DATA_DIR / "defininghashes_reports",
        help="Directory containing defining-app JSON reports.",
    )
    parser.add_argument(
        "--requesting-reports",
        default=DATA_DIR / "requestinghashes_reports",
        help="Directory containing requesting-app JSON reports.",
    )
    parser.add_argument(
        "--output-csv",
        default=OUTPUT_DIR / "provider_permission_pair_usage_analysis.csv",
        help="Output CSV path.",
    )
    parser.add_argument(
        "--output-json",
        default=OUTPUT_DIR / "provider_permission_pair_usage_summary.json",
        help="Output JSON summary path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, summary = build_rows(
        pairs_csv=Path(args.pairs_csv),
        defining_reports=Path(args.defining_reports),
        requesting_reports=Path(args.requesting_reports),
    )
    write_csv(ensure_parent(Path(args.output_csv)), rows)
    write_json(ensure_parent(Path(args.output_json)), summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
