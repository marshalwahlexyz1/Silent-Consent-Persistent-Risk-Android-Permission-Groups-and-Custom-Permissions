#!/usr/bin/env python3
import csv
import json
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from androguard.core.axml import AXMLPrinter
from loguru import logger


ROOT = Path("/data/olawalea/Permission/Custom-Permission")
PAIR_CSV = ROOT / "provider_permission_pair_usage_analysis.csv"
PROBE_APP_DIR = ROOT / "probe-app"
MANIFEST_PATH = PROBE_APP_DIR / "app/src/main/AndroidManifest.xml"
TARGETS_PATH = PROBE_APP_DIR / "app/src/main/assets/provider_targets.json"
DEFINING_APK_DIR = Path("/data/olawalea/test/defininghashes")

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

logger.remove()


def normalize_name(package_name: str, raw: str) -> str:
    if raw.startswith("."):
        return package_name + raw
    if "." not in raw:
        return f"{package_name}.{raw}"
    return raw


def parse_provider_entries(apk_path: Path):
    with zipfile.ZipFile(apk_path, "r") as zf:
        raw = zf.read("AndroidManifest.xml")
    xml_bytes = AXMLPrinter(raw).get_xml()
    root = ET.fromstring(xml_bytes)
    package_name = root.get("package", "")
    providers = []
    for provider in root.findall(".//provider"):
        raw_name = provider.get(f"{ANDROID_NS}name") or ""
        if not raw_name:
            continue
        providers.append(
            {
                "name": normalize_name(package_name, raw_name),
                "authorities": [
                    a.strip()
                    for a in (provider.get(f"{ANDROID_NS}authorities") or "").split(";")
                    if a.strip()
                ],
                "permission": provider.get(f"{ANDROID_NS}permission") or "",
                "readPermission": provider.get(f"{ANDROID_NS}readPermission") or "",
                "writePermission": provider.get(f"{ANDROID_NS}writePermission") or "",
                "exported": (provider.get(f"{ANDROID_NS}exported") or "false").lower() == "true",
            }
        )
    return package_name, providers


def split_field(value: str):
    if not value:
        return []
    return [item.strip() for item in value.split(";") if item.strip()]


def canonical_permission(name: str, defining_package: str) -> str:
    if name.startswith(".") and defining_package:
        return f"{defining_package}{name}"
    return name


def choose_uri(authority: str, sample_uris):
    for uri in sample_uris:
        if authority in uri:
            return uri
    return f"content://{authority}/"


def render_manifest(permission_names):
    lines = ['<?xml version="1.0" encoding="utf-8"?>', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">', ""]
    for perm in sorted(permission_names):
        lines.append(f'    <uses-permission android:name="{perm}" />')
    lines.extend(
        [
            "",
            "    <application",
            '        android:allowBackup="true"',
            '        android:icon="@mipmap/ic_launcher"',
            '        android:label="@string/app_name"',
            '        android:roundIcon="@mipmap/ic_launcher_round"',
            '        android:supportsRtl="true"',
            '        android:theme="@style/Theme.CustomPermissionProbe">',
            "        <activity",
            '            android:name=".MainActivity"',
            '            android:exported="true">',
            "            <intent-filter>",
            '                <action android:name="android.intent.action.MAIN" />',
            "",
            '                <category android:name="android.intent.category.LAUNCHER" />',
            "            </intent-filter>",
            "        </activity>",
            "    </application>",
            "",
            "</manifest>",
            "",
        ]
    )
    return "\n".join(lines)


def safe_alias(idx: int) -> str:
    return f"CP{idx:03d}"


def main():
    csv.field_size_limit(10**9)
    rows = []
    permissions = set()
    with PAIR_CSV.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            rows.append((idx, row))
            defining_package_fallbacks = split_field(row.get("defining_package_names", ""))
            fallback_pkg = defining_package_fallbacks[0] if defining_package_fallbacks else ""
            permissions.add(canonical_permission(row["custom_permission"].strip(), fallback_pkg))

    targets = []
    for idx, row in rows:
        defining_package_fallbacks = split_field(row.get("defining_package_names", ""))
        requesting_packages = split_field(row.get("requesting_package_names", ""))
        custom_permission = canonical_permission(
            row["custom_permission"].strip(),
            defining_package_fallbacks[0] if defining_package_fallbacks else ""
        )
        defining_sha = row["defining_sha256"].strip()
        apk_path = DEFINING_APK_DIR / f"{defining_sha}.apk"
        if not apk_path.exists():
            continue

        sample_uris = [u for u in split_field(row.get("sample_requester_access_uris", "")) if u.startswith("content://")]

        try:
            parsed_package, providers = parse_provider_entries(apk_path)
        except Exception as exc:
            targets.append(
                {
                    "alias": safe_alias(idx),
                    "custom_permission": custom_permission,
                        "defining_package": defining_package_fallbacks[0] if defining_package_fallbacks else "",
                    "requesting_package": requesting_packages[0] if requesting_packages else "",
                    "authority": "",
                    "uri": "",
                    "exported": False,
                    "permission_via": "",
                    "provider_classes": split_field(row.get("provider_names", "")),
                    "sample_requester_uris": sample_uris[:5],
                    "notes": f"manifest parse failed: {type(exc).__name__}",
                }
            )
            continue

        matched = []
        for provider in providers:
            vias = []
            if provider["permission"] == custom_permission:
                vias.append("permission")
            if provider["readPermission"] == custom_permission:
                vias.append("readPermission")
            if provider["writePermission"] == custom_permission:
                vias.append("writePermission")
            if vias:
                matched.append((provider, ",".join(vias)))

        if not matched:
            targets.append(
                {
                    "alias": safe_alias(idx),
                    "custom_permission": custom_permission,
                    "defining_package": parsed_package or (defining_package_fallbacks[0] if defining_package_fallbacks else ""),
                    "requesting_package": requesting_packages[0] if requesting_packages else "",
                    "authority": "",
                    "uri": "",
                    "exported": False,
                    "permission_via": "",
                    "provider_classes": split_field(row.get("provider_names", "")),
                    "sample_requester_uris": sample_uris[:5],
                    "notes": "no matching provider authority recovered from manifest",
                }
            )
            continue

        for provider, via in matched:
            authorities = provider["authorities"] or [""]
            for authority in authorities:
                targets.append(
                    {
                        "alias": safe_alias(idx),
                        "custom_permission": custom_permission,
                        "defining_package": parsed_package,
                        "requesting_package": requesting_packages[0] if requesting_packages else "",
                        "authority": authority,
                        "uri": choose_uri(authority, sample_uris) if authority else "",
                        "exported": provider["exported"],
                        "permission_via": via,
                        "provider_classes": [provider["name"]],
                        "sample_requester_uris": sample_uris[:5],
                        "notes": "",
                    }
                )

    MANIFEST_PATH.write_text(render_manifest(permissions), encoding="utf-8")
    TARGETS_PATH.write_text(json.dumps(targets, indent=2), encoding="utf-8")

    no_authority = sum(1 for target in targets if not target["authority"])
    print(f"wrote {MANIFEST_PATH}")
    print(f"wrote {TARGETS_PATH}")
    print(f"permissions={len(permissions)}")
    print(f"targets={len(targets)}")
    print(f"targets_without_authority={no_authority}")


if __name__ == "__main__":
    main()
