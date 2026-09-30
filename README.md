# Silent Consent, Persistent Risk: Public Artifact Subset

Public artifact repository:

`Silent Consent, Persistent Risk: Android Permission Groups and Custom Permissions`

This release contains only the subset that is safe to publish while coordinated
disclosure remains active.

Included now:

- analysis scripts for market sensitivity, VT-threshold plotting, VT-threshold
  recomputation, provider-pair summarization, and probe-app data generation
- aggregate summaries that do not identify unresolved apps
- paper figures used for the revision
- a sanitized probe-app harness template
- the current AutoGrant Monitor APK artifact

Intentionally withheld until remediation is complete:

- unresolved app/package identities
- raw package-to-alias mappings
- exact custom permission strings for unresolved cases
- provider authorities and exploit-ready target catalogs
- pair-level custom-permission datasets that identify affected apps
- device-specific runtime logs and app-state dumps

Top-level layout:

- `scripts/`: analysis and figure-generation scripts
- `aggregates/`: safe aggregate summaries
- `figures/`: released figure PDFs
- `probe-app-template/`: sanitized generic probe harness
- `autogrant-monitor-apk/`: current APK artifact and release note

Running the scripts:

```
pip install -r requirements.txt
python scripts/analyze_market_sensitivity.py --help
```

Every script takes `--flags` for its inputs and outputs. Unset flags default to
files under two base folders, which you can set with environment variables:

- `CUSTOMPERM_DATA_DIR` (default `data/`): input datasets such as
  `sortedandrozoo.csv`, `metadata.csv`, `permission_autogrant_flows.csv`,
  `multi_version_packages.txt`, `expanding_packages.txt`, and the defining /
  requesting APK and report folders
- `CUSTOMPERM_OUTPUT_DIR` (default `output/`): generated CSV, Markdown, JSON and
  PDF files

`generate_probe_app_data.py` writes into `probe-app-template/probe-app` by
default; use `--probe-app-dir` to point it at a private copy instead. The input
datasets are not part of this public release.
