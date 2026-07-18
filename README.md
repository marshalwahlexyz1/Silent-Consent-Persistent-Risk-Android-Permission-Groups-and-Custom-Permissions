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
