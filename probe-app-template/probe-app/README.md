# Probe App Template

This directory contains a sanitized version of the generic provider probe app
used in the custom-permission validation workflow.

What is included:

- Android app source for the reusable probe harness
- build files and UI code
- an empty provider target catalog template

What is intentionally omitted:

- unresolved custom-permission strings
- provider authorities
- package-name mappings
- generated target catalogs derived from unresolved disclosure cases

To use this template on a private/local dataset:

1. Generate a local target catalog and matching manifest entries from your own
   data.
2. Replace `app/src/main/assets/provider_targets.json`.
3. Add the corresponding `<uses-permission>` entries to
   `app/src/main/AndroidManifest.xml`.
4. Build and install the app on a test device.

This public version is a harness template, not the internal disclosure dataset.
