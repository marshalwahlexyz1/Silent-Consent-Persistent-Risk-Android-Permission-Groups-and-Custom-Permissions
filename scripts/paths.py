"""Shared default locations for the analysis scripts.

Every script accepts command-line flags for its individual inputs and outputs.
When a flag is omitted, the default is resolved under one of two base folders:

- ``CUSTOMPERM_DATA_DIR``: raw inputs (AndroZoo CSVs, package lists, APKs,
  reports). Defaults to ``<repo>/data``.
- ``CUSTOMPERM_OUTPUT_DIR``: generated CSV/Markdown/JSON/PDF files. Defaults
  to ``<repo>/output``.
"""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("CUSTOMPERM_DATA_DIR", REPO_ROOT / "data"))
OUTPUT_DIR = Path(os.environ.get("CUSTOMPERM_OUTPUT_DIR", REPO_ROOT / "output"))


def ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
