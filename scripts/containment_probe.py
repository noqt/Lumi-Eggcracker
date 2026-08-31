#!/usr/bin/env python3
"""Run the no-network Lumi Eggcracker containment-primitive probe."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
try:
    source_entries = tuple(SOURCE_ROOT.iterdir())
except OSError:
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED") from None
if (
    len(source_entries) != 1
    or source_entries[0] != SOURCE_ROOT / "lumi_eggcracker"
    or source_entries[0].is_symlink()
    or not source_entries[0].is_dir()
):
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED")
sys.path.insert(0, str(SOURCE_ROOT))

from lumi_eggcracker.containment_probe import main

if __name__ == "__main__":
    raise SystemExit(main())
