#!/usr/bin/env python3
"""Compatibility wrapper for the installed supported-path receipt tooling."""

from __future__ import annotations

import sys
from pathlib import Path

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from lumi_eggcracker import supported_path_receipt as _implementation

# Preserve the historical import surface for source-checkout callers and tests.
for _name in dir(_implementation):
    if _name not in {"__name__", "__package__", "__loader__", "__spec__"}:
        globals()[_name] = getattr(_implementation, _name)


if __name__ == "__main__":
    raise SystemExit(_implementation.main())
