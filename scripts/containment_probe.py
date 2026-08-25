#!/usr/bin/env python3
"""Run the no-network Lumi Eggcracker containment-primitive probe."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lumi_eggcracker.containment_probe import main

if __name__ == "__main__":
    raise SystemExit(main())
