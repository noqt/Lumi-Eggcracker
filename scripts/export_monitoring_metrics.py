#!/usr/bin/env python3
"""Export read-only Lumi Eggcracker health to an explicitly owned textfile."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def run() -> int:
    from lumi_eggcracker.monitoring import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
