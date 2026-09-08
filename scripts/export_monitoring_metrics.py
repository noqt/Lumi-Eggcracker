"""Export read-only Lumi Eggcracker health to an explicitly owned textfile."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def run() -> int:
    from lumi_eggcracker.monitoring import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
