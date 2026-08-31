#!/usr/bin/env python3
"""Start the reviewed Lumi Eggcracker hosted proof in a personal GitHub fork."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def run() -> int:
    from lumi_eggcracker.hosted_proof import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
