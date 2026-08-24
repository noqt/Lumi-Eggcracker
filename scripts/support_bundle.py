"""Write a local redacted support bundle from a source checkout."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lumi_eggcracker.support_bundle import main

parser = argparse.ArgumentParser(description="write a local redacted Eggcracker support bundle")
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
raise SystemExit(main(args.output))
