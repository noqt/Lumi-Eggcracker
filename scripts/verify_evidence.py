"""Validate the minimal release evidence pack without interpreting extra claims."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REQUIRED = {
    "environment.json", "asset-provenance.json", "ai-smoke.json",
    "native-matrix.json", "install-cycle.json", "release-manifest.json",
    "SHA256SUMS", "report.md",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--require-source-commit", required=True)
    args = parser.parse_args()
    found = {item.name for item in args.evidence.iterdir()} if args.evidence.is_dir() else set()
    if found != REQUIRED:
        raise SystemExit(f"evidence pack files differ: {sorted(found)}")
    manifest = json.loads((args.evidence / "release-manifest.json").read_text(encoding="utf-8"))
    assets = json.loads((args.evidence / "asset-provenance.json").read_text(encoding="utf-8"))
    matrix = json.loads((args.evidence / "native-matrix.json").read_text(encoding="utf-8"))
    smoke = json.loads((args.evidence / "ai-smoke.json").read_text(encoding="utf-8"))
    if (
        manifest.get("source_commit") != args.require_source_commit
        or matrix.get("result") != "PASS"
        or smoke.get("result") != "PASS"
        or assets.get("schema_version") != "lumi-eggcracker.ai-smoke-assets.v1"
        or len(smoke.get("repetitions", [])) != 5
    ):
        raise SystemExit("evidence does not meet release gate")
    print(json.dumps({"result": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
