"""Validate the minimal release evidence pack without interpreting extra claims."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

REQUIRED = {
    "environment.json",
    "doctor.json",
    "real-ai-smoke.json",
    "safetensors-ai-smoke.json",
    "content-matrix.json",
    "benign-model-matrix.json",
    "content-adversarial-matrix.json",
    "autonomous-regression.json",
    "selected-workload-regression.json",
    "validation.json",
    "SHA256SUMS",
    "report.md",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--require-source-commit", required=True)
    args = parser.parse_args()
    found = {item.name for item in args.evidence.iterdir()} if args.evidence.is_dir() else set()
    if found != REQUIRED:
        raise SystemExit(f"evidence pack files differ: {sorted(found)}")
    values = {
        name: json.loads((args.evidence / name).read_text(encoding="utf-8"))
        for name in REQUIRED
        if name.endswith(".json")
    }
    environment = values["environment.json"]
    validation = values["validation.json"]
    if (
        environment.get("source_commit") != args.require_source_commit
        or validation.get("source_commit") != args.require_source_commit
        or validation.get("result") != "PASS"
        or not isinstance(environment.get("catalogue"), dict)
    ):
        raise SystemExit("evidence does not meet release gate")
    for name, value in values.items():
        if name in {"environment.json", "doctor.json", "validation.json"}:
            continue
        if value.get("result") != "PASS":
            raise SystemExit(f"evidence job did not pass: {name}")
    checksums: dict[str, str] = {}
    for line in (args.evidence / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise SystemExit("evidence checksum line is invalid")
        checksums[fields[1].removeprefix("*")] = fields[0]
    expected = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in args.evidence.iterdir()
        if path.name != "SHA256SUMS"
    }
    if checksums != expected:
        raise SystemExit("evidence checksums do not match")
    print(json.dumps({"result": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
