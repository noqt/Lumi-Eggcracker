"""Prove model handling without inference runtime evidence is not killed."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from smoke_content_ai import assets

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
MODES = ("read", "hash", "map", "copy", "read", "hash", "map", "copy", "read", "map")


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("content benign matrix must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", type=int, default=300)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        args.repetitions != 300
        or args.output.exists()
        or args.output.is_symlink()
        or not args.output.parent.is_dir()
    ):
        raise SystemExit("output must be new and repetitions must equal 300")
    result: dict[str, object] = {"classes": {}, "kills": 0, "result": "FAIL"}
    try:
        _runner, model, _manifest = assets(args.assets_manifest)
        fixture = ROOT / "tests" / "fixtures" / "benign_model_handler.py"
        with tempfile.TemporaryDirectory(prefix="lumi-content-benign-", dir="/tmp") as raw:
            root = Path(raw)
            os.chmod(root, 0o755)
            for index in range(args.repetitions):
                mode = MODES[index % len(MODES)]
                destination = root / f"copy-{index}"
                before = set(DETECTIONS.glob("*.json"))
                process = subprocess.run(
                    [
                        "/usr/sbin/runuser",
                        "-u",
                        args.user,
                        "--",
                        sys.executable,
                        str(fixture),
                        str(model),
                        mode,
                        str(destination),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                if process.returncode:
                    raise RuntimeError(
                        process.stderr.strip() or "benign model handler was interrupted"
                    )
                new = set(DETECTIONS.glob("*.json")) - before
                if new:
                    result["kills"] = int(result["kills"]) + len(new)
                    raise RuntimeError("benign model handler received an autonomous detection")
                classes = result["classes"]
                assert isinstance(classes, dict)
                classes[mode] = int(classes.get(mode, 0)) + 1
        result["result"] = "PASS"
        args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        result["error"] = str(error)
        if not args.output.exists():
            args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"content benign matrix failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
