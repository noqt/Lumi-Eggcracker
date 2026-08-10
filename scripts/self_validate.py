"""Run Eggcracker's local full qualification and produce a portable evidence pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pwd
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CLI = Path("/usr/local/bin/eggcracker")
POLICY = Path("/etc/lumi-eggcracker/policy.json")


def run(argv: list[str], *, timeout: int = 900) -> None:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or "qualification command failed"
        )


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def new_directory(path: Path) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError(
            "evidence directory must be a new absolute child of an existing directory"
        )
    path.mkdir(mode=0o700)
    return path


def doctor(operator: str) -> dict[str, Any]:
    result = subprocess.run(
        ["/usr/sbin/runuser", "-u", operator, "--", str(CLI), "doctor"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Eggcracker doctor failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or value.get("result") != "PASS":
        raise RuntimeError("Eggcracker doctor did not pass")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Eggcracker's complete local qualification against an installed instance."
    )
    parser.add_argument("--operator", required=True)
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--safetensors-assets-manifest", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise SystemExit("self-validation must run as root")
    evidence: Path | None = None
    summary: dict[str, Any] = {
        "result": "FAIL",
        "schema_version": "lumi-eggcracker.self-validation.v1",
    }
    try:
        evidence = new_directory(args.evidence_dir)
        if not CLI.is_file() or not POLICY.is_file() or POLICY.is_symlink():
            raise RuntimeError("Eggcracker is not installed")
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        if policy.get("operator_uid") is None or policy.get("source_commit") is None:
            raise RuntimeError("installed policy is invalid")
        workload = pwd.getpwuid(int(policy["workload_uid"])).pw_name
        if workload == args.operator:
            raise RuntimeError("installed workload identity must differ from operator")
        checked = doctor(args.operator)
        environment = {
            "catalogue": checked["catalogue"],
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "source_commit": policy["source_commit"],
            "validated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "version": checked["version"],
        }
        (evidence / "environment.json").write_text(
            json.dumps(environment, sort_keys=True) + "\n", encoding="utf-8"
        )
        (evidence / "doctor.json").write_text(
            json.dumps(checked, sort_keys=True) + "\n", encoding="utf-8"
        )
        jobs = (
            (
                "real-ai-smoke.json",
                [
                    "smoke_content_ai.py",
                    "--assets-manifest",
                    str(args.assets_manifest),
                    "--user",
                    workload,
                    "--repetitions",
                    "5",
                ],
            ),
            (
                "safetensors-ai-smoke.json",
                [
                    "smoke_safetensors_ai.py",
                    "--assets-manifest",
                    str(args.safetensors_assets_manifest),
                    "--user",
                    workload,
                    "--repetitions",
                    "5",
                ],
            ),
            (
                "content-matrix.json",
                [
                    "run_content_matrix.py",
                    "--assets-manifest",
                    str(args.assets_manifest),
                    "--user",
                    workload,
                    "--repetitions",
                    "100",
                ],
            ),
            (
                "benign-model-matrix.json",
                [
                    "run_content_benign_matrix.py",
                    "--assets-manifest",
                    str(args.assets_manifest),
                    "--user",
                    workload,
                    "--repetitions",
                    "300",
                ],
            ),
            (
                "content-adversarial-matrix.json",
                [
                    "run_content_adversarial_matrix.py",
                    "--assets-manifest",
                    str(args.assets_manifest),
                    "--user",
                    workload,
                    "--tree-repetitions",
                    "100",
                    "--startup-repetitions",
                    "20",
                    "--restart-repetitions",
                    "20",
                ],
            ),
            (
                "autonomous-regression.json",
                [
                    "run_autonomous_matrix.py",
                    "--discoveries",
                    "100",
                    "--approved",
                    "50",
                    "--benign",
                    "200",
                ],
            ),
            (
                "selected-workload-regression.json",
                [
                    "run_native_matrix.py",
                    "--fork-race-repetitions",
                    "100",
                    "--benign-repetitions",
                    "50",
                    "--restart-repetitions",
                    "20",
                    "--socket-attempts",
                    "100",
                ],
            ),
        )
        for filename, arguments in jobs:
            run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / arguments[0]),
                    *arguments[1:],
                    "--output",
                    str(evidence / filename),
                ]
            )
        summary.update(
            {
                "result": "PASS",
                "source_commit": policy["source_commit"],
                "version": checked["version"],
            }
        )
        (evidence / "validation.json").write_text(
            json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8"
        )
        report = "# Lumi Eggcracker local validation\n\nPASS: all precommitted 0.3.1 regression and 0.4 Safetensors/PyTorch qualification matrices completed on the installed instance.\n"
        (evidence / "report.md").write_text(report, encoding="utf-8")
        sums = "".join(
            f"{digest(path)}  {path.name}\n"
            for path in sorted(evidence.iterdir())
            if path.name != "SHA256SUMS"
        )
        (evidence / "SHA256SUMS").write_text(sums, encoding="utf-8")
        print(json.dumps({"evidence_dir": str(evidence), **summary}, sort_keys=True))
        return 0
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        summary["error"] = str(error)
        if evidence is not None:
            (evidence / "validation.json").write_text(
                json.dumps(summary, sort_keys=True) + "\n", encoding="utf-8"
            )
        raise SystemExit(f"self-validation failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
