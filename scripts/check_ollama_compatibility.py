"""Check one Ollama launcher/runner pair against Eggcracker's exact release pins."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lumi_eggcracker import __version__
from lumi_eggcracker.elfmarkers import (
    OLLAMA_LAUNCHER_EVIDENCE_ID,
    OLLAMA_RUNNER_EVIDENCE_ID,
    RuntimeEvidence,
    inspect_ollama_descriptor,
)

SCHEMA = "lumi-eggcracker.ollama-compatibility.v1"
PROFILE = "content.gguf-ollama"


def _absolute_path(parser: argparse.ArgumentParser, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        parser.error("Ollama binary paths must be absolute")
    return path


def _inspect_regular_path(path: Path) -> RuntimeEvidence | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        return inspect_ollama_descriptor(descriptor)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def compatibility(launcher: Path, runner: Path) -> dict[str, object]:
    launcher_evidence = _inspect_regular_path(launcher)
    runner_evidence = _inspect_regular_path(runner)
    launcher_supported = (
        launcher_evidence is not None
        and launcher_evidence.evidence_id == OLLAMA_LAUNCHER_EVIDENCE_ID
    )
    runner_supported = (
        runner_evidence is not None
        and runner_evidence.evidence_id == OLLAMA_RUNNER_EVIDENCE_ID
    )
    supported = launcher_supported and runner_supported
    return {
        "checks": {
            "launcher_identity": "SUPPORTED" if launcher_supported else "UNSUPPORTED",
            "runner_identity": "SUPPORTED" if runner_supported else "UNSUPPORTED",
        },
        "limitations": [
            "BINARY_IDENTITY_ONLY",
            "GGUF_MODEL_NOT_INSPECTED",
            "LIVE_TOPOLOGY_NOT_PROVEN",
            "EXECUTION_CONTEXT_NOT_QUALIFIED",
            "COMPATIBILITY_CHECK_NOT_CONTAINMENT_EVIDENCE",
        ],
        "result": "SUPPORTED" if supported else "UNSUPPORTED",
        "schema_version": SCHEMA,
        "target_profile": PROFILE,
        "version": __version__,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Check exact Ollama launcher and runner identities without installing or starting "
            "Eggcracker."
        )
    )
    value.add_argument("--launcher", required=True, help="absolute path to the real launcher ELF")
    value.add_argument("--runner", required=True, help="absolute path to the real runner ELF")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    result = compatibility(
        _absolute_path(argument_parser, args.launcher),
        _absolute_path(argument_parser, args.runner),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "SUPPORTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
