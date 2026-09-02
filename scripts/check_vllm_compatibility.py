"""Check four vLLM/PyTorch binary roles against Eggcracker's exact release pins."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lumi_eggcracker import __version__, elfmarkers
from lumi_eggcracker.elfmarkers import (
    PYTORCH_ATEN_EVIDENCE_ID,
    PYTORCH_BRIDGE_EVIDENCE_ID,
    VLLM_EXTENSION_EVIDENCE_ID,
    VLLM_PYTHON_EVIDENCE_ID,
    RuntimeEvidence,
)

SCHEMA = "lumi-eggcracker.vllm-compatibility.v1"
PROFILE = "content.safetensors-vllm"
DescriptorInspector = Callable[[int], RuntimeEvidence | None]


def _absolute_path(parser: argparse.ArgumentParser, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        parser.error("vLLM and PyTorch binary paths must be absolute")
    return path


def _inspect_regular_path(
    path: Path, inspector: DescriptorInspector
) -> RuntimeEvidence | None:
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
        return inspector(descriptor)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def compatibility(
    pytorch_bridge: Path,
    pytorch_aten: Path,
    vllm_python: Path,
    vllm_extension: Path,
) -> dict[str, object]:
    evidence = {
        "pytorch_bridge_identity": _inspect_regular_path(
            pytorch_bridge, elfmarkers._inspect_pytorch_descriptor
        ),
        "pytorch_aten_identity": _inspect_regular_path(
            pytorch_aten, elfmarkers._inspect_pytorch_descriptor
        ),
        "vllm_python_identity": _inspect_regular_path(
            vllm_python, elfmarkers._inspect_vllm_python_descriptor
        ),
        "vllm_extension_identity": _inspect_regular_path(
            vllm_extension, elfmarkers._inspect_vllm_extension_descriptor
        ),
    }
    expected = {
        "pytorch_bridge_identity": PYTORCH_BRIDGE_EVIDENCE_ID,
        "pytorch_aten_identity": PYTORCH_ATEN_EVIDENCE_ID,
        "vllm_python_identity": VLLM_PYTHON_EVIDENCE_ID,
        "vllm_extension_identity": VLLM_EXTENSION_EVIDENCE_ID,
    }
    checks = {
        role: (
            "SUPPORTED"
            if value is not None and value.evidence_id == expected[role]
            else "UNSUPPORTED"
        )
        for role, value in evidence.items()
    }
    supported = all(value == "SUPPORTED" for value in checks.values())
    return {
        "checks": checks,
        "limitations": [
            "BINARY_IDENTITY_ONLY",
            "SAFETENSORS_MODEL_NOT_INSPECTED",
            "LIVE_TOPOLOGY_NOT_PROVEN",
            "EXECUTION_CONTEXT_NOT_QUALIFIED",
            "COMPATIBILITY_CHECK_NOT_CONTAINMENT_EVIDENCE",
            "COMPATIBILITY_CHECK_NOT_ADOPTION_EVIDENCE",
        ],
        "result": "SUPPORTED" if supported else "UNSUPPORTED",
        "schema_version": SCHEMA,
        "target_profile": PROFILE,
        "version": __version__,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=(
            "Check exact vLLM and PyTorch binary identities without installing or starting "
            "Eggcracker."
        )
    )
    value.add_argument(
        "--pytorch-bridge", required=True, help="absolute path to the PyTorch bridge ELF"
    )
    value.add_argument(
        "--pytorch-aten", required=True, help="absolute path to the PyTorch ATen ELF"
    )
    value.add_argument(
        "--vllm-python", required=True, help="absolute path to the vLLM CPython ELF"
    )
    value.add_argument(
        "--vllm-extension", required=True, help="absolute path to the vLLM extension ELF"
    )
    return value


def main(argv: Sequence[str] | None = None) -> int:
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    result = compatibility(
        _absolute_path(argument_parser, args.pytorch_bridge),
        _absolute_path(argument_parser, args.pytorch_aten),
        _absolute_path(argument_parser, args.vllm_python),
        _absolute_path(argument_parser, args.vllm_extension),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "SUPPORTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
