"""Prepare the pinned external Safetensors/PyTorch smoke assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import urllib.request
from pathlib import Path

REPOSITORY = "hf-internal-testing/tiny-random-LlamaForCausalLM"
REVISION = "9fb191250dd56d0ba7ec9785a025ed29c03d5998"
MODEL_SHA256 = "49c20f32c6c597480fcaec5df2f86c645eabea765cbea1e67886dbae45e5c992"
SCHEMA = "lumi-eggcracker.safetensors-ai-smoke-assets.v1"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def download(url: str, destination: Path) -> None:
    if not url.startswith("https://"):
        raise RuntimeError("external assets must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "Lumi-Eggcracker-0.4.0"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as handle:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            handle.write(block)


def python_metadata(python: Path) -> dict[str, object]:
    if not python.is_file() or not os.access(python, os.X_OK):
        raise RuntimeError(f"pinned Python executable is invalid: {python}")
    code = (
        "import torch,transformers,safetensors; "
        "print(torch.__version__); print(transformers.__version__); print(safetensors.__version__)"
    )
    result = subprocess.run([str(python), "-c", code], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "pinned AI environment cannot import dependencies")
    versions = result.stdout.splitlines()
    if len(versions) != 3 or versions[0] != "2.5.1+cpu" or versions[1] != "4.46.3" or versions[2] != "0.4.5":
        raise RuntimeError(f"pinned AI environment versions differ: {versions}")
    return {"path": str(python), "torch": versions[0], "transformers": versions[1], "safetensors": versions[2]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--python", default="/opt/lumi-eggcracker-torch-smoke/bin/python")
    parser.add_argument("--accept-third-party-downloads", action="store_true")
    args = parser.parse_args()
    if not args.accept_third_party_downloads:
        raise SystemExit("refusing third-party download without --accept-third-party-downloads")
    workspace = args.workspace
    if workspace.exists() and any(workspace.iterdir()):
        raise SystemExit("workspace must be new or empty")
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    model_dir = workspace / "model"
    model_dir.mkdir(mode=0o700)
    files = {"config.json": None, "model.safetensors": MODEL_SHA256}
    for filename, expected in files.items():
        destination = model_dir / filename
        url = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{filename}"
        download(url, destination)
        actual = digest(destination)
        if expected is not None and actual != expected:
            raise RuntimeError(f"{filename} SHA-256 differs from pinned value")
    metadata = python_metadata(Path(args.python))
    manifest = {
        "environment": metadata,
        "model": {
            "path": str(model_dir / "model.safetensors"),
            "config": str(model_dir / "config.json"),
            "repository": REPOSITORY,
            "revision": REVISION,
            "sha256": digest(model_dir / "model.safetensors"),
            "config_sha256": digest(model_dir / "config.json"),
        },
        "platform": {"machine": platform.machine(), "system": platform.system()},
        "schema_version": SCHEMA,
    }
    destination = workspace / "safetensors-ai-smoke-assets.json"
    destination.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
