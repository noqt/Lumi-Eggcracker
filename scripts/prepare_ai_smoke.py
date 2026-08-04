"""Prepare the pinned, external assets used by the real-AI smoke test."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "lumi-eggcracker.ai-smoke-assets.v1"
LLAMA_REPOSITORY = "https://github.com/ggml-org/llama.cpp.git"
LLAMA_TAG = "b10240"
LLAMA_COMMIT = "0b14b87d7c20cb753b94b96854dd7b45306fc696"
MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf"
MODEL_SHA256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
MODEL_NAME = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
MAX_MODEL_BYTES = 600 * 1024 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=900)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "asset preparation command failed")
    return result.stdout.strip()


def regular(path: Path, *, executable: bool = False) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"asset must be a regular file: {path}")
    if executable and not os.access(path, os.X_OK):
        raise RuntimeError(f"asset is not executable: {path}")
    if metadata.st_size < 1:
        raise RuntimeError(f"asset is empty: {path}")


def under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_workspace(raw: Path) -> Path:
    if not raw.is_absolute():
        raise RuntimeError("asset workspace must be an absolute path")
    workspace = raw.resolve(strict=False)
    protected = (Path("/usr"), Path("/etc"), Path("/var/lib/lumi-eggcracker"), Path("/run/lumi-eggcracker"), ROOT.resolve())
    if workspace == Path("/") or any(workspace == item or under(workspace, item) for item in protected):
        raise RuntimeError("asset workspace overlaps a protected product or system path")
    cursor = workspace
    while cursor != cursor.parent:
        if cursor.exists() and cursor.is_symlink():
            raise RuntimeError("asset workspace must not traverse a symlink")
        cursor = cursor.parent
    return workspace


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.write(descriptor, (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def manifest_path(workspace: Path) -> Path:
    return workspace / "ai-smoke-assets.json"


def load_manifest(workspace: Path) -> dict[str, Any]:
    path = manifest_path(workspace)
    regular(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = {"llama", "model", "platform", "schema_version"}
    if set(value) != expected or value["schema_version"] != SCHEMA:
        raise RuntimeError("asset manifest schema is invalid")
    return value


def verify_manifest(workspace: Path) -> dict[str, Any]:
    value = load_manifest(workspace)
    llama, model = value["llama"], value["model"]
    if not isinstance(llama, dict) or not isinstance(model, dict):
        raise TypeError("asset manifest entries are invalid")
    expected_llama = {"commit", "license", "path", "repository", "sha256", "size", "tag"}
    expected_model = {"license", "path", "revision", "sha256", "size", "url"}
    if set(llama) != expected_llama or set(model) != expected_model:
        raise RuntimeError("asset manifest fields are invalid")
    runner = Path(llama["path"])
    gguf = Path(model["path"])
    if not under(runner.resolve(), workspace) or not under(gguf.resolve(), workspace):
        raise RuntimeError("asset manifest escapes its workspace")
    regular(runner, executable=True)
    regular(gguf)
    if llama["repository"] != LLAMA_REPOSITORY or llama["tag"] != LLAMA_TAG or llama["commit"] != LLAMA_COMMIT:
        raise RuntimeError("runner provenance differs from the pinned smoke input")
    if model["url"] != MODEL_URL or model["revision"] != "9217f5db79a29953eb74d5343926648285ec7e67" or model["sha256"] != MODEL_SHA256:
        raise RuntimeError("model provenance differs from the pinned smoke input")
    if digest(runner) != llama["sha256"] or runner.stat().st_size != llama["size"]:
        raise RuntimeError("runner digest or size differs from manifest")
    if digest(gguf) != MODEL_SHA256 or gguf.stat().st_size != model["size"]:
        raise RuntimeError("model digest or size differs from manifest")
    return value


def download_model(destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.download")
    temporary.unlink(missing_ok=True)
    value = hashlib.sha256()
    size = 0
    request = urllib.request.Request(MODEL_URL, headers={"User-Agent": "Lumi-Eggcracker-0.2.0"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("xb") as handle:
            if not response.url.startswith("https://"):
                raise RuntimeError("model download did not resolve to HTTPS")
            while block := response.read(64 * 1024):
                size += len(block)
                if size > MAX_MODEL_BYTES:
                    raise RuntimeError("model download exceeds the smoke size limit")
                value.update(block)
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
        if value.hexdigest() != MODEL_SHA256:
            raise RuntimeError("model download digest differs from the pinned value")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def prepare(workspace: Path) -> dict[str, Any]:
    source = workspace / "llama.cpp"
    build = workspace / "llama-build"
    model = workspace / "model" / MODEL_NAME
    if workspace.exists() and any(workspace.iterdir()):
        return verify_manifest(workspace)
    workspace.mkdir(mode=0o755, parents=True, exist_ok=True)
    run(["git", "clone", "--filter=blob:none", "--no-checkout", LLAMA_REPOSITORY, str(source)])
    run(["git", "-C", str(source), "checkout", "--detach", LLAMA_COMMIT])
    if run(["git", "-C", str(source), "rev-parse", "HEAD"]) != LLAMA_COMMIT:
        raise RuntimeError("runner source did not resolve to the pinned commit")
    run(["cmake", "-S", str(source), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release"])
    run(["cmake", "--build", str(build), "--target", "llama-cli", "-j"])
    runner = build / "bin" / "llama-cli"
    regular(runner, executable=True)
    model.parent.mkdir(mode=0o755)
    download_model(model)
    os.chmod(model, 0o644)
    license_path = source / "LICENSE"
    regular(license_path)
    shutil.copyfile(license_path, workspace / "llama.cpp-LICENSE")
    value = {
        "schema_version": SCHEMA,
        "platform": {"machine": platform.machine(), "system": platform.system()},
        "llama": {"repository": LLAMA_REPOSITORY, "tag": LLAMA_TAG, "commit": LLAMA_COMMIT, "path": str(runner), "sha256": digest(runner), "size": runner.stat().st_size, "license": "MIT"},
        "model": {"url": MODEL_URL, "revision": "9217f5db79a29953eb74d5343926648285ec7e67", "path": str(model), "sha256": MODEL_SHA256, "size": model.stat().st_size, "license": "Apache-2.0"},
    }
    atomic_json(manifest_path(workspace), value)
    return verify_manifest(workspace)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--accept-third-party-downloads", action="store_true")
    args = parser.parse_args()
    workspace = validate_workspace(args.workspace)
    if workspace.exists() and any(workspace.iterdir()):
        print(json.dumps(verify_manifest(workspace), sort_keys=True))
        return 0
    if not args.accept_third_party_downloads:
        raise SystemExit("--accept-third-party-downloads is required before staging external assets")
    try:
        value = prepare(workspace)
    except (OSError, RuntimeError, TypeError, subprocess.SubprocessError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise SystemExit(f"AI smoke asset preparation failed: {error}") from error
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
