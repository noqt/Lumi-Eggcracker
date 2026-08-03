"""Run and contain a real, explicitly selected local llama.cpp workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "scripts" / "ai_smoke_worker.py"
ASSET_SCHEMA = "lumi-eggcracker.ai-smoke-assets.v1"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def regular(path: Path, *, executable: bool = False) -> None:
    path.lstat()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required asset must be a regular file: {path}")
    if executable and not os.access(path, os.X_OK):
        raise RuntimeError(f"required runner is not executable: {path}")


def call(args: list[str]) -> dict[str, Any]:
    result = subprocess.run(["/usr/local/bin/eggcracker", *args], capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Eggcracker command failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker command returned an invalid JSON object")
    return value


def assets_from_manifest(path: Path) -> tuple[Path, Path, dict[str, Any]]:
    regular(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"llama", "model", "platform", "schema_version"} or value.get("schema_version") != ASSET_SCHEMA:
        raise RuntimeError("AI smoke asset manifest schema is invalid")
    llama, model = value["llama"], value["model"]
    if not isinstance(llama, dict) or not isinstance(model, dict) or not isinstance(llama.get("path"), str) or not isinstance(model.get("path"), str):
        raise TypeError("AI smoke asset manifest paths are invalid")
    runner, gguf = Path(llama["path"]), Path(model["path"])
    regular(runner, executable=True)
    regular(gguf)
    if digest(runner) != llama.get("sha256") or digest(gguf) != model.get("sha256"):
        raise RuntimeError("AI smoke asset digest differs from manifest")
    return runner, gguf, value


def stop_canary(canary: subprocess.Popen[bytes]) -> None:
    if canary.poll() is None:
        os.killpg(canary.pid, signal.SIGKILL)
        canary.wait(timeout=3)


def generated(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and path.stat().st_size >= 32


def one_smoke(*, runner: Path, model: Path, provenance: dict[str, Any], index: int) -> dict[str, Any]:
    prompt = "Explain one safe property of a Linux cgroup in a concise paragraph."
    with tempfile.TemporaryDirectory(prefix="lumi-eggcracker-ai-smoke-", dir="/tmp") as raw:
        root = Path(raw)
        output, diagnostics, receipt_path = root / "generated.txt", root / "runner.stderr", root / "receipt.json"
        for path in (output, diagnostics):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            os.close(descriptor)
            os.chmod(path, 0o666)
        # The workload can traverse to the two pre-created writable outputs,
        # but cannot create or replace the root-owned receipt path.
        os.chmod(root, 0o711)
        name = f"local-ai-{secrets.token_hex(8)}-{index}"
        canary = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
        started: dict[str, Any] | None = None
        contained = False
        try:
            runner_argv = [str(runner), "-m", str(model), "-p", prompt, "-n", "4096", "--no-display-prompt", "--seed", "1234"]
            started = call(["start", "--name", name, "--max-pids", "64", "--", "/usr/bin/python3", str(WORKER), "--stdout", str(output), "--stderr", str(diagnostics), "--", *runner_argv])
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline and not generated(output):
                time.sleep(0.05)
            if not generated(output):
                raise RuntimeError("real AI workload did not produce 32 bytes of generated output")
            status = call(["status", "--name", name])
            if status.get("state") != "RUNNING":
                raise RuntimeError("real AI workload completed before operator containment")
            receipt = call(["kill", "--name", name, "--receipt", str(receipt_path)])
            contained = True
            containment = receipt.get("containment")
            if receipt.get("result") != "TERMINATED" or receipt.get("trigger", {}).get("kind") != "OPERATOR" or not isinstance(containment, dict):
                raise RuntimeError("real AI workload did not return an operator termination receipt")
            if containment.get("primitive") != "cgroup.kill" or containment.get("root_populated") != 0 or containment.get("surviving_pids"):
                raise RuntimeError("real AI receipt did not prove exact empty cgroup containment")
            if receipt.get("workload", {}).get("run_id") != started.get("run_id") or canary.poll() is not None:
                raise RuntimeError("real AI receipt identity or canary survival failed")
            return {
                "generated_bytes": output.stat().st_size,
                "generated_sha256": digest(output),
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "receipt": receipt,
                "result": "PASS",
                "runner": {key: provenance["llama"][key] for key in ("commit", "license", "repository", "sha256", "size", "tag")},
                "model": {key: provenance["model"][key] for key in ("license", "revision", "sha256", "size", "url")},
                "started": started,
            }
        finally:
            if started is not None and not contained:
                try:
                    call(["kill", "--name", name, "--receipt", str(root / "failure-receipt.json")])
                except (RuntimeError, TypeError, json.JSONDecodeError):
                    pass
            stop_canary(canary)


def main() -> int:
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--assets-manifest", type=Path)
    inputs.add_argument("--llama-cli", type=Path)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    if not 1 <= args.repetitions <= 5:
        raise SystemExit("repetitions must be from 1 to 5")
    try:
        if args.assets_manifest:
            if args.model is not None:
                raise RuntimeError("--model cannot be combined with --assets-manifest")
            runner, model, provenance = assets_from_manifest(args.assets_manifest)
        else:
            if args.model is None:
                raise RuntimeError("--model is required with --llama-cli")
            runner, model = args.llama_cli, args.model
            regular(runner, executable=True); regular(model)
            provenance = {"llama": {"repository": "operator-supplied", "tag": None, "commit": None, "sha256": digest(runner), "size": runner.stat().st_size, "license": "operator-supplied"}, "model": {"url": "operator-supplied", "revision": None, "sha256": digest(model), "size": model.stat().st_size, "license": "operator-supplied"}}
        results = [one_smoke(runner=runner, model=model, provenance=provenance, index=index) for index in range(args.repetitions)]
        args.output.write_text(json.dumps({"repetitions": results, "result": "PASS"}, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        if not args.output.exists():
            args.output.write_text(json.dumps({"error": str(error), "result": "FAIL"}, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"real AI smoke failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
