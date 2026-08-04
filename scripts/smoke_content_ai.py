"""Exercise name-independent GGUF/llama.cpp recognition with real local AI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
CLI = "/usr/local/bin/eggcracker"
ASSET_SCHEMA = "lumi-eggcracker.ai-smoke-assets.v1"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def assets(path: Path) -> tuple[Path, Path, dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"llama", "model", "platform", "schema_version"} or value["schema_version"] != ASSET_SCHEMA:
        raise RuntimeError("asset manifest is invalid")
    runner, model = Path(value["llama"]["path"]), Path(value["model"]["path"])
    if any(item.is_symlink() or not item.is_file() for item in (runner, model)) or not os.access(runner, os.X_OK):
        raise RuntimeError("AI smoke assets are invalid")
    if digest(runner) != value["llama"]["sha256"] or digest(model) != value["model"]["sha256"]:
        raise RuntimeError("AI smoke asset digest differs from manifest")
    return runner, model, value


def control(user: str, argv: list[str]) -> dict[str, Any]:
    result = subprocess.run(["/usr/sbin/runuser", "-u", user, "--", CLI, *argv], capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Eggcracker control command failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker control command returned invalid JSON")
    return value


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def receipt_after(before: set[Path], *, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        paths = set(DETECTIONS.glob("*.json")) - before
        if paths:
            value = json.loads(max(paths, key=lambda item: item.stat().st_mtime_ns).read_text(encoding="utf-8"))
            if value.get("result") != "TERMINATED":
                raise RuntimeError(f"content containment failed: {value.get('error', value.get('result'))}")
            return value
        time.sleep(0.02)
    raise RuntimeError("content detection receipt did not appear")


def command(runner: Path, model: Path) -> list[str]:
    return [str(runner), "-m", str(model), "-p", "Name a Linux cgroup property.", "-n", "4096", "-t", "12", "-tb", "12", "-c", "512", "--simple-io", "--single-turn", "--no-warmup", "--no-display-prompt", "--seed", "1234"]


def launch(user: str, wrapper: Path, argv: list[str], output: Path) -> subprocess.Popen[bytes]:
    handle = output.open("wb")
    try:
        # The wrapper is deliberately unfamiliar and replaces itself; the
        # observed executable/argv0 is a copied random filename, not Python.
        return subprocess.Popen(["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/python3", str(wrapper), *argv], stdout=handle, stderr=subprocess.DEVNULL, start_new_session=True)
    finally:
        handle.close()


def one(runner: Path, model: Path, user: str, index: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="lumi-content-smoke-", dir="/tmp") as raw:
        root = Path(raw); os.chmod(root, 0o755)
        disguised_runner = root / secrets.token_hex(12)
        disguised_model = root / secrets.token_hex(12)
        wrapper = root / f"{secrets.token_hex(8)}.py"
        output = root / "out"
        shutil.copyfile(runner, disguised_runner); os.chmod(disguised_runner, 0o755)
        try:
            os.link(model, disguised_model)
        except OSError:
            shutil.copyfile(model, disguised_model)
        wrapper.write_text("import os,sys\nos.execv(sys.argv[1], sys.argv[1:])\n", encoding="utf-8")
        final_argv = command(disguised_runner, disguised_model)
        if any(item.endswith(".gguf") for item in final_argv) or disguised_runner.name in {"llama-cli", "llama-server", "main"}:
            raise RuntimeError("content smoke accidentally satisfies a fast-name condition")
        canary = subprocess.Popen(["/bin/sleep", "180"], start_new_session=True)
        unapproved: subprocess.Popen[bytes] | None = None
        allowed: subprocess.Popen[bytes] | None = None
        name = f"content-{index}-{secrets.token_hex(4)}"
        try:
            before = set(DETECTIONS.glob("*.json"))
            unapproved = launch(user, wrapper, final_argv, output)
            first = receipt_after(before)
            stop(unapproved); unapproved = None
            if first.get("detector", {}).get("profile") != "content.gguf-llama" or first.get("detector", {}).get("detection_path") != "CONTENT" or canary.poll() is not None:
                raise RuntimeError("content profile or canary proof failed")
            if str(disguised_model) in json.dumps(first, sort_keys=True) or str(wrapper) in json.dumps(first, sort_keys=True):
                raise RuntimeError("content receipt leaked a local model or wrapper path")
            approved = control(user, ["approve", "--name", name, "--uid", str(pwd.getpwnam(user).pw_uid), "--", *final_argv])
            if approved.get("result") != "APPROVED":
                raise RuntimeError("exact content approval failed")
            allowed = launch(user, wrapper, final_argv, output)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and (not output.is_file() or output.stat().st_size < 32):
                time.sleep(0.05)
            if allowed.poll() is not None or output.stat().st_size < 32:
                raise RuntimeError("approved disguised AI did not produce output")
            generated = output.stat().st_size
            stop(allowed); allowed = None
            control(user, ["revoke", "--name", name])
            before = set(DETECTIONS.glob("*.json"))
            unapproved = launch(user, wrapper, final_argv, output)
            second = receipt_after(before)
            stop(unapproved); unapproved = None
            if second.get("detector", {}).get("profile") != "content.gguf-llama" or canary.poll() is not None:
                raise RuntimeError("revoked disguised AI was not terminated")
            return {"approved_generated_bytes": generated, "first_receipt": first, "result": "PASS", "second_receipt": second}
        finally:
            stop(unapproved); stop(allowed); stop(canary)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("content AI smoke must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.repetitions != 5 or args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be new and repetitions must equal five")
    try:
        pwd.getpwnam(args.user)
        runner, model, _manifest = assets(args.assets_manifest)
        values = [one(runner, model, args.user, index) for index in range(args.repetitions)]
        args.output.write_text(json.dumps({"repetitions": values, "result": "PASS"}, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        if not args.output.exists():
            args.output.write_text(json.dumps({"error": str(error), "result": "FAIL"}, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"content AI smoke failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
