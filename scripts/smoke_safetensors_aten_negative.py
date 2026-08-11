"""Prove a real Safetensors artifact plus ATen alone is not a match."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from smoke_safetensors_ai import load_assets

CLI = "/usr/local/bin/eggcracker"
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")


def run(argv: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def torch_aten_path(python: Path) -> Path:
    result = run(
        [
            str(python),
            "-c",
            "import pathlib,torch; print(pathlib.Path(torch.__file__).parent / 'lib' / 'libtorch_cpu.so')",
        ]
    )
    path = Path(result.stdout.strip())
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("pinned ATen library is not a regular file")
    return path


def wrapper_source() -> str:
    return """import mmap, sys, time
from pathlib import Path

weights = Path(sys.argv[1]).open('rb')
aten = Path(sys.argv[2]).open('rb')
mapped = mmap.mmap(aten.fileno(), 0, access=mmap.ACCESS_READ)
Path(sys.argv[3]).write_text('ready\\n', encoding='ascii')
try:
    time.sleep(30)
finally:
    mapped.close()
    aten.close()
    weights.close()
"""


def launch(python: Path, user: str, wrapper: Path, weights: Path, aten: Path, ready: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            user,
            "--",
            str(python),
            str(wrapper),
            str(weights),
            str(aten),
            str(ready),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_ready(process: subprocess.Popen[bytes], ready: Path, *, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ready.is_file():
            return
        if process.poll() is not None:
            raise RuntimeError("ATen-only workload exited before readiness")
        time.sleep(0.02)
    raise RuntimeError("ATen-only workload did not become ready")


def one(python: Path, model: Path, user: str, aten: Path, index: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="lumi-safetensors-aten-negative-", dir="/tmp") as raw:
        root = Path(raw)
        os.chmod(root, 0o733)
        weights = root / "weights.safetensors"
        wrapper = root / "worker.py"
        ready = root / "ready"
        shutil.copyfile(model, weights)
        os.chmod(weights, 0o644)
        wrapper.write_text(wrapper_source(), encoding="utf-8")
        os.chmod(wrapper, 0o644)
        canary = subprocess.Popen(["/bin/sleep", "45"], start_new_session=True)
        process: subprocess.Popen[bytes] | None = None
        before = set(DETECTIONS.glob("*.json"))
        try:
            process = launch(python, user, wrapper, weights, aten, ready)
            wait_ready(process, ready)
            maps = Path(f"/proc/{process.pid}/maps").read_text(encoding="ascii", errors="replace")
            if aten.name not in maps or "libtorch_python" in maps:
                raise RuntimeError("ATen-only fixture did not have the expected runtime topology")
            time.sleep(4)
            detections = set(DETECTIONS.glob("*.json")) - before
            if detections:
                raise RuntimeError("ATen-only partial pair was incorrectly contained")
            if process.poll() is not None or canary.poll() is not None:
                raise RuntimeError("ATen-only workload or canary did not survive")
            return {"aten_path": aten.name, "receipt_count": 0, "result": "PASS"}
        finally:
            stop(process)
            stop(canary)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("ATen-only Safetensors smoke must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.repetitions != 5 or args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be new and repetitions must equal five")
    try:
        python, model, _config, _manifest = load_assets(args.assets_manifest)
        aten = torch_aten_path(python)
        user_uid = pwd.getpwnam(args.user).pw_uid
        if user_uid == 0:
            raise RuntimeError("negative smoke workload must be unprivileged")
        values = [one(python, model, args.user, aten, index) for index in range(args.repetitions)]
        args.output.write_text(
            json.dumps({"repetitions": values, "result": "PASS"}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        if not args.output.exists():
            args.output.write_text(
                json.dumps({"error": str(error), "result": "FAIL"}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        raise SystemExit(f"ATen-only Safetensors smoke failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
