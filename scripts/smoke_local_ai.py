"""Kill a real, explicitly selected local llama.cpp inference workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import secrets
import tempfile
import time
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def call(args: list[str]) -> dict[str, object]:
    result = subprocess.run(["/usr/local/bin/nutcracker", *args], capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Nutcracker command failed")
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llama-cli", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    if not args.llama_cli.is_file() or not os.access(args.llama_cli, os.X_OK) or not args.model.is_file():
        raise SystemExit("llama-cli executable and GGUF model are required")
    with tempfile.TemporaryDirectory(prefix="lumi-nutcracker-ai-smoke-", dir="/tmp") as raw:
        root = Path(raw)
        # The operator owns this short-lived directory; the dedicated workload
        # identity needs a writable output location for the visible demo.
        os.chmod(root, 0o777)
        generated = root / "generated.txt"
        wrapper = root / "run-ai.sh"
        wrapper.write_text(f"#!/bin/sh\nexec {args.llama_cli} -m {args.model} -p 'Explain one safe property of a Linux cgroup.' -n 4096 > {generated} 2>&1\n", encoding="utf-8")
        os.chmod(wrapper, 0o755)
        name = f"local-ai-smoke-{secrets.token_hex(6)}"
        canary = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        try:
            started = call(["start", "--name", name, "--max-pids", "64", "--", "/bin/sh", str(wrapper)])
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and (not generated.exists() or generated.stat().st_size == 0):
                time.sleep(0.05)
            if not generated.exists() or generated.stat().st_size == 0:
                raise RuntimeError("local AI workload did not produce output")
            receipt = call(["kill", "--name", name, "--receipt", str(root / "receipt.json")])
            if receipt.get("result") != "TERMINATED" or canary.poll() is not None:
                raise RuntimeError("AI containment or canary survival failed")
            args.output.write_text(json.dumps({"engine": str(args.llama_cli), "engine_sha256": digest(args.llama_cli), "generated_bytes": generated.stat().st_size, "model": str(args.model), "model_sha256": digest(args.model), "receipt": receipt, "result": "PASS", "started": started}, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        finally:
            if canary.poll() is None:
                os.killpg(canary.pid, signal.SIGKILL)
                canary.wait(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
