"""Exercise content detection with descendants, supervisor startup and restart."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from smoke_content_ai import assets, command, receipt_after, stop

DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
SERVICE = "lumi-eggcracker.service"


def launch(user: str, wrapper: Path, argv: list[str], output: Path) -> subprocess.Popen[bytes]:
    handle = output.open("wb")
    try:
        return subprocess.Popen(
            ["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/python3", str(wrapper), *argv],
            stdout=handle,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    finally:
        handle.close()


def wait_service(*, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (
            subprocess.run(
                ["/usr/bin/systemctl", "is-active", "--quiet", SERVICE], check=False
            ).returncode
            == 0
        ):
            return
        time.sleep(0.02)
    raise RuntimeError("supervisor did not become active")


def child_pids(path: Path) -> list[int]:
    if not path.is_file():
        return []
    return [int(item) for item in path.read_text(encoding="ascii").split() if item.isdigit()]


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("content adversarial matrix must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--tree-repetitions", type=int, default=100)
    parser.add_argument("--startup-repetitions", type=int, default=20)
    parser.add_argument("--restart-repetitions", type=int, default=20)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        (args.tree_repetitions, args.startup_repetitions, args.restart_repetitions) != (100, 20, 20)
        or args.output.exists()
        or args.output.is_symlink()
        or not args.output.parent.is_dir()
    ):
        raise SystemExit("qualification counts or output path are invalid")
    result: dict[str, Any] = {"restart": 0, "startup": 0, "tree": 0, "result": "FAIL"}
    try:
        runner, model, _manifest = assets(args.assets_manifest)
        with tempfile.TemporaryDirectory(prefix="lumi-content-adversarial-", dir="/tmp") as raw:
            root = Path(raw)
            os.chmod(root, 0o755)
            disguised_runner = root / secrets.token_hex(12)
            disguised_model = root / secrets.token_hex(12)
            pid_file = root / "children"
            shutil.copyfile(runner, disguised_runner)
            os.chmod(disguised_runner, 0o755)
            try:
                os.link(model, disguised_model)
            except OSError:
                shutil.copyfile(model, disguised_model)
            wrapper = root / f"{secrets.token_hex(8)}.py"
            wrapper.write_text(
                "import os,sys,time\np=open('"
                + str(pid_file)
                + "','w')\nfor _ in range(32):\n c=os.fork()\n if c==0: time.sleep(30); os._exit(0)\n print(c,file=p,flush=True)\nos.execv(sys.argv[1],sys.argv[1:])\n",
                encoding="utf-8",
            )
            argv = command(disguised_runner, disguised_model)
            for index in range(args.tree_repetitions):
                pid_file.unlink(missing_ok=True)
                canary = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
                process: subprocess.Popen[bytes] | None = None
                try:
                    before = set(DETECTIONS.glob("*.json"))
                    process = launch(args.user, wrapper, argv, root / f"out-{index}")
                    receipt = receipt_after(before)
                    pids = child_pids(pid_file)
                    if receipt.get("detector", {}).get("profile") != "content.gguf-llama":
                        raise RuntimeError("content profile did not qualify")
                    if (
                        receipt["capture"]["captured_processes"] < 33
                        or canary.poll() is not None
                        or any(Path(f"/proc/{pid}").exists() for pid in pids)
                    ):
                        raise RuntimeError("content descendants or canary proof failed")
                    result["tree"] += 1
                finally:
                    stop(process)
                    stop(canary)
            for kind, repetitions in (
                ("startup", args.startup_repetitions),
                ("restart", args.restart_repetitions),
            ):
                for index in range(repetitions):
                    before = set(DETECTIONS.glob("*.json"))
                    process = None
                    try:
                        if kind == "startup":
                            subprocess.run(
                                ["/usr/bin/systemctl", "stop", SERVICE], check=True, timeout=30
                            )
                        process = launch(args.user, wrapper, argv, root / f"{kind}-{index}")
                        if kind == "startup":
                            subprocess.run(
                                ["/usr/bin/systemctl", "start", SERVICE], check=True, timeout=30
                            )
                        else:
                            subprocess.run(
                                [
                                    "/usr/bin/systemctl",
                                    "kill",
                                    "--kill-who=main",
                                    "-s",
                                    "SIGKILL",
                                    SERVICE,
                                ],
                                check=True,
                                timeout=30,
                            )
                        wait_service()
                        receipt = receipt_after(before, timeout=15)
                        if (
                            receipt.get("detector", {}).get("profile") != "content.gguf-llama"
                            or receipt.get("result") != "TERMINATED"
                        ):
                            raise RuntimeError(f"content {kind} rediscovery failed")
                        result[kind] += 1
                    finally:
                        stop(process)
        result["result"] = "PASS"
        args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        result["error"] = str(error)
        if not args.output.exists():
            args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"content adversarial matrix failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
