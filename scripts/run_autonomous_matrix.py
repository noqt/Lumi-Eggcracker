"""Native root-only qualification of autonomous discovery and containment."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from smoke_content_ai import assets, command

CLI = "/usr/local/bin/eggcracker"
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")


def run(argv: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def call(operator: str, argv: list[str]) -> dict[str, Any]:
    command = [CLI, *argv] if argv and argv[0] in {"approve", "revoke"} else ["/usr/sbin/runuser", "-u", operator, "--", CLI, *argv]
    value = json.loads(run(command).stdout)
    if not isinstance(value, dict):
        raise TypeError("invalid Eggcracker response")
    return value


def wait_for_armed_doctor(operator: str, *, timeout: float = 45) -> dict[str, Any]:
    """Wait through truthful between-scan UNSUPPORTED responses."""
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    command = ["/usr/sbin/runuser", "-u", operator, "--", CLI, "doctor"]
    while time.monotonic() < deadline:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=30
        )
        raw = result.stdout.strip() or result.stderr.strip()
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            value = None
        if isinstance(value, dict):
            last = value
            if value.get("result") == "PASS" and value.get("autonomous_discovery"):
                return value
        time.sleep(0.05)
    raise RuntimeError(f"autonomous discovery did not become armed: {last}")


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def new_receipt(previous: set[Path], *, timeout: float = 8) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        created = set(DETECTIONS.glob("*.json")) - previous
        if created:
            value = json.loads(max(created, key=lambda item: item.stat().st_mtime_ns).read_text(encoding="utf-8"))
            if value.get("result") != "TERMINATED":
                raise RuntimeError(f"autonomous containment failed: {value.get('error', value.get('result'))}")
            return value
        time.sleep(0.01)
    raise RuntimeError("autonomous receipt did not appear")


def percentile(values: list[float], percent: int) -> float:
    ordered = sorted(values)
    return ordered[max(0, (len(ordered) * percent + 99) // 100 - 1)]


def launch(user: str, argv: list[str]) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["/usr/sbin/runuser", "-u", user, "--", *argv],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_selected(operator: str, name: str) -> None:
    receipt = Path(f"/tmp/lumi-autonomous-kill-{secrets.token_hex(8)}.json")
    try:
        call(operator, ["kill", "--name", name, "--receipt", str(receipt)])
    finally:
        receipt.unlink(missing_ok=True)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("autonomous matrix must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--discoveries", required=True, type=int)
    parser.add_argument("--approved", required=True, type=int)
    parser.add_argument("--benign", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.discoveries != 100 or args.approved != 50 or args.benign < 200 or args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("qualification counts or output path are invalid")
    install = json.loads(Path("/var/lib/lumi-eggcracker/install-manifest.json").read_text(encoding="utf-8"))
    operator = str(install["operator"])
    user = str(install["workload_user"])
    account = pwd.getpwnam(user)
    if account.pw_uid != int(install["workload_uid"]) or account.pw_uid == pwd.getpwnam(operator).pw_uid:
        raise RuntimeError("installed workload identity is not isolated from the operator")
    uid = account.pw_uid
    results: dict[str, Any] = {"approved": [], "benign": 0, "canary_survival": 0, "discoveries": [], "result": "FAIL"}
    starts: list[float] = []
    empties: list[float] = []
    try:
        runner, model, _manifest = assets(args.assets_manifest)
        argv = command(runner, model)
        try:
            wait_for_armed_doctor(operator)
            for index in range(args.discoveries):
                canary = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
                process: subprocess.Popen[bytes] | None = None
                try:
                    before = set(DETECTIONS.glob("*.json")); started = time.monotonic_ns()
                    process = launch(user, argv)
                    receipt = new_receipt(before)
                    stop(process)
                    if receipt.get("detector", {}).get("profile") != "content.gguf-llama" or canary.poll() is not None or receipt.get("containment", {}).get("surviving_pids"):
                        raise RuntimeError("autonomous fixture containment or canary proof failed")
                    starts.append((receipt["containment"]["first_stop_monotonic_ns"] - started) / 1_000_000)
                    empties.append(float(receipt["containment"]["trigger_to_empty_ms"]))
                    results["discoveries"].append(receipt["event_id"]); results["canary_survival"] += 1
                finally:
                    if process is not None:
                        stop(process)
                    stop(canary)
            for index in range(args.approved):
                approval_name = f"allow-{secrets.token_hex(6)}"
                run_name = f"approved-{secrets.token_hex(6)}"
                call(
                    operator,
                    ["approve", "--name", approval_name, "--uid", str(uid), "--", *argv],
                )
                before = set(DETECTIONS.glob("*.json"))
                started = False
                try:
                    response = call(
                        operator,
                        [
                            "start",
                            "--name",
                            run_name,
                            "--max-pids",
                            "64",
                            "--max-memory-mib",
                            "4096",
                            "--cpu-quota-percent",
                            "1200",
                            "--",
                            *argv,
                        ],
                    )
                    started = True
                    if response.get("state") != "RUNNING":
                        raise RuntimeError("protected approved invocation did not start")
                    # The real runner normally exposes its complete content and
                    # runtime evidence during this interval.  Approval is valid
                    # only because the exact command crossed the protected
                    # pre-exec start gate.
                    time.sleep(2.5)
                    if set(DETECTIONS.glob("*.json")) - before:
                        raise RuntimeError("exact approved invocation was killed")
                    if call(operator, ["status", "--name", run_name]).get("state") != "RUNNING":
                        raise RuntimeError("exact approved invocation did not remain running")
                    results["approved"].append(approval_name)
                finally:
                    if started:
                        stop_selected(operator, run_name)
                    call(operator, ["revoke", "--name", approval_name])
            for _ in range(args.benign):
                process = subprocess.Popen(["/usr/sbin/runuser", "-u", user, "--", sys.executable, "-c", "import time; time.sleep(0.03)"], start_new_session=True)
                process.wait(timeout=5)
                if process.returncode != 0:
                    raise RuntimeError("benign process was interrupted")
                results["benign"] += 1
            results["latency_ms"] = {"process_start_to_first_stop_p95": percentile(starts, 95), "trigger_to_empty_p95": percentile(empties, 95)}
            # Workload startup (especially a real ELF fixture) is diagnostic;
            # the release gate is deterministic containment after qualification.
            if percentile(empties, 95) >= 500:
                raise RuntimeError("autonomous latency gate failed")
            results["result"] = "PASS"
            args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
            return 0
        except Exception as error:
            results["error"] = str(error)
            if not args.output.exists():
                args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
            raise
    except Exception as error:
        results["error"] = str(error)
        if not args.output.exists():
            args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
