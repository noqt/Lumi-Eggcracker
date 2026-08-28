#!/usr/bin/env python3
"""Root-only native integration gates for the offline boundary.

This runner exercises the installed public CLI.  It deliberately keeps the
evidence aggregate-only: receipts are inspected locally, while no command
arguments, environments or packet payloads are written to the output file.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

CLI = "/usr/local/bin/eggcracker"
STATE_DIR = Path("/var/lib/lumi-eggcracker")
RECEIPT_DIR = STATE_DIR / "receipts"


def run(argv: list[str], *, check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def call(operator: str, args: list[str], *, check: bool = True) -> dict[str, Any]:
    result = run(["/usr/sbin/runuser", "-u", operator, "--", CLI, *args], check=check)
    if not result.stdout.strip():
        return {}
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker response is not an object")
    return value


def wait_state(operator: str, name: str, expected: str, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            latest = call(operator, ["status", "--name", name])
        except (RuntimeError, json.JSONDecodeError):
            time.sleep(0.05)
            continue
        if latest.get("state") == expected:
            return latest
        time.sleep(0.05)
    raise RuntimeError(f"{name} did not reach {expected}: {latest}")


def receipt_for(run_id: str, trigger: str) -> dict[str, Any]:
    candidates: list[tuple[int, Path]] = []
    for path in RECEIPT_DIR.glob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        workload = value.get("workload") if isinstance(value, dict) else None
        event = value.get("trigger") if isinstance(value, dict) else None
        if (
            isinstance(workload, dict)
            and workload.get("run_id") == run_id
            and isinstance(event, dict)
            and event.get("kind") == trigger
        ):
            candidates.append((path.stat().st_mtime_ns, path))
    if not candidates:
        raise RuntimeError(f"no {trigger} receipt for run {run_id}")
    return json.loads(max(candidates, key=lambda item: item[0])[1].read_text(encoding="utf-8"))


def receipt_summary(value: dict[str, Any]) -> dict[str, Any]:
    trigger = value.get("trigger") if isinstance(value.get("trigger"), dict) else {}
    containment = value.get("containment") if isinstance(value.get("containment"), dict) else {}
    return {
        "event_id": value.get("event_id"),
        "result": value.get("result"),
        "trigger": trigger.get("kind"),
        "primitive": containment.get("primitive"),
        "surviving_pids": containment.get("surviving_pids"),
        "trigger_to_empty_ms": containment.get("trigger_to_empty_ms"),
    }


def stop_canary(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def percentile(values: list[float], percent: int) -> float:
    ordered = sorted(values)
    index = max(0, (len(ordered) * percent + 99) // 100 - 1)
    return ordered[index]


def boundary_command() -> list[str]:
    code = (
        "import os,socket,time; "
        "[(os.fork() == 0 and (time.sleep(30), os._exit(0))) for _ in range(4)]; "
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
        "[s.sendto(b'eggcracker',('192.0.2.1',9)) for _ in range(16)]; "
        "time.sleep(30)"
    )
    return ["/usr/bin/python3", "-c", code]


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("offline integration qualification must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--boundary-repetitions", required=True, type=int)
    parser.add_argument("--benign-repetitions", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    if args.boundary_repetitions < 100 or args.benign_repetitions < 20:
        raise SystemExit("integration counts are below the precommitted gates")

    manifest = json.loads((STATE_DIR / "install-manifest.json").read_text(encoding="utf-8"))
    operator = str(manifest["operator"])
    workload = str(manifest["workload_user"])
    workload_uid = pwd.getpwnam(workload).pw_uid
    token = secrets.token_hex(8)
    results: dict[str, Any] = {
        "boundary": [],
        "benign": [],
        "canary_survival": {"expected": args.boundary_repetitions, "survived": 0},
        "workload_uid": workload_uid,
        "result": "FAIL",
    }
    latencies: list[float] = []
    try:
        if call(operator, ["doctor"]).get("result") != "PASS":
            raise RuntimeError("installed supervisor doctor failed")
        for index in range(args.boundary_repetitions):
            name = f"boundary-{token}-{index}"
            canary = subprocess.Popen(
                ["/usr/sbin/runuser", "-u", workload, "--", "/bin/sleep", "60"],
                start_new_session=True,
            )
            try:
                started = call(
                    operator,
                    [
                        "start",
                        "--name",
                        name,
                        "--max-pids",
                        "64",
                        "--max-memory-mib",
                        "128",
                        "--cpu-quota-percent",
                        "100",
                        "--",
                        *boundary_command(),
                    ],
                )
                run_id = str(started["run_id"])
                wait_state(operator, name, "TERMINATED")
                receipt = receipt_for(run_id, "NETWORK_BOUNDARY")
                summary = receipt_summary(receipt)
                if (
                    summary["result"] != "TERMINATED"
                    or summary["primitive"] != "cgroup.kill"
                    or summary["surviving_pids"]
                ):
                    raise RuntimeError(f"boundary receipt was not exact: {summary}")
                if canary.poll() is not None:
                    raise RuntimeError("unrelated same-host canary died")
                results["canary_survival"]["survived"] += 1
                latency = float(summary["trigger_to_empty_ms"])
                latencies.append(latency)
                results["boundary"].append(latency)
            finally:
                stop_canary(canary)
        for index in range(args.benign_repetitions):
            name = f"benign-{token}-{index}"
            started = call(
                operator,
                [
                    "start",
                    "--name",
                    name,
                    "--max-pids",
                    "8",
                    "--max-memory-mib",
                    "128",
                    "--cpu-quota-percent",
                    "100",
                    "--",
                    "/bin/sleep",
                    "0.2",
                ],
            )
            state = wait_state(operator, name, "COMPLETED_ALLOWED")
            if state.get("state") != "COMPLETED_ALLOWED":
                raise RuntimeError(f"benign workload was not allowed: {started}")
            results["benign"].append("COMPLETED_ALLOWED")
        results["latency_ms"] = {
            "p50": percentile(latencies, 50),
            "p95": percentile(latencies, 95),
            "max": max(latencies),
            "samples": len(latencies),
        }
        if percentile(latencies, 95) >= 500:
            raise RuntimeError(f"p95 trigger-to-empty latency failed: {percentile(latencies, 95)} ms")
        results["result"] = "PASS"
        args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except Exception as error:
        results["error"] = str(error)[:240]
        args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
