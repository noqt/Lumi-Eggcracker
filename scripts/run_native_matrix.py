"""Root-only native qualification for fresh Eggcracker-owned fixture workloads."""

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

ROOT = Path(__file__).resolve().parents[1]
CLI = "/usr/local/bin/eggcracker"


def run(argv: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result


def call(operator: str, args: list[str], *, check: bool = True) -> dict[str, Any]:
    result = run(["/usr/sbin/runuser", "-u", operator, "--", CLI, *args], check=check)
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def alive(process: subprocess.Popen[bytes]) -> bool:
    return process.poll() is None


def stop_canary(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def percentile(values: list[float], percent: int) -> float:
    values = sorted(values)
    return values[max(0, (len(values) * percent + 99) // 100 - 1)]


def wait_state(operator: str, name: str, expected: str, timeout: float = 8) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            latest = call(operator, ["status", "--name", name])
        except RuntimeError:
            # systemd is deliberately restarting the root supervisor; its
            # Unix socket is absent only during this bounded fail-closed window.
            time.sleep(0.02)
            continue
        if latest.get("state") == expected:
            return latest
        time.sleep(0.02)
    raise RuntimeError(f"{name} did not reach {expected}: {latest}")


def start_workload(operator: str, args: list[str]) -> dict[str, Any]:
    """Start once, resolving a response lost during bounded supervisor restart."""
    try:
        return call(operator, args)
    except RuntimeError as error:
        if args[:1] != ["start"] or "truncated supervisor response" not in str(error):
            raise
        try:
            name_index = args.index("--name")
            name = args[name_index + 1]
        except (ValueError, IndexError) as parse_error:
            raise RuntimeError("restart response was truncated and start name is unavailable") from parse_error
        wait_state(operator, name, "RUNNING", timeout=5)
        return {"result": "STARTED", "response_recovered": True}


RESTART_RECOVERY_TIMEOUT_SECONDS = 25


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("native matrix must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--fork-race-repetitions", required=True, type=int)
    parser.add_argument("--benign-repetitions", required=True, type=int)
    parser.add_argument("--restart-repetitions", required=True, type=int)
    parser.add_argument("--socket-attempts", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    if args.fork_race_repetitions != 100 or args.benign_repetitions < 50 or args.restart_repetitions < 20 or args.socket_attempts < 100:
        raise SystemExit("qualification counts are below the precommitted gates")
    install = json.loads(Path("/var/lib/lumi-eggcracker/install-manifest.json").read_text(encoding="utf-8"))
    operator = str(install["operator"])
    workload = str(install["workload_user"])
    workload_uid = pwd.getpwnam(workload).pw_uid
    token = secrets.token_hex(8)
    results: dict[str, Any] = {"fork_race": [], "benign": [], "pid_tripwire": [], "restart": [], "socket": {}, "result": "FAIL"}
    latencies: list[float] = []
    canaries = 0
    try:
        if run(["/usr/sbin/runuser", "-u", workload, "--", CLI, "doctor"], check=False).returncode == 0:
            raise RuntimeError("workload identity accessed supervisor client")
        if call(operator, ["doctor"]).get("result") != "PASS":
            raise RuntimeError("operator supervisor authentication failed")
        modes = ("fork", "session", "replace", "fork")
        for index in range(args.fork_race_repetitions):
            canary = subprocess.Popen(["/usr/sbin/runuser", "-u", workload, "--", "/usr/bin/python3", str(ROOT / "tests/fixtures/canary.py")], start_new_session=True)
            try:
                name = f"race-{token}-{index}"
                start_workload(operator, ["start", "--name", name, "--max-pids", "4096", "--", "/usr/bin/python3", str(ROOT / "tests/fixtures/fork_race.py"), modes[index % len(modes)]])
                time.sleep(0.12)
                receipt_path = Path("/tmp") / f"lumi-eggcracker-receipt-{token}-{index}.json"
                receipt = call(operator, ["kill", "--name", name, "--receipt", str(receipt_path)])
                if receipt.get("result") != "TERMINATED" or receipt["trigger"]["kind"] != "OPERATOR" or receipt["containment"]["surviving_pids"]:
                    raise RuntimeError("fork race did not produce exact termination receipt")
                if not alive(canary):
                    raise RuntimeError("unrelated canary died during cgroup kill")
                latencies.append(float(receipt["containment"]["trigger_to_empty_ms"]))
                results["fork_race"].append(receipt["containment"]["trigger_to_empty_ms"])
                canaries += 1
                receipt_path.unlink(missing_ok=True)
            finally:
                stop_canary(canary)
        for index in range(5):
            name = f"pressure-{token}-{index}"
            start_workload(operator, ["start", "--name", name, "--max-pids", "4", "--", "/usr/bin/python3", str(ROOT / "tests/fixtures/pid_pressure.py")])
            state = wait_state(operator, name, "TERMINATED")
            receipt_files = sorted(Path("/var/lib/lumi-eggcracker/receipts").glob("*.json"), key=lambda path: path.stat().st_mtime_ns)
            receipt = json.loads(receipt_files[-1].read_text(encoding="utf-8"))
            if receipt["trigger"]["kind"] != "PID_LIMIT":
                raise RuntimeError(f"PID tripwire did not create PID receipt: {state}")
            latencies.append(float(receipt["containment"]["trigger_to_empty_ms"]))
            results["pid_tripwire"].append(receipt["containment"]["trigger_to_empty_ms"])
        for index in range(args.benign_repetitions):
            name = f"benign-{token}-{index}"
            start_workload(operator, ["start", "--name", name, "--max-pids", "16", "--", "/usr/bin/python3", str(ROOT / "tests/fixtures/benign_near_limit.py"), "12"])
            state = wait_state(operator, name, "COMPLETED_ALLOWED")
            if state.get("state") != "COMPLETED_ALLOWED":
                raise RuntimeError("benign near-limit workload was not allowed")
            results["benign"].append(state["state"])
        hostile_path = Path("/tmp") / f"lumi-eggcracker-hostile-{token}.json"
        hostile = f"hostile-{token}"
        start_workload(operator, ["start", "--name", hostile, "--max-pids", "8", "--", "/usr/bin/python3", str(ROOT / "tests/fixtures/hostile_client.py"), str(hostile_path), str(args.socket_attempts)])
        wait_state(operator, hostile, "COMPLETED_ALLOWED", timeout=30)
        hostile_result = json.loads(hostile_path.read_text(encoding="utf-8"))
        hostile_path.unlink(missing_ok=True)
        if (
            hostile_result["uid"] != workload_uid
            or any(hostile_result["connection_successes"].values())
            or hostile_result["replacement_successes"]
        ):
            raise RuntimeError(f"workload control access succeeded: {hostile_result}")
        units = run(["/usr/bin/systemctl", "list-units", "replacement-*", "--all", "--plain", "--no-legend"]).stdout
        if units.strip():
            raise RuntimeError("replacement workload unit exists")
        results["socket"] = hostile_result
        for index in range(args.restart_repetitions):
            name = f"restart-{token}-{index}"
            # Keep the target alive across the slowest full qualification run;
            # the probe must exercise restart containment of a live workload,
            # not race a naturally completed 30-second sleep.
            start_workload(operator, ["start", "--name", name, "--max-pids", "8", "--", "/bin/sleep", "300"])
            run(["/usr/bin/systemctl", "kill", "--kill-who=main", "-s", "SIGKILL", "lumi-eggcracker.service"])
            # The supervisor socket is intentionally absent while systemd
            # restarts the service.  Allow the full bounded recovery window,
            # which remains below the independent watchdog's 30-second
            # heartbeat fail-closed timeout.
            state = wait_state(
                operator, name, "TERMINATED", timeout=RESTART_RECOVERY_TIMEOUT_SECONDS
            )
            receipt_files = sorted(Path("/var/lib/lumi-eggcracker/receipts").glob("*.json"), key=lambda path: path.stat().st_mtime_ns)
            receipt = json.loads(receipt_files[-1].read_text(encoding="utf-8"))
            if receipt["trigger"]["kind"] != "SUPERVISOR_RESTART_FAIL_CLOSED":
                raise RuntimeError(f"restart did not fail closed: {state}")
            latencies.append(float(receipt["containment"]["trigger_to_empty_ms"]))
            results["restart"].append(receipt["containment"]["trigger_to_empty_ms"])
        if percentile(latencies, 95) >= 500:
            raise RuntimeError(f"p95 trigger-to-empty latency failed: {percentile(latencies, 95)} ms")
        results["canary_survival"] = {"expected": 100, "survived": canaries}
        results["latency_ms"] = {"p50": percentile(latencies, 50), "p95": percentile(latencies, 95), "max": max(latencies), "samples": latencies}
        results["result"] = "PASS"
        args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except Exception as error:
        results["error"] = str(error)
        if not args.output.exists():
            args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        raise
    finally:
        active = run(["/usr/bin/systemctl", "list-units", "lumi-eggcracker-workload-*", "--type=service", "--state=active", "--plain", "--no-legend"], check=False)
        for line in active.stdout.splitlines():
            if line.split() and line.split()[0].startswith("lumi-eggcracker-workload-"):
                run(["/usr/bin/systemctl", "stop", line.split()[0]], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
