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
RUNS = Path("/var/lib/lumi-eggcracker/runs")
NETNS = Path("/run/netns")


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


def root_call(argv: list[str]) -> dict[str, Any]:
    value = json.loads(run([CLI, *argv]).stdout)
    if not isinstance(value, dict):
        raise TypeError("invalid root Eggcracker response")
    return value


def incident_ids() -> set[str]:
    value = root_call(["incidents"])
    incidents = value.get("incidents", [])
    if not isinstance(incidents, list):
        raise TypeError("invalid Eggcracker incident response")
    return {
        item["incident_id"]
        for item in incidents
        if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
    }


def clear_new_incidents(
    previous: set[str],
    *,
    expected_event_id: str,
    timeout: float = 8.0,
    settle_seconds: float = 1.0,
) -> int:
    """Wait for post-receipt response persistence, then clear this phase.

    The containment receipt is intentionally durable before local active
    response.  Polling once immediately after the final receipt can therefore
    miss the incident and let its lockdown race the following approved phase.
    """
    if not expected_event_id or expected_event_id in previous:
        raise ValueError("expected event identity is invalid")
    deadline = time.monotonic() + timeout
    observed_response = False
    quiet_since: float | None = None
    cleared: set[str] = set()
    while time.monotonic() < deadline:
        incidents = root_call(["incidents"]).get("incidents", [])
        if not isinstance(incidents, list):
            raise TypeError("invalid Eggcracker incident response")
        current_ids = {
            item["incident_id"]
            for item in incidents
            if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
        }
        new_active = {
            item["incident_id"]
            for item in incidents
            if isinstance(item, dict)
            and item.get("state") == "ACTIVE"
            and isinstance(item.get("incident_id"), str)
            and item["incident_id"] not in previous
        }
        observed_response = observed_response or expected_event_id in current_ids or bool(
            new_active
        )
        if new_active:
            for incident_id in sorted(new_active):
                root_call(["incident", "clear", incident_id])
                cleared.add(incident_id)
            quiet_since = None
        elif observed_response:
            now = time.monotonic()
            quiet_since = now if quiet_since is None else quiet_since
            if now - quiet_since >= settle_seconds:
                return len(cleared)
        time.sleep(0.01)
    raise RuntimeError("autonomous incident response did not settle before approval")


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


def approved_outcome(state: object) -> bool:
    return state in {"RUNNING", "COMPLETED_ALLOWED"}


def supervisor_pid() -> int:
    value = run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=MainPID",
            "--value",
            "lumi-eggcracker.service",
        ]
    ).stdout.strip()
    if not value.isdecimal() or int(value) < 2:
        raise RuntimeError("supervisor main PID is unavailable")
    return int(value)


def wait_selected_state(
    operator: str, name: str, expected: str, *, timeout: float = 8.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            latest = call(operator, ["status", "--name", name])
        except RuntimeError:
            time.sleep(0.01)
            continue
        if latest.get("state") == expected:
            return latest
        time.sleep(0.01)
    raise RuntimeError(f"protected workload did not reach {expected}: {latest}")


def wait_owned_namespace_cleanup(run_id: str, *, timeout: float = 5.0) -> dict[str, Any]:
    if len(run_id) != 24 or any(character not in "0123456789abcdef" for character in run_id):
        raise ValueError("owned run identity is invalid")
    names = (
        f"lumi-eggcracker-w-{run_id}",
        f"lumi-eggcracker-s-{run_id}",
    )
    paths = tuple(NETNS / name for name in names)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        mountinfo = Path("/proc/1/mountinfo").read_text(
            encoding="utf-8", errors="replace"
        )
        existing = [
            str(path) for path in paths if path.exists() or path.is_symlink()
        ]
        mounted = [name for name in names if name in mountinfo]
        if not existing and not mounted:
            return {"mount_entries": 0, "namespace_paths": 0}
        time.sleep(0.01)
    raise RuntimeError(
        f"autonomous owned-run cleanup retained namespaces: paths={existing}, mounts={mounted}"
    )


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
        try:
            call(operator, ["kill", "--name", name, "--receipt", str(receipt)])
        except RuntimeError:
            # The real runner can finish between the RUNNING status proof and
            # this best-effort cleanup call.  Accept only one exact durable
            # benign-completion record for that randomized run name; do not
            # mask TERMINATED, containment-failure, or ambiguous states.
            completed = []
            for path in RUNS.glob("*.json"):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if value.get("name") == name:
                    completed.append(value)
            if len(completed) != 1 or completed[0].get("state") != "COMPLETED_ALLOWED":
                raise
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
    results: dict[str, Any] = {
        "approved": [],
        "benign": 0,
        "canary_survival": 0,
        "discoveries": [],
        "owned_autonomous_cleanup": None,
        "result": "FAIL",
    }
    starts: list[float] = []
    empties: list[float] = []
    try:
        runner, model, _manifest = assets(args.assets_manifest)
        argv = command(runner, model)
        try:
            wait_for_armed_doctor(operator)
            before_incidents = incident_ids()
            last_event_id = ""
            for index in range(args.discoveries):
                canary = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
                process: subprocess.Popen[bytes] | None = None
                try:
                    before = set(DETECTIONS.glob("*.json"))
                    started = time.monotonic_ns()
                    process = launch(user, argv)
                    receipt = new_receipt(before)
                    stop(process)
                    if receipt.get("detector", {}).get("profile") != "content.gguf-llama" or canary.poll() is not None or receipt.get("containment", {}).get("surviving_pids"):
                        raise RuntimeError("autonomous fixture containment or canary proof failed")
                    starts.append((receipt["containment"]["first_stop_monotonic_ns"] - started) / 1_000_000)
                    empties.append(float(receipt["containment"]["trigger_to_empty_ms"]))
                    results["discoveries"].append(receipt["event_id"])
                    last_event_id = str(receipt["event_id"])
                    results["canary_survival"] += 1
                finally:
                    if process is not None:
                        stop(process)
                    stop(canary)
            # The discovery phase deliberately leaves an exact lockdown
            # incident.  Root-clear only this run's incident before the
            # independent approved-survival phase; protected relaunch blocking
            # remains covered by the dedicated incident/lockdown tests.
            clear_new_incidents(
                before_incidents,
                expected_event_id=last_event_id,
            )
            # Recreate the C8 failure mode inside an Eggcracker-owned offline
            # workload. Autonomous containment must terminate the run and
            # reclaim both exact namespace mounts without relying on a
            # supervisor restart.
            wait_for_armed_doctor(operator)
            owned_before_incidents = incident_ids()
            owned_before_detections = set(DETECTIONS.glob("*.json"))
            owned_name = f"owned-unapproved-{secrets.token_hex(6)}"
            pid_before = supervisor_pid()
            owned = call(
                operator,
                [
                    "start",
                    "--name",
                    owned_name,
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
            owned_run_id = str(owned.get("run_id", ""))
            owned_receipt = new_receipt(owned_before_detections)
            wait_selected_state(operator, owned_name, "TERMINATED")
            namespace_cleanup = wait_owned_namespace_cleanup(owned_run_id)
            pid_after = supervisor_pid()
            if (
                owned_receipt.get("detector", {}).get("profile")
                != "content.gguf-llama"
                or pid_before != pid_after
                or call(operator, ["doctor"]).get("result") != "PASS"
            ):
                raise RuntimeError(
                    "owned autonomous containment required restart or failed health"
                )
            clear_new_incidents(
                owned_before_incidents,
                expected_event_id=str(owned_receipt.get("event_id", "")),
            )
            results["owned_autonomous_cleanup"] = {
                **namespace_cleanup,
                "profile": "content.gguf-llama",
                "state": "TERMINATED",
                "supervisor_restarted": False,
            }
            for index in range(args.approved):
                approval_name = f"allow-{secrets.token_hex(6)}"
                run_name = f"approved-{secrets.token_hex(6)}"
                call(
                    operator,
                    [
                        "approve", "--name", approval_name, "--uid", str(uid),
                        "--max-pids", "64", "--max-memory-mib", "4096",
                        "--cpu-quota-percent", "1200", "--", *argv,
                    ],
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
                    state = call(operator, ["status", "--name", run_name]).get("state")
                    if not approved_outcome(state):
                        raise RuntimeError("exact approved invocation was not allowed")
                    # A small real model may finish its bounded context before
                    # cleanup.  That is a successful approval outcome, not a
                    # false kill, and no active cgroup remains to stop.
                    started = state == "RUNNING"
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
