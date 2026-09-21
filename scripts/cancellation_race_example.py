#!/usr/bin/env python3
"""Reproduce one bounded child fork that occurs after cancellation begins."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
try:
    source_entries = tuple(SOURCE_ROOT.iterdir())
except OSError:
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED") from None
if (
    len(source_entries) != 1
    or source_entries[0] != SOURCE_ROOT / "lumi_eggcracker"
    or source_entries[0].is_symlink()
    or not source_entries[0].is_dir()
):
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED")
sys.path.insert(0, str(SOURCE_ROOT))

from lumi_eggcracker import containment_probe as probe
from lumi_eggcracker.adoption import open_pidfd
from lumi_eggcracker.containment import kill_path
from lumi_eggcracker.discovery import identity

TOTAL_TIMEOUT_SECONDS = 20.0
WORKER_LIFETIME_SECONDS = 30
TARGET_UID = 65534
TARGET_GID = 65534
OWNER_TASK_LIMIT = 3
MAX_CHILDREN = 1

TARGET_CODE = (
    "import os, signal, sys, time\n"
    "report_fd = int(sys.argv[1])\n"
    "barrier_fd = int(sys.argv[2])\n"
    "parent_cgroup_procs = sys.argv[3]\n"
    f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
    "if os.read(barrier_fd, 1) != b'A': os._exit(2)\n"
    "os.setgroups([])\n"
    f"os.setgid({TARGET_GID})\n"
    f"os.setuid({TARGET_UID})\n"
    "if os.access(parent_cgroup_procs, os.W_OK):\n"
    "    os.write(report_fd, b'MIGRATION_ALLOWED\\n')\n"
    "    os._exit(3)\n"
    "forked = False\n"
    "def on_cancel(_signum, _frame):\n"
    "    global forked\n"
    "    if forked: return\n"
    "    forked = True\n"
    "    os.write(report_fd, b'CANCEL_STARTED\\n')\n"
    "    if os.read(barrier_fd, 1) != b'F': os._exit(4)\n"
    "    child = os.fork()\n"
    "    if child == 0:\n"
    "        signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "        os.write(report_fd, ('CHILD:' + str(os.getpid()) + '\\n').encode('ascii'))\n"
    f"        deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
    "        while time.monotonic() < deadline: time.sleep(0.1)\n"
    "        os._exit(0)\n"
    "signal.signal(signal.SIGTERM, on_cancel)\n"
    "os.write(report_fd, ('READY:' + str(os.getpid()) + '\\n').encode('ascii'))\n"
    "while time.monotonic() < deadline: time.sleep(0.1)\n"
)


def _start_owner(unit: str) -> None:
    result = probe._safe_run(
        [
            str(probe.SYSTEMD_RUN),
            "--quiet",
            f"--unit={unit}",
            "--service-type=exec",
            "--property=Delegate=pids",
            f"--property=TasksMax={OWNER_TASK_LIMIT}",
            f"--property=RuntimeMaxSec={WORKER_LIFETIME_SECONDS}s",
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=NoNewPrivileges=yes",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=3s",
            "--setenv=LANG=C.UTF-8",
            str(probe.PYTHON),
            "-I",
            "-S",
            "-c",
            "import time; time.sleep(30)",
        ]
    )
    if result.returncode:
        raise probe.ProbeError("UNIT_START_FAILED")


def _spawn_target(value: probe.ProbeCgroupIdentity) -> tuple[subprocess.Popen[bytes], int, int]:
    probe._validate_owner(value)
    report_read, report_write = os.pipe()
    barrier_read, barrier_write = os.pipe()
    try:
        process = subprocess.Popen(
            [
                str(probe.PYTHON),
                "-I",
                "-S",
                "-c",
                TARGET_CODE,
                str(report_write),
                str(barrier_read),
                str(value.parent_path / "cgroup.procs"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(report_write, barrier_read),
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    except BaseException:
        for descriptor in (report_read, report_write, barrier_read, barrier_write):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    os.close(report_write)
    os.close(barrier_read)
    return process, report_read, barrier_write


def _attach(value: probe.ProbeCgroupIdentity, pid: int) -> None:
    descriptor = os.open(
        probe._validate_owner(value) / "cgroup.procs",
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        raw = f"{pid}\n".encode("ascii")
        if os.write(descriptor, raw) != len(raw):
            raise probe.ProbeError("TARGET_CGROUP_ATTACH_FAILED")
    finally:
        os.close(descriptor)


def _write_byte(descriptor: int, value: bytes, code: str) -> None:
    try:
        if len(value) != 1 or os.write(descriptor, value) != 1:
            raise probe.ProbeError(code)
    except OSError as error:
        raise probe.ProbeError(code) from error


def _event(descriptor: int, deadline: float) -> str:
    remaining = deadline - time.monotonic()
    ready, _, _ = select.select([descriptor], [], [], max(0.0, remaining))
    if not ready:
        raise probe.ProbeError("TARGET_EVENT_TIMEOUT")
    value = bytearray()
    while len(value) <= 64:
        item = os.read(descriptor, 1)
        if not item:
            raise probe.ProbeError("TARGET_EVENT_UNAVAILABLE")
        if item == b"\n":
            return value.decode("ascii")
        value.extend(item)
    raise probe.ProbeError("TARGET_EVENT_INVALID")


def _stable_processes(
    value: probe.ProbeCgroupIdentity, expected: set[int], deadline: float
) -> set[int]:
    previous: set[int] | None = None
    while time.monotonic() < deadline:
        current = probe._cgroup_processes(probe._validate_owner(value))
        if current == expected and current == previous:
            return current
        previous = current
        time.sleep(0.005)
    raise probe.ProbeError("TARGET_PROCESS_SET_UNEXPECTED")


def _credentials(pid: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    lines = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii").splitlines()
    fields = {
        name: tuple(int(item) for item in raw.split())
        for line in lines
        for name, separator, raw in [line.partition(":")]
        if separator and name in {"Uid", "Gid"}
    }
    return fields.get("Uid", ()), fields.get("Gid", ())


def run(*, acknowledged: bool) -> dict[str, object]:
    probe._host_preflight(acknowledged)
    for unit in ("lumi-eggcracker.service", "lumi-eggcracker-watchdog.service"):
        if probe._load_state(unit) != "not-found":
            raise probe.ProbeError("ACTIVE_INSTALLATION_REFUSED")
    source_commit, source_tree_sha256 = probe._source_identity()
    example_source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    resources = probe.ProbeResources(target_pidfds={})
    report_fd: int | None = None
    barrier_fd: int | None = None
    result: dict[str, object] | None = None
    failure: BaseException | None = None
    cleanup_complete = False
    try:
        token = probe.secrets.token_hex(16)
        resources.unit = f"lumi-eggcracker-probe-{token}.service"
        probe._assert_owner_available(resources.unit)
        resources.owner_started = True
        _start_owner(resources.unit)
        resources.identity = probe._capture_owner(resources.unit)
        resources.canary, resources.canary_identity, resources.canary_pidfd = probe._spawn_canary()
        canary_cgroup = probe._process_cgroup(resources.canary_identity)
        if canary_cgroup == resources.identity.control_group or canary_cgroup.startswith(
            resources.identity.control_group + "/"
        ):
            raise probe.ProbeError("CANARY_INSIDE_TARGET_OWNER")
        resources.target, report_fd, barrier_fd = _spawn_target(resources.identity)
        target = identity(resources.target.pid)
        if target is None:
            raise probe.ProbeError("TARGET_IDENTITY_UNAVAILABLE")
        _attach(resources.identity, target.pid)
        expected_cgroup = resources.identity.control_group + "/target"
        if probe._process_cgroup(target) != expected_cgroup:
            raise probe.ProbeError("TARGET_OUTSIDE_CAPTURED_CGROUP")
        _write_byte(barrier_fd, b"A", "TARGET_ATTACH_RELEASE_FAILED")
        if _event(report_fd, deadline) != f"READY:{target.pid}":
            raise probe.ProbeError("TARGET_READINESS_INVALID")
        expected_credentials = ((TARGET_UID,) * 4, (TARGET_GID,) * 4)
        if _credentials(target.pid) != expected_credentials or identity(target.pid) != target:
            raise probe.ProbeError("TARGET_PRIVILEGE_DROP_FAILED")
        resources.target_pidfds[target] = open_pidfd(target)
        before = _stable_processes(resources.identity, {target.pid}, deadline)
        if probe._process_cgroup(target) != expected_cgroup:
            raise probe.ProbeError("TARGET_CGROUP_IDENTITY_DRIFT")
        signal.pidfd_send_signal(resources.target_pidfds[target], signal.SIGTERM)
        if _event(report_fd, deadline) != "CANCEL_STARTED":
            raise probe.ProbeError("CANCELLATION_BARRIER_NOT_REACHED")
        _write_byte(barrier_fd, b"F", "SNAPSHOT_RELEASE_FAILED")
        child_event = _event(report_fd, deadline)
        match = re.fullmatch(r"CHILD:([0-9]+)", child_event)
        if match is None:
            raise probe.ProbeError("CANCELLATION_CHILD_INVALID")
        child_pid = int(match.group(1))
        if child_pid in before or child_pid == target.pid:
            raise probe.ProbeError("CANCELLATION_CHILD_NOT_NEW")
        child = identity(child_pid)
        if child is None or probe._process_cgroup(child) != expected_cgroup:
            raise probe.ProbeError("CANCELLATION_CHILD_OUTSIDE_TARGET")
        at_kill = _stable_processes(resources.identity, {target.pid, child_pid}, deadline)
        if identity(target.pid) != target or identity(child_pid) != child:
            raise probe.ProbeError("TARGET_IDENTITY_DRIFT")
        target_path = probe._validate_owner(resources.identity)
        kill_path(target_path)
        _, populated, descendants = probe._strict_empty(resources.identity, deadline)
        if resources.canary_pidfd is None or not probe._pidfd_alive(resources.canary_pidfd):
            raise probe.ProbeError("CANARY_DIED")
        result = {
            "canary_survived": True,
            "child_absent_from_pre_cancel_snapshot": child_pid not in before,
            "children_created_during_cancellation": 1,
            "cleanup_complete": False,
            "descendant_cgroups_checked": descendants,
            "example_source_sha256": example_source_sha256,
            "mode": "fork-during-cancellation-example",
            "pre_cancel_snapshot_processes": len(before),
            "primitive": "cgroup.kill",
            "result": "TERMINATED",
            "root_populated": populated,
            "source_commit": source_commit,
            "source_tree_sha256": source_tree_sha256,
            "target_processes_at_kill": len(at_kill),
            "target_survivors": 0,
        }
    except (
        OSError,
        ProcessLookupError,
        UnicodeDecodeError,
        ValueError,
        probe.ProbeError,
        subprocess.SubprocessError,
    ) as error:
        failure = error
    finally:
        for descriptor in (report_fd, barrier_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    failure = failure or probe.ProbeError("PIPE_CLEANUP_FAILED")
        try:
            cleanup_complete = probe._cleanup(resources, deadline=min(deadline, time.monotonic() + 4))
        except (OSError, probe.ProbeError, subprocess.SubprocessError, RuntimeError) as error:
            failure = failure or error
    if not cleanup_complete:
        raise probe.ProbeError("CLEANUP_INCOMPLETE") from failure
    if failure is not None:
        if isinstance(failure, probe.ProbeError):
            raise failure
        raise probe.ProbeError("EXAMPLE_STAGE_FAILED") from failure
    if result is None:
        raise probe.ProbeError("EXAMPLE_INCOMPLETE")
    result["cleanup_complete"] = True
    if not (
        result["child_absent_from_pre_cancel_snapshot"] is True
        and result["root_populated"] == 0
        and result["target_survivors"] == 0
        and result["canary_survived"] is True
        and result["cleanup_complete"] is True
    ):
        raise probe.ProbeError("RACE_ACCEPTANCE_FAILED")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i-understand-this-kills-a-test-tree", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = run(acknowledged=args.i_understand_this_kills_a_test_tree)
    except probe.ProbeError as error:
        print(json.dumps({"mode": "fork-during-cancellation-example", "reason_code": error.code, "result": "FAILED"}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
