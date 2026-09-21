#!/usr/bin/env python3
"""Run one bounded fork-during-cancellation cgroup-v2 example."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
try:
    _source_entries = tuple(SOURCE_ROOT.iterdir())
except OSError:
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED") from None
if (
    len(_source_entries) != 1
    or _source_entries[0] != SOURCE_ROOT / "lumi_eggcracker"
    or _source_entries[0].is_symlink()
    or not _source_entries[0].is_dir()
):
    raise SystemExit("SOURCE_IMPORT_PATH_UNQUALIFIED")
sys.path.insert(0, str(SOURCE_ROOT))

from lumi_eggcracker import containment_probe as probe
from lumi_eggcracker.discovery import ProcessIdentity, identity
from lumi_eggcracker.jsonio import JsonInputError

MODE = "fork-during-cancellation-example"
OWNER_TASK_LIMIT = 3  # one systemd owner, one target, and exactly one child
MAX_CHILDREN = 1
WORKER_LIFETIME_SECONDS = 27
OWNER_RUNTIME_CEILING_SECONDS = 30
RUN_TIMEOUT_SECONDS = 22.0
STAGE_TIMEOUT_SECONDS = 3.0
CLEANUP_TIMEOUT_SECONDS = 5.0
CANCELLATION_UID = 65534
CANCELLATION_GID = 65534
SYSTEMCTL = probe.SYSTEMCTL
SYSTEMD_RUN = probe.SYSTEMD_RUN
PYTHON = probe.PYTHON
SCRIPT_RELATIVE = Path("scripts/cancellation_race_example.py")
SUCCESS_KEYS = frozenset(
    {
        "canary_identity_bound",
        "canary_survived",
        "child_absent_from_pre_cancel_snapshot",
        "children_created_during_cancellation",
        "cleanup_complete",
        "descendant_cgroups_checked",
        "example_source_sha256",
        "git_tree",
        "installation_performed",
        "journal_history_may_persist",
        "mode",
        "network_requests_made",
        "pre_cancel_snapshot_processes",
        "primitive",
        "result",
        "source_commit",
        "source_tree_sha256",
        "target_migration_denied",
        "target_populated",
        "target_processes_at_kill",
        "target_survivors",
        "target_unprivileged",
        "workload_detection_performed",
    }
)

CANCELLATION_TARGET_CODE = (
    "import os, signal, sys, time\n"
    f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
    "cgroup_fd, attach_gate, report_fd, fork_gate = map(int, sys.argv[1:5])\n"
    "parent_procs = sys.argv[5]\n"
    "def emit(value):\n"
    "    os.write(report_fd, value.encode('ascii') + b'\\n')\n"
    "os.write(cgroup_fd, b'0\\n')\n"
    "os.close(cgroup_fd)\n"
    "emit('ATTACHED:' + str(os.getpid()))\n"
    "if os.read(attach_gate, 1) != b'A': raise SystemExit(91)\n"
    "os.close(attach_gate)\n"
    "os.setgroups([])\n"
    f"os.setgid({CANCELLATION_GID})\n"
    f"os.setuid({CANCELLATION_UID})\n"
    "try:\n"
    "    migration_fd = os.open(parent_procs, os.O_WRONLY | os.O_CLOEXEC)\n"
    "except PermissionError:\n"
    "    migration_fd = -1\n"
    "if migration_fd >= 0:\n"
    "    os.close(migration_fd)\n"
    "    emit('MIGRATION_ALLOWED')\n"
    "    raise SystemExit(92)\n"
    "forked = False\n"
    "def on_cancel(_signum, _frame):\n"
    "    global forked\n"
    "    if forked: return\n"
    "    forked = True\n"
    "    emit('CANCEL_STARTED')\n"
    "    if os.read(fork_gate, 1) != b'F': return\n"
    "    try:\n"
    "        child_pid = os.fork()\n"
    "    except OSError:\n"
    "        emit('FORK_FAILED')\n"
    "        return\n"
    "    if child_pid == 0:\n"
    "        while time.monotonic() < deadline: time.sleep(0.1)\n"
    "        os._exit(0)\n"
    "    emit('CHILD:' + str(child_pid))\n"
    "signal.signal(signal.SIGTERM, on_cancel)\n"
    "emit('READY:' + str(os.getpid()))\n"
    "while time.monotonic() < deadline: time.sleep(0.1)\n"
)


@dataclass
class TargetChannels:
    process: subprocess.Popen[bytes]
    report_fd: int
    attach_release_fd: int
    fork_release_fd: int


@dataclass
class RaceResources:
    probe_resources: probe.ProbeResources
    report_fd: int | None = None
    attach_release_fd: int | None = None
    fork_release_fd: int | None = None
    target_cancel_pidfd: int | None = None
    canary_cgroup: str | None = None
    interrupted: bool = False


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=3.0,
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise probe.ProbeError("SOURCE_GIT_IDENTITY_UNAVAILABLE") from error
    if completed.returncode:
        raise probe.ProbeError("SOURCE_GIT_IDENTITY_UNAVAILABLE")
    return completed.stdout


def _source_identity(*, root: Path = ROOT) -> tuple[str, str, str, str]:
    """Bind the receipt to HEAD/tree and the exact committed standalone script."""
    commit, source_tree_sha256 = probe._source_identity(root=root)
    head = _git_bytes(root, "rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    git_tree = (
        _git_bytes(root, "rev-parse", "HEAD^{tree}").decode("ascii", errors="strict").strip()
    )
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or head != commit:
        raise probe.ProbeError("SOURCE_COMMIT_DRIFT")
    if not re.fullmatch(r"[0-9a-f]{40}", git_tree):
        raise probe.ProbeError("SOURCE_TREE_INVALID")

    script = root / SCRIPT_RELATIVE
    try:
        if script.is_symlink():
            raise probe.ProbeError("EXAMPLE_SOURCE_INVALID")
        raw = probe._bounded_bytes(script, maximum=1024 * 1024)
    except OSError as error:
        raise probe.ProbeError("EXAMPLE_SOURCE_UNAVAILABLE") from error
    example_source_sha256 = hashlib.sha256(raw).hexdigest()
    entry = _git_bytes(root, "ls-tree", "-z", "HEAD", "--", SCRIPT_RELATIVE.as_posix())
    entries = entry.split(b"\0")
    if len(entries) != 2 or entries[1] != b"":
        raise probe.ProbeError("EXAMPLE_SOURCE_NOT_COMMITTED")
    metadata, separator, relative = entries[0].partition(b"\t")
    fields = metadata.split()
    if (
        not separator
        or relative != SCRIPT_RELATIVE.as_posix().encode("ascii")
        or len(fields) != 3
        or fields[0] not in {b"100644", b"100755"}
        or fields[1] != b"blob"
        or not re.fullmatch(rb"[0-9a-f]{40}", fields[2])
    ):
        raise probe.ProbeError("EXAMPLE_SOURCE_NOT_COMMITTED")
    working_blob = _git_bytes(root, "hash-object", "--", SCRIPT_RELATIVE.as_posix()).strip()
    if working_blob != fields[2]:
        raise probe.ProbeError("EXAMPLE_SOURCE_DRIFT")
    return commit, source_tree_sha256, git_tree, example_source_sha256


def _check_no_active_service() -> None:
    for unit in ("lumi-eggcracker.service", "lumi-eggcracker-watchdog.service"):
        if probe._load_state(unit) == "not-found":
            continue
        active = probe._property(unit, "ActiveState").lower()
        if active not in {"inactive", "failed"}:
            raise probe.ProbeError("ACTIVE_SERVICE_REFUSED")


def _start_owner(unit: str) -> None:
    if not probe.PROBE_RE.fullmatch(unit):
        raise probe.ProbeError("UNIT_NAME_INVALID")
    owner_code = (
        "import time\n"
        f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
        "while time.monotonic() < deadline: time.sleep(0.1)\n"
    )
    result = probe._safe_run(
        [
            str(SYSTEMD_RUN),
            "--quiet",
            f"--unit={unit}",
            "--service-type=exec",
            "--property=Delegate=pids",
            f"--property=TasksMax={OWNER_TASK_LIMIT}",
            f"--property=RuntimeMaxSec={OWNER_RUNTIME_CEILING_SECONDS}s",
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=NoNewPrivileges=yes",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=3s",
            "--setenv=LANG=C.UTF-8",
            str(PYTHON),
            "-I",
            "-S",
            "-c",
            owner_code,
        ]
    )
    if result.returncode:
        raise probe.ProbeError("UNIT_START_FAILED")


def _spawn_canary() -> tuple[subprocess.Popen[bytes], ProcessIdentity, int]:
    worker = (
        "import time\n"
        f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
        "while time.monotonic() < deadline: time.sleep(0.1)\n"
    )
    process = subprocess.Popen(
        [str(PYTHON), "-I", "-S", "-c", worker],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
    )
    value = identity(process.pid)
    if value is None:
        process.kill()
        process.wait(timeout=1)
        raise probe.ProbeError("CANARY_IDENTITY_UNAVAILABLE")
    try:
        descriptor = probe.open_pidfd(value)
    except (JsonInputError, OSError, ProcessLookupError) as error:
        process.kill()
        process.wait(timeout=1)
        raise probe.ProbeError("CANARY_PIDFD_UNAVAILABLE") from error
    return process, value, descriptor


def _spawn_target(owner: probe.ProbeCgroupIdentity, resources: RaceResources) -> TargetChannels:
    path = probe._validate_owner(owner)
    cgroup_fd = os.open(
        path / "cgroup.procs",
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    owned: set[int] = {cgroup_fd}
    process: subprocess.Popen[bytes] | None = None
    try:
        attach_read, attach_write = os.pipe()
        fork_read, fork_write = os.pipe()
        report_read, report_write = os.pipe()
        owned.update((attach_read, attach_write, fork_read, fork_write, report_read, report_write))
        os.set_blocking(report_read, False)
        process = subprocess.Popen(
            [
                str(PYTHON),
                "-I",
                "-S",
                "-c",
                CANCELLATION_TARGET_CODE,
                str(cgroup_fd),
                str(attach_read),
                str(report_write),
                str(fork_read),
                str(_parent_membership_path(owner)),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(cgroup_fd, attach_read, report_write, fork_read),
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
        resources.probe_resources.target = process
        for descriptor in (cgroup_fd, attach_read, report_write, fork_read):
            os.close(descriptor)
            owned.remove(descriptor)
        for descriptor in (report_read, attach_write, fork_write):
            owned.remove(descriptor)
        return TargetChannels(process, report_read, attach_write, fork_write)
    finally:
        for descriptor in owned:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parent_membership_path(owner: probe.ProbeCgroupIdentity) -> Path:
    """Return the owner membership file that would let the target escape its child cgroup."""
    return owner.parent_path / "cgroup.procs"


def _read_event(descriptor: int, *, deadline: float) -> str:
    raw = bytearray()
    while time.monotonic() < deadline:
        try:
            chunk = os.read(descriptor, 128)
        except BlockingIOError:
            time.sleep(0.002)
            continue
        except OSError as error:
            raise probe.ProbeError("WORKER_CHANNEL_FAILED") from error
        if not chunk:
            raise probe.ProbeError("WORKER_CHANNEL_CLOSED")
        raw.extend(chunk)
        if len(raw) > 128:
            raise probe.ProbeError("WORKER_EVENT_INVALID")
        if b"\n" in raw:
            if raw.count(b"\n") != 1 or raw[-1:] != b"\n":
                raise probe.ProbeError("WORKER_EVENT_INVALID")
            try:
                return raw[:-1].decode("ascii")
            except UnicodeDecodeError as error:
                raise probe.ProbeError("WORKER_EVENT_INVALID") from error
    raise probe.ProbeError("WORKER_EVENT_TIMEOUT")


def _release_barrier(descriptor: int, token: bytes, code: str) -> None:
    try:
        if os.write(descriptor, token) != len(token):
            raise probe.ProbeError(code)
    except OSError as error:
        raise probe.ProbeError(code) from error


def _process_credentials(pid: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    try:
        lines = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise probe.ProbeError("TARGET_CREDENTIALS_UNAVAILABLE") from error
    credentials: dict[str, tuple[int, ...]] = {}
    for name in ("Uid", "Gid"):
        values = [line.split(":", 1)[1].split() for line in lines if line.startswith(name + ":")]
        if len(values) != 1 or len(values[0]) != 4 or any(not item.isdigit() for item in values[0]):
            raise probe.ProbeError("TARGET_CREDENTIALS_INVALID")
        credentials[name] = tuple(int(item) for item in values[0])
    return credentials["Uid"], credentials["Gid"]


def _wait_process_set(
    owner: probe.ProbeCgroupIdentity, expected_pids: set[int], *, deadline: float
) -> set[ProcessIdentity]:
    previous: tuple[ProcessIdentity, ...] | None = None
    stable = 0
    while time.monotonic() < deadline:
        path = probe._validate_owner(owner)
        values = probe._cgroup_processes(path)
        current_values = tuple(sorted(identity(pid) for pid in values if identity(pid) is not None))
        if values == expected_pids and len(current_values) == len(expected_pids) and current_values == previous:
            stable += 1
            if stable >= 2:
                return set(current_values)
        else:
            stable = 0
        previous = current_values
        time.sleep(0.005)
    raise probe.ProbeError("TARGET_PROCESS_SET_TIMEOUT")


def _assert_canary_survived(resources: RaceResources, owner: probe.ProbeCgroupIdentity) -> None:
    canary = resources.probe_resources.canary_identity
    descriptor = resources.probe_resources.canary_pidfd
    if canary is None or descriptor is None or resources.canary_cgroup is None:
        raise probe.ProbeError("CANARY_IDENTITY_UNAVAILABLE")
    if identity(canary.pid) != canary:
        raise probe.ProbeError("CANARY_IDENTITY_DRIFT")
    if probe._process_cgroup(canary) != resources.canary_cgroup:
        raise probe.ProbeError("CANARY_CGROUP_DRIFT")
    if resources.canary_cgroup == owner.control_group or resources.canary_cgroup.startswith(
        owner.control_group + "/"
    ):
        raise probe.ProbeError("CANARY_INSIDE_TARGET_OWNER")
    if not probe._pidfd_alive(descriptor):
        raise probe.ProbeError("CANARY_DIED")


def _close_held(resources: RaceResources) -> bool:
    ok = True
    for attribute in ("target_cancel_pidfd", "report_fd", "attach_release_fd", "fork_release_fd"):
        descriptor = getattr(resources, attribute)
        if descriptor is None:
            continue
        setattr(resources, attribute, None)
        try:
            os.close(descriptor)
        except OSError:
            ok = False
    return ok


def _assert_uninterrupted(resources: RaceResources) -> None:
    if resources.interrupted:
        raise probe.ProbeError("INTERRUPTED")


def run_example(*, acknowledged: bool) -> dict[str, object]:
    probe._host_preflight(acknowledged)
    _check_no_active_service()
    source_commit, source_tree_sha256, git_tree, example_source_sha256 = _source_identity()
    started = time.monotonic()
    deadline = started + RUN_TIMEOUT_SECONDS
    previous_handlers: dict[int, object] = {}
    resources: RaceResources | None = None
    interrupted = False

    def request_cleanup(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        if resources is not None:
            resources.interrupted = True

    handled_signals = {signal.SIGINT, signal.SIGTERM}
    if hasattr(signal, "SIGHUP"):
        handled_signals.add(signal.SIGHUP)
    for signum in handled_signals:
        previous_handlers[signum] = signal.signal(signum, request_cleanup)

    resources = RaceResources(probe.ProbeResources(target_pidfds={}))
    resources.interrupted = interrupted

    success: dict[str, object] | None = None
    failure: probe.ProbeError | None = None
    held_fds_closed = True
    cleanup_complete = False
    try:
        _assert_uninterrupted(resources)
        token = probe.secrets.token_hex(16)
        base = resources.probe_resources
        base.unit = f"lumi-eggcracker-probe-{token}.service"
        probe._assert_owner_available(base.unit)
        base.owner_started = True
        _start_owner(base.unit)
        _assert_uninterrupted(resources)
        base.identity = probe._capture_owner(base.unit)
        base.canary, base.canary_identity, base.canary_pidfd = _spawn_canary()
        resources.canary_cgroup = probe._process_cgroup(base.canary_identity)
        if resources.canary_cgroup == base.identity.control_group or resources.canary_cgroup.startswith(
            base.identity.control_group + "/"
        ):
            raise probe.ProbeError("CANARY_INSIDE_TARGET_OWNER")

        channels = _spawn_target(base.identity, resources)
        resources.report_fd = channels.report_fd
        resources.attach_release_fd = channels.attach_release_fd
        resources.fork_release_fd = channels.fork_release_fd
        expected_cgroup = base.identity.control_group + "/target"
        attached = _read_event(
            resources.report_fd,
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if attached != f"ATTACHED:{channels.process.pid}":
            raise probe.ProbeError("TARGET_ATTACH_EVENT_INVALID")
        target_identity = identity(channels.process.pid)
        if target_identity is None or probe._process_cgroup(target_identity) != expected_cgroup:
            raise probe.ProbeError("TARGET_OUTSIDE_CAPTURED_CGROUP")
        _release_barrier(
            resources.attach_release_fd,
            b"A",
            "TARGET_ATTACH_RELEASE_FAILED",
        )
        os.close(resources.attach_release_fd)
        resources.attach_release_fd = None
        ready = _read_event(
            resources.report_fd,
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if ready == "MIGRATION_ALLOWED":
            raise probe.ProbeError("TARGET_MIGRATION_ALLOWED")
        ready_match = re.fullmatch(r"READY:([0-9]+)", ready)
        if ready_match is None or int(ready_match.group(1)) != target_identity.pid:
            raise probe.ProbeError("TARGET_READINESS_INVALID")
        expected_credentials = (
            (CANCELLATION_UID,) * 4,
            (CANCELLATION_GID,) * 4,
        )
        if _process_credentials(target_identity.pid) != expected_credentials:
            raise probe.ProbeError("TARGET_PRIVILEGE_DROP_FAILED")
        if identity(target_identity.pid) != target_identity:
            raise probe.ProbeError("TARGET_IDENTITY_DRIFT")
        resources.target_cancel_pidfd = probe.open_pidfd(target_identity)

        before_cancel = _wait_process_set(
            base.identity,
            {target_identity.pid},
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if before_cancel != {target_identity}:
            raise probe.ProbeError("PRE_CANCEL_SNAPSHOT_INVALID")
        _assert_uninterrupted(resources)
        probe._validate_owner(base.identity)
        if probe._process_cgroup(target_identity) != expected_cgroup:
            raise probe.ProbeError("TARGET_CGROUP_IDENTITY_DRIFT")
        signal.pidfd_send_signal(resources.target_cancel_pidfd, signal.SIGTERM)

        cancellation_event = _read_event(
            resources.report_fd,
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if cancellation_event != "CANCEL_STARTED":
            raise probe.ProbeError("CANCELLATION_BARRIER_NOT_REACHED")
        _assert_uninterrupted(resources)
        _release_barrier(
            resources.fork_release_fd,
            b"F",
            "CANCELLATION_FORK_RELEASE_FAILED",
        )
        os.close(resources.fork_release_fd)
        resources.fork_release_fd = None
        child_event = _read_event(
            resources.report_fd,
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        child_match = re.fullmatch(r"CHILD:([0-9]+)", child_event)
        if child_match is None:
            raise probe.ProbeError("CANCELLATION_CHILD_INVALID")
        child_pid = int(child_match.group(1))
        if child_pid == target_identity.pid:
            raise probe.ProbeError("CANCELLATION_CHILD_NOT_NEW")
        child_identity = identity(child_pid)
        if child_identity is None or probe._process_cgroup(child_identity) != expected_cgroup:
            raise probe.ProbeError("CANCELLATION_CHILD_OUTSIDE_TARGET")
        if child_identity in before_cancel or child_pid in {item.pid for item in before_cancel}:
            raise probe.ProbeError("CANCELLATION_CHILD_NOT_NEW")
        at_kill = _wait_process_set(
            base.identity,
            {target_identity.pid, child_identity.pid},
            deadline=min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if at_kill != {target_identity, child_identity}:
            raise probe.ProbeError("CANCELLATION_PROCESS_SET_INVALID")
        _assert_uninterrupted(resources)
        if identity(target_identity.pid) != target_identity or identity(child_identity.pid) != child_identity:
            raise probe.ProbeError("CANCELLATION_CHILD_IDENTITY_DRIFT")
        if any(
            probe._process_cgroup(value) != expected_cgroup
            for value in (target_identity, child_identity)
        ):
            raise probe.ProbeError("TARGET_CGROUP_IDENTITY_DRIFT")

        target_path = probe._validate_owner(base.identity)
        probe.kill_path(target_path)
        _empty_ns, populated, descendants = probe._strict_empty(
            base.identity,
            min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS),
        )
        if populated != 0:
            raise probe.ProbeError("TARGET_NOT_EMPTY")
        _assert_canary_survived(resources, base.identity)
        _assert_uninterrupted(resources)
        success = {
            "canary_identity_bound": True,
            "canary_survived": True,
            "child_absent_from_pre_cancel_snapshot": child_identity not in before_cancel,
            "children_created_during_cancellation": MAX_CHILDREN,
            "cleanup_complete": False,
            "descendant_cgroups_checked": descendants,
            "example_source_sha256": example_source_sha256,
            "git_tree": git_tree,
            "installation_performed": False,
            "journal_history_may_persist": True,
            "mode": MODE,
            "network_requests_made": False,
            "pre_cancel_snapshot_processes": len(before_cancel),
            "primitive": "cgroup.kill",
            "result": "TERMINATED",
            "source_commit": source_commit,
            "source_tree_sha256": source_tree_sha256,
            "target_migration_denied": True,
            "target_populated": populated,
            "target_processes_at_kill": len(at_kill),
            "target_survivors": 0,
            "target_unprivileged": True,
            "workload_detection_performed": False,
        }
    except (probe.ProbeError, JsonInputError, OSError, ProcessLookupError, subprocess.SubprocessError) as error:
        failure = error if isinstance(error, probe.ProbeError) else probe.ProbeError("RACE_STAGE_FAILED")
    finally:
        held_fds_closed = _close_held(resources)
        try:
            cleanup_complete = probe._cleanup(
                resources.probe_resources,
                deadline=min(started + RUN_TIMEOUT_SECONDS + CLEANUP_TIMEOUT_SECONDS,
                             time.monotonic() + CLEANUP_TIMEOUT_SECONDS),
            )
        except (OSError, probe.ProbeError, JsonInputError, subprocess.SubprocessError, RuntimeError):
            cleanup_complete = False
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    if resources.interrupted and failure is None:
        failure = probe.ProbeError("INTERRUPTED")
    if not held_fds_closed:
        raise probe.ProbeError("HELD_PIDFD_CLEANUP_FAILED") from failure
    if not cleanup_complete:
        raise probe.ProbeError("CLEANUP_INCOMPLETE") from failure
    if failure is not None:
        raise failure
    if success is None:
        raise probe.ProbeError("RACE_INCOMPLETE")
    success["cleanup_complete"] = True
    if set(success) != SUCCESS_KEYS:
        raise probe.ProbeError("RECEIPT_SCHEMA_INVALID")
    if (
        success["target_populated"] != 0
        or success["target_survivors"] != 0
        or success["canary_identity_bound"] is not True
        or success["canary_survived"] is not True
        or success["child_absent_from_pre_cancel_snapshot"] is not True
        or success["children_created_during_cancellation"] != MAX_CHILDREN
        or success["pre_cancel_snapshot_processes"] != 1
        or success["target_processes_at_kill"] != 2
        or success["target_migration_denied"] is not True
        or success["target_unprivileged"] is not True
        or success["cleanup_complete"] is not True
    ):
        raise probe.ProbeError("RACE_ACCEPTANCE_FAILED")
    return success


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one bounded Lumi Eggcracker fork-during-cancellation example"
    )
    parser.add_argument("--i-understand-this-kills-a-test-tree", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = run_example(acknowledged=args.i_understand_this_kills_a_test_tree)
    except probe.ProbeError as error:
        print(
            json.dumps({"mode": MODE, "reason_code": error.code, "result": "FAILED"}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
