"""Bounded no-network proof of the direct Linux containment primitive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .adoption import open_pidfd, stop_pidfd
from .containment import boot_id, events_from_fd, kill_path
from .discovery import ProcessIdentity, identity
from .jsonio import JsonInputError

CGROUP_ROOT = Path("/sys/fs/cgroup")
SYSTEM_SLICE = CGROUP_ROOT / "system.slice"
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
PYTHON = Path("/usr/bin/python3")
WORKER_LIFETIME_SECONDS = 45
OWNER_TASK_LIMIT = 3
WORKER_SLEEP_CODE = (
    "import time\n"
    f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
    "while time.monotonic() < deadline: time.sleep(0.1)\n"
)
WORKER_TARGET_CODE = (
    "import os, subprocess, sys, time\n"
    f"deadline = time.monotonic() + {WORKER_LIFETIME_SECONDS}\n"
    "descriptor = int(sys.argv[1])\n"
    "os.write(descriptor, b'0\\n')\n"
    "os.close(descriptor)\n"
    f"subprocess.Popen([sys.executable, '-I', '-S', '-c', {WORKER_SLEEP_CODE!r}], close_fds=True)\n"
    "while time.monotonic() < deadline: time.sleep(0.1)\n"
)
PROBE_RE = re.compile(r"^lumi-eggcracker-probe-([0-9a-f]{32})\.service$")
INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
TOTAL_TIMEOUT_SECONDS = 20.0
STAGE_TIMEOUT_SECONDS = 3.0
INSTALL_TARGETS = (
    Path("/usr/local/lib/lumi-eggcracker"),
    Path("/usr/local/bin/eggcracker"),
    Path("/etc/lumi-eggcracker"),
    Path("/var/lib/lumi-eggcracker"),
    Path("/run/lumi-eggcracker"),
    Path("/run/lumi-eggcracker-watchdog"),
    Path("/etc/systemd/system/lumi-eggcracker.service"),
    Path("/etc/systemd/system/lumi-eggcracker-watchdog.service"),
    Path("/etc/tmpfiles.d/lumi-eggcracker.conf"),
)
SUCCESS_KEYS = frozenset(
    {
        "canary_survived",
        "changes_made",
        "cleanup_complete",
        "descendant_cgroups_checked",
        "installation_performed",
        "journal_history_may_persist",
        "mode",
        "network_requests_made",
        "primitive",
        "result",
        "root_populated",
        "source_commit",
        "source_tree_sha256",
        "target_processes",
        "target_survivors",
        "trigger_to_empty_ms",
        "workload_detection_performed",
    }
)


class ProbeError(RuntimeError):
    """One bounded public failure code without host-private detail."""

    def __init__(self, code: str) -> None:
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code):
            raise ValueError("invalid probe failure code")
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ProbeCgroupIdentity:
    unit: str
    invocation_id: str
    control_group: str
    parent_device: int
    parent_inode: int
    target_device: int
    target_inode: int
    boot: str

    @property
    def parent_path(self) -> Path:
        return CGROUP_ROOT.joinpath(*self.control_group.lstrip("/").split("/"))

    @property
    def target_path(self) -> Path:
        return self.parent_path / "target"


@dataclass
class ProbeResources:
    unit: str | None = None
    owner_started: bool = False
    identity: ProbeCgroupIdentity | None = None
    target: subprocess.Popen[bytes] | None = None
    canary: subprocess.Popen[bytes] | None = None
    target_pidfds: dict[ProcessIdentity, int] | None = None
    canary_identity: ProcessIdentity | None = None
    canary_pidfd: int | None = None
    interrupted: bool = False


def _bounded_bytes(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ProbeError("SOURCE_IDENTITY_INVALID")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        value = b"".join(chunks)
        if len(value) != metadata.st_size:
            raise ProbeError("SOURCE_IDENTITY_DRIFT")
        return value
    finally:
        os.close(descriptor)


def _source_identity(*, root: Path | None = None) -> tuple[str, str]:
    root = root or Path(__file__).resolve().parents[2]
    git_dir = root / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise ProbeError("SOURCE_GIT_IDENTITY_REQUIRED")
    try:
        head = _bounded_bytes(git_dir / "HEAD", maximum=4096).decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ProbeError("SOURCE_COMMIT_UNAVAILABLE") from error
    commit = head
    if head.startswith("ref: "):
        reference = head.removeprefix("ref: ")
        if not re.fullmatch(r"refs/[A-Za-z0-9._/-]{1,240}", reference) or ".." in reference:
            raise ProbeError("SOURCE_REFERENCE_INVALID")
        reference_path = git_dir.joinpath(*reference.split("/"))
        try:
            commit = _bounded_bytes(reference_path, maximum=128).decode("ascii").strip()
        except FileNotFoundError:
            try:
                packed = _bounded_bytes(git_dir / "packed-refs", maximum=1024 * 1024).decode(
                    "ascii"
                )
            except (OSError, UnicodeDecodeError) as error:
                raise ProbeError("SOURCE_COMMIT_UNAVAILABLE") from error
            matches = [
                line.split(" ", 1)[0]
                for line in packed.splitlines()
                if not line.startswith(("#", "^")) and line.endswith(" " + reference)
            ]
            if len(matches) != 1:
                raise ProbeError("SOURCE_COMMIT_UNAVAILABLE")
            commit = matches[0]
        except (OSError, UnicodeDecodeError) as error:
            raise ProbeError("SOURCE_COMMIT_UNAVAILABLE") from error
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ProbeError("SOURCE_COMMIT_INVALID")
    relatives = (
        Path("scripts/containment_probe.py"),
        Path("src/lumi_eggcracker/__init__.py"),
        Path("src/lumi_eggcracker/adoption.py"),
        Path("src/lumi_eggcracker/containment.py"),
        Path("src/lumi_eggcracker/containment_probe.py"),
        Path("src/lumi_eggcracker/discovery.py"),
        Path("src/lumi_eggcracker/jsonio.py"),
    )
    digest = hashlib.sha256()
    try:
        for relative in relatives:
            raw = _bounded_bytes(root / relative, maximum=1024 * 1024)
            name = relative.as_posix().encode("ascii")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
    except OSError as error:
        raise ProbeError("SOURCE_TREE_UNAVAILABLE") from error
    return commit, digest.hexdigest()


def _safe_run(argv: list[str], *, timeout: float = STAGE_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ProbeError("HOST_COMMAND_FAILED") from error


def _property(unit: str, name: str) -> str:
    result = _safe_run([str(SYSTEMCTL), "show", unit, f"--property={name}", "--value"])
    if result.returncode:
        raise ProbeError("UNIT_IDENTITY_UNAVAILABLE")
    return result.stdout.strip()


def _load_state(unit: str) -> str:
    result = _safe_run([str(SYSTEMCTL), "show", unit, "--property=LoadState", "--value"])
    value = result.stdout.strip()
    if value == "not-found":
        return value
    if result.returncode or not value:
        raise ProbeError("UNIT_STATE_UNAVAILABLE")
    return value


def _read_events(path: Path) -> dict[str, int]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return events_from_fd(descriptor)
    finally:
        os.close(descriptor)


def _write_control(path: Path, value: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if os.write(descriptor, value) != len(value):
            raise ProbeError("CGROUP_CONTROL_SHORT_WRITE")
    finally:
        os.close(descriptor)


def _exact_directory(path: Path) -> os.stat_result:
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ProbeError("CGROUP_IDENTITY_UNAVAILABLE") from error
    if path.is_symlink() or not stat.S_ISDIR(value.st_mode):
        raise ProbeError("CGROUP_IDENTITY_INVALID")
    return value


def _host_preflight(acknowledged: bool) -> None:
    if not acknowledged:
        raise ProbeError("DISPOSABLE_HOST_ACK_REQUIRED")
    if platform.system() != "Linux":
        raise ProbeError("NATIVE_LINUX_REQUIRED")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ProbeError("ROOT_REQUIRED")
    if Path("/run/systemd/container").exists():
        raise ProbeError("CONTAINER_UNSUPPORTED")
    try:
        osrelease = Path("/proc/sys/kernel/osrelease").read_text(encoding="ascii").lower()
        comm = Path("/proc/1/comm").read_text(encoding="ascii").strip()
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ProbeError("HOST_IDENTITY_UNAVAILABLE") from error
    if "microsoft" in osrelease or os.environ.get("WSL_DISTRO_NAME"):
        raise ProbeError("WSL_UNSUPPORTED")
    if comm != "systemd":
        raise ProbeError("SYSTEMD_PID1_REQUIRED")
    if not re.search(r'^ID=["\']?ubuntu["\']?$', os_release, re.MULTILINE) or not re.search(
        r'^VERSION_ID=["\']?24\.04["\']?$', os_release, re.MULTILINE
    ):
        raise ProbeError("UBUNTU_2404_REQUIRED")
    if not all(path.is_file() for path in (SYSTEMCTL, SYSTEMD_RUN, PYTHON)):
        raise ProbeError("REQUIRED_COMMAND_MISSING")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ProbeError("PIDFD_UNAVAILABLE")
    try:
        controllers = (CGROUP_ROOT / "cgroup.controllers").read_text(encoding="ascii").split()
    except (OSError, UnicodeDecodeError) as error:
        raise ProbeError("CGROUP_V2_UNAVAILABLE") from error
    if "pids" not in controllers:
        raise ProbeError("PIDS_CONTROLLER_UNAVAILABLE")
    if any(path.exists() or path.is_symlink() for path in INSTALL_TARGETS):
        raise ProbeError("ACTIVE_INSTALLATION_REFUSED")


def _start_owner(unit: str) -> None:
    if not PROBE_RE.fullmatch(unit):
        raise ProbeError("UNIT_NAME_INVALID")
    result = _safe_run(
        [
            str(SYSTEMD_RUN),
            "--quiet",
            f"--unit={unit}",
            "--service-type=exec",
            "--property=Delegate=pids",
            f"--property=TasksMax={OWNER_TASK_LIMIT}",
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
            WORKER_SLEEP_CODE,
        ]
    )
    if result.returncode:
        raise ProbeError("UNIT_START_FAILED")


def _assert_owner_available(unit: str) -> None:
    if not PROBE_RE.fullmatch(unit):
        raise ProbeError("UNIT_NAME_INVALID")
    expected = SYSTEM_SLICE / unit
    if _load_state(unit) != "not-found" or expected.exists() or expected.is_symlink():
        raise ProbeError("UNIT_COLLISION")


def _capture_owner(unit: str) -> ProbeCgroupIdentity:
    match = PROBE_RE.fullmatch(unit)
    if match is None:
        raise ProbeError("UNIT_NAME_INVALID")
    invocation = _property(unit, "InvocationID").lower()
    cgroup = _property(unit, "ControlGroup")
    if not INVOCATION_RE.fullmatch(invocation):
        raise ProbeError("INVOCATION_ID_INVALID")
    if cgroup != f"/system.slice/{unit}":
        raise ProbeError("CONTROL_GROUP_INVALID")
    parent = CGROUP_ROOT.joinpath(*cgroup.lstrip("/").split("/"))
    metadata = _exact_directory(parent)
    parent_required = ("pids.events", "pids.max")
    if not all((parent / item).is_file() for item in parent_required):
        raise ProbeError("OWNER_TASK_CONTROLS_MISSING")
    try:
        task_limit = (parent / "pids.max").read_text(encoding="ascii").strip()
        task_events = _read_events(parent / "pids.events")
    except (OSError, UnicodeDecodeError) as error:
        raise ProbeError("OWNER_TASK_LIMIT_UNAVAILABLE") from error
    if task_limit != str(OWNER_TASK_LIMIT) or "max" not in task_events:
        raise ProbeError("OWNER_TASK_LIMIT_INVALID")
    target = parent / "target"
    try:
        target.mkdir(mode=0o755)
    except OSError as error:
        raise ProbeError("TARGET_CGROUP_CREATE_FAILED") from error
    target_meta = _exact_directory(target)
    required = ("cgroup.events", "cgroup.kill", "cgroup.procs")
    if not all((target / item).is_file() for item in required):
        raise ProbeError("TARGET_CGROUP_CONTROLS_MISSING")
    if "populated" not in _read_events(target / "cgroup.events"):
        raise ProbeError("TARGET_CGROUP_EVENTS_INVALID")
    return ProbeCgroupIdentity(
        unit,
        invocation,
        cgroup,
        metadata.st_dev,
        metadata.st_ino,
        target_meta.st_dev,
        target_meta.st_ino,
        boot_id(),
    )


def _validate_owner(value: ProbeCgroupIdentity) -> Path:
    if boot_id() != value.boot:
        raise ProbeError("BOOT_IDENTITY_DRIFT")
    if _property(value.unit, "InvocationID").lower() != value.invocation_id:
        raise ProbeError("INVOCATION_ID_DRIFT")
    if _property(value.unit, "ControlGroup") != value.control_group:
        raise ProbeError("CONTROL_GROUP_DRIFT")
    parent = _exact_directory(value.parent_path)
    target = _exact_directory(value.target_path)
    if (parent.st_dev, parent.st_ino) != (value.parent_device, value.parent_inode):
        raise ProbeError("OWNER_CGROUP_IDENTITY_DRIFT")
    if (target.st_dev, target.st_ino) != (value.target_device, value.target_inode):
        raise ProbeError("TARGET_CGROUP_IDENTITY_DRIFT")
    return value.target_path


def _cgroup_processes(path: Path) -> set[int]:
    directories = [path, *(item for item in path.rglob("*") if item.is_dir() and not item.is_symlink())]
    values: set[int] = set()
    for directory in directories:
        try:
            lines = (directory / "cgroup.procs").read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise ProbeError("CGROUP_PROCESS_READ_FAILED") from error
        if any(not line.isdigit() for line in lines):
            raise ProbeError("CGROUP_PROCESS_LIST_INVALID")
        values.update(int(line) for line in lines)
    return values


def _wait_target(value: ProbeCgroupIdentity, deadline: float) -> tuple[ProcessIdentity, ProcessIdentity]:
    previous: tuple[ProcessIdentity, ...] | None = None
    stable = 0
    while time.monotonic() < deadline:
        path = _validate_owner(value)
        current_values = _cgroup_processes(path)
        resolved = tuple(identity(pid) for pid in current_values)
        current = tuple(sorted(item for item in resolved if item is not None))
        if len(current_values) == 2 and len(current) == 2 and current == previous:
            stable += 1
            if stable >= 2:
                return current[0], current[1]
        else:
            stable = 0
        previous = current
        time.sleep(0.005)
    raise ProbeError("TARGET_READINESS_TIMEOUT")


def _process_cgroup(value: ProcessIdentity) -> str:
    if identity(value.pid) != value:
        raise ProbeError("PROCESS_IDENTITY_DRIFT")
    try:
        lines = (Path("/proc") / str(value.pid) / "cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ProbeError("PROCESS_CGROUP_UNAVAILABLE") from error
    matches = [line.removeprefix("0::") for line in lines if line.startswith("0::")]
    if len(matches) != 1:
        raise ProbeError("PROCESS_CGROUP_INVALID")
    return matches[0]


def _strict_empty(value: ProbeCgroupIdentity, deadline: float) -> tuple[int, int, int]:
    last_count = -1
    while time.monotonic() < deadline:
        path = _validate_owner(value)
        populated = _read_events(path / "cgroup.events").get("populated", -1)
        survivors = _cgroup_processes(path)
        last_count = len(survivors)
        if populated == 0 and not survivors:
            descendants = 1 + sum(1 for item in path.rglob("*") if item.is_dir() and not item.is_symlink())
            return time.monotonic_ns(), populated, descendants
        time.sleep(0.002)
    raise ProbeError("EMPTY_PROOF_TIMEOUT" if last_count >= 0 else "EMPTY_PROOF_UNAVAILABLE")


def _pidfd_alive(descriptor: int) -> bool:
    try:
        signal.pidfd_send_signal(descriptor, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        raise ProbeError("PIDFD_LIVENESS_FAILED") from error


def _spawn_canary() -> tuple[subprocess.Popen[bytes], ProcessIdentity, int]:
    process = subprocess.Popen(
        [str(PYTHON), "-I", "-S", "-c", WORKER_SLEEP_CODE],
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
        raise ProbeError("CANARY_IDENTITY_UNAVAILABLE")
    try:
        descriptor = open_pidfd(value)
    except (JsonInputError, OSError, ProcessLookupError):
        process.kill()
        process.wait(timeout=1)
        raise
    return process, value, descriptor


def _spawn_target(value: ProbeCgroupIdentity) -> subprocess.Popen[bytes]:
    path = _validate_owner(value)
    descriptor = os.open(
        path / "cgroup.procs",
        os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        return subprocess.Popen(
            [str(PYTHON), "-I", "-S", "-c", WORKER_TARGET_CODE, str(descriptor)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=(descriptor,),
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
    finally:
        os.close(descriptor)


def _held_kill(descriptor: int) -> None:
    try:
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ProbeError("HELD_PIDFD_CLEANUP_FAILED") from error


def _cleanup(resources: ProbeResources, *, deadline: float) -> bool:
    ok = True
    if resources.identity is not None:
        try:
            path = _validate_owner(resources.identity)
            if _cgroup_processes(path):
                kill_path(path)
            empty_ns, populated, _descendants = _strict_empty(resources.identity, min(deadline, time.monotonic() + 1.0))
            del empty_ns
            if populated != 0:
                ok = False
            path.rmdir()
        except (OSError, ProbeError, JsonInputError):
            ok = False
    for descriptor in (resources.target_pidfds or {}).values():
        try:
            _held_kill(descriptor)
        except ProbeError:
            ok = False
        try:
            os.close(descriptor)
        except OSError:
            ok = False
    resources.target_pidfds = {}
    if resources.canary_pidfd is not None:
        try:
            _held_kill(resources.canary_pidfd)
        except ProbeError:
            ok = False
        try:
            os.close(resources.canary_pidfd)
        except OSError:
            ok = False
        resources.canary_pidfd = None
    for process in (resources.target, resources.canary):
        if process is None:
            continue
        try:
            process.wait(timeout=max(0.1, min(1.0, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            ok = False
    if resources.unit is not None and resources.owner_started:
        try:
            if (
                resources.identity is not None
                and _property(resources.unit, "InvocationID").lower()
                != resources.identity.invocation_id
            ):
                return False
            stopped = _safe_run([str(SYSTEMCTL), "stop", resources.unit], timeout=2.0)
            if stopped.returncode and _load_state(resources.unit) != "not-found":
                ok = False
            reset = _safe_run([str(SYSTEMCTL), "reset-failed", resources.unit], timeout=2.0)
            if reset.returncode and _load_state(resources.unit) != "not-found":
                ok = False
        except ProbeError:
            ok = False
        while time.monotonic() < deadline:
            parent_gone = resources.identity is None or not resources.identity.parent_path.exists()
            if _load_state(resources.unit) == "not-found" and parent_gone:
                break
            time.sleep(0.02)
        else:
            ok = False
    return ok


def run_probe(*, acknowledged: bool) -> dict[str, object]:
    _host_preflight(acknowledged)
    source_commit, source_tree_sha256 = _source_identity()
    started = time.monotonic()
    deadline = started + TOTAL_TIMEOUT_SECONDS
    resources = ProbeResources(target_pidfds={})
    previous_handlers: dict[int, object] = {}

    def request_cleanup(_signum: int, _frame: object) -> None:
        resources.interrupted = True

    handled_signals = {signal.SIGINT, signal.SIGTERM}
    if hasattr(signal, "SIGHUP"):
        handled_signals.add(signal.SIGHUP)
    for signum in handled_signals:
        previous_handlers[signum] = signal.signal(signum, request_cleanup)
    success: dict[str, object] | None = None
    failure: ProbeError | None = None
    cleanup_complete = False
    try:
        token = secrets.token_hex(16)
        resources.unit = f"lumi-eggcracker-probe-{token}.service"
        _assert_owner_available(resources.unit)
        # From this point an exact, preflight-empty 128-bit unit name has been
        # handed to systemd. Cleanup must attempt that exact name even when
        # command completion or owner capture fails.
        resources.owner_started = True
        _start_owner(resources.unit)
        resources.identity = _capture_owner(resources.unit)
        resources.canary, resources.canary_identity, resources.canary_pidfd = _spawn_canary()
        canary_cgroup = _process_cgroup(resources.canary_identity)
        if canary_cgroup == resources.identity.control_group or canary_cgroup.startswith(
            resources.identity.control_group + "/"
        ):
            raise ProbeError("CANARY_INSIDE_TARGET_OWNER")
        resources.target = _spawn_target(resources.identity)
        targets = _wait_target(resources.identity, min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS))
        if resources.interrupted:
            raise ProbeError("INTERRUPTED")
        expected_cgroup = resources.identity.control_group + "/target"
        if any(_process_cgroup(value) != expected_cgroup for value in targets):
            raise ProbeError("TARGET_OUTSIDE_CAPTURED_CGROUP")
        for value in targets:
            resources.target_pidfds[value] = open_pidfd(value)
        stop_times = [stop_pidfd(value, resources.target_pidfds[value]) for value in targets]
        if resources.interrupted:
            raise ProbeError("INTERRUPTED")
        path = _validate_owner(resources.identity)
        kill_path(path)
        empty_ns, populated, descendants = _strict_empty(
            resources.identity, min(deadline, time.monotonic() + STAGE_TIMEOUT_SECONDS)
        )
        if resources.canary_pidfd is None or not _pidfd_alive(resources.canary_pidfd):
            raise ProbeError("CANARY_DIED")
        success = {
            "canary_survived": True,
            "changes_made": True,
            "cleanup_complete": False,
            "descendant_cgroups_checked": descendants,
            "installation_performed": False,
            "journal_history_may_persist": True,
            "mode": "containment-primitive-probe",
            "network_requests_made": False,
            "primitive": "pidfd-stop+cgroup.kill",
            "result": "TERMINATED",
            "root_populated": populated,
            "source_commit": source_commit,
            "source_tree_sha256": source_tree_sha256,
            "target_processes": len(targets),
            "target_survivors": 0,
            "trigger_to_empty_ms": round((empty_ns - min(stop_times)) / 1_000_000, 3),
            "workload_detection_performed": False,
        }
    except (ProbeError, JsonInputError, OSError, ProcessLookupError, subprocess.SubprocessError) as error:
        failure = error if isinstance(error, ProbeError) else ProbeError("PROBE_STAGE_FAILED")
    finally:
        try:
            cleanup_complete = _cleanup(
                resources, deadline=min(deadline, time.monotonic() + 4.0)
            )
        except (OSError, ProbeError, JsonInputError, subprocess.SubprocessError, RuntimeError):
            cleanup_complete = False
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    if resources.interrupted and failure is None:
        failure = ProbeError("INTERRUPTED")
    if not cleanup_complete:
        raise ProbeError("CLEANUP_INCOMPLETE") from failure
    if failure is not None:
        raise failure
    if success is None:
        raise ProbeError("PROBE_INCOMPLETE")
    success["cleanup_complete"] = True
    if set(success) != SUCCESS_KEYS:
        raise ProbeError("RECEIPT_SCHEMA_INVALID")
    return success


def failure_receipt(code: str) -> dict[str, object]:
    return {
        "mode": "containment-primitive-probe",
        "reason_code": code,
        "result": "FAILED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe Lumi Eggcracker's bounded Linux containment primitive")
    parser.add_argument("--i-understand-this-kills-a-test-tree", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = run_probe(acknowledged=args.i_understand_this_kills_a_test_tree)
    except ProbeError as error:
        print(json.dumps(failure_receipt(error.code), sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0
