"""Native Linux qualification for the brokered operation recovery boundary.

This harness is intentionally a small, fixed-purpose orchestrator.  It does
not provide a general command runner, does not install software, and does not
run product code as root.  The only root work is disposable identity/path
provisioning, launching one of the fixed non-root roles, and exact owned
cleanup.  The qualification is refused unless the caller is the exact
GitHub-hosted Ubuntu 24.04 context used by the workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # These modules exist only on the native Unix host we qualify.
    import grp
    import pwd
except ImportError:  # pragma: no cover - deliberate non-Linux refusal path.
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path("/usr/bin/python3")
SETPRIV = Path("/usr/bin/setpriv")
USERADD = Path("/usr/sbin/useradd")
USERDEL = Path("/usr/sbin/userdel")
GROUPADD = Path("/usr/sbin/groupadd")
GROUPDEL = Path("/usr/sbin/groupdel")
CLI = ROOT / "scripts" / "brokered_operator_demo.py"

SERVICE_UID = 1200
WORKLOAD_UID = 1201
PEER_UID = 1202
IPC_GID = 1301
SERVICE_NAME = "eggcracker_qual_service"
WORKLOAD_NAME = "eggcracker_qual_workload"
PEER_NAME = "eggcracker_qual_peer"
IPC_GROUP_NAME = "eggcracker_qual_ipc"
QUALIFICATION_WORKFLOW = "brokered recovery native qualification"
QUALIFICATION_EVENT = "pull_request"
QUALIFICATION_BRANCH = "codex/eggcracker-recovery-native-20261027-439"
IDENTITY_DESCRIPTOR_SCHEMA = "lumi-eggcracker.native-recovery-identity.v1"
MAX_DESCRIPTOR_BYTES = 64 * 1024
FIXED_QUALIFICATION_UIDS = frozenset((SERVICE_UID, WORKLOAD_UID, PEER_UID))

SOCKET_DIRECTORY_MODE = 0o710
SOCKET_MODE = 0o660
STATE_DIRECTORY_MODE = 0o700
STATE_FILE_MODE = 0o600
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_EVENTS = 2 + (64 * (1 + (2 * 4) + 1))
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_CHILD_OUTPUT = 16 * 1024
MAX_PROC_STATUS_BYTES = 64 * 1024
CHILD_TIMEOUT_SECONDS = 10.0
READY_TIMEOUT_SECONDS = 10.0
OPERATION_IDS = {
    "lost_output": "native-a-lost-output",
    "applied": "native-a-applied",
    "rejected": "native-b-rejected",
    "unknown": "native-a-unknown",
}

ACCEPTED_438_HASHES = {
    "src/lumi_eggcracker/brokered/operator.py": "d770da780fbb061598f87348a091eeb9bf441d80bb381f8315ad2913f6285647",
    "src/lumi_eggcracker/brokered/linux_ipc.py": "adb991834fd79506ddcb6a784f51f746c330c557013e09958552370a9e8bb2b9",
    "scripts/brokered_operator_demo.py": "6b7c8b0fb1ad083f3059ecbd4e1d4cd0bed073845c99ce3d538ec34e4a6e5fe4",
    "tests/test_brokered_operator.py": "2c4feacdfc873a10f6656b599d9adbb7b9b95dfdba85ebe2f663c4868e32187c",
    "tests/test_brokered_linux_ipc.py": "35240da865c6f1029162904c04607261f23b7524b183484773f48dfb43ef5245",
    "docs/BROKERED_OPERATOR.md": "532c45fd0e7c3224bd0927548737772c0db89a7ee7baab3aead5c938d45dc5b0",
}
QUALIFICATION_PATHS = tuple(ACCEPTED_438_HASHES) + (
    "scripts/qualify_brokered_recovery.py",
    ".github/workflows/brokered-recovery-qualification.yml",
)

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


class QualificationIssue(RuntimeError):
    """Base class with a sanitized, stable reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Inconclusive(QualificationIssue):
    """A host primitive, restriction, or cleanup condition is unavailable."""


class AssertionFailure(QualificationIssue):
    """A product or evidence assertion did not match the qualification."""


@dataclass
class OwnedPath:
    label: str
    path: Path
    kind: str
    identity: tuple[int, int]
    uid: int
    gid: int
    mode: int


@dataclass
class ProvisionedIdentity:
    name: str
    uid: int
    created: bool = False


@dataclass
class ChildRecord:
    label: str
    uid: int
    gid: int
    process: subprocess.Popen[bytes]
    identity_observed: bool = False


@dataclass
class RunTracker:
    children: list[ChildRecord] = field(default_factory=list)
    command_counts: Counter[str] = field(default_factory=Counter)
    child_identity_observations: int = 0
    group_created: bool = False

    def count(self, name: str) -> None:
        self.command_counts[name] += 1

    def add(self, record: ChildRecord) -> None:
        self.children.append(record)
        self.count(record.label)


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _utc_timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _invocation_identity() -> dict[str, str | dict[str, str]]:
    return {
        "interpreter": "/usr/bin/python3 -I -S",
        "entrypoint": "scripts/qualify_brokered_recovery.py",
        "mode": "orchestrator",
        "result_target": "RUNNER_TEMP/brokered-recovery-native-qualification/result.json",
        "workflow": {
            "name": QUALIFICATION_WORKFLOW,
            "event": QUALIFICATION_EVENT,
            "branch": QUALIFICATION_BRANCH,
        },
    }


def _raise_inconclusive(code: str) -> None:
    raise Inconclusive(code)


def _raise_failure(code: str) -> None:
    raise AssertionFailure(code)


def _lstat(path: Path, code: str = "PATH_IDENTITY_UNAVAILABLE") -> os.stat_result:
    try:
        return path.lstat()
    except OSError:
        _raise_inconclusive(code)
    raise AssertionError("unreachable")


def _assert_directory(path: Path, code: str) -> os.stat_result:
    metadata = _lstat(path, code)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _raise_inconclusive(code)
    return metadata


def _parse_os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        raw = Path("/etc/os-release").read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        _raise_inconclusive("HOST_IDENTITY_UNAVAILABLE")
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z0-9_]+", key):
            continue
        result[key] = value.strip().strip('"')
    return result


def _host_gate() -> None:
    if sys.platform != "linux" or os.name != "posix" or not hasattr(os, "geteuid"):
        _raise_inconclusive("NATIVE_LINUX_REQUIRED")
    if os.geteuid() != 0 or os.getuid() != 0:
        _raise_inconclusive("ROOT_ORCHESTRATOR_REQUIRED")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        _raise_inconclusive("GITHUB_HOSTED_REQUIRED")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        _raise_inconclusive("GITHUB_ACTIONS_REQUIRED")
    if os.environ.get("GITHUB_REPOSITORY") != "noqt/Lumi-Eggcracker":
        _raise_inconclusive("PUBLIC_REPOSITORY_REQUIRED")
    if os.environ.get("GITHUB_SERVER_URL") != "https://github.com":
        _raise_inconclusive("GITHUB_SERVER_REQUIRED")
    if os.environ.get("GITHUB_EVENT_NAME") != QUALIFICATION_EVENT:
        _raise_inconclusive("PULL_REQUEST_REQUIRED")
    if os.environ.get("GITHUB_BASE_REF") != "main":
        _raise_inconclusive("MAIN_BASE_REQUIRED")
    if os.environ.get("GITHUB_HEAD_REF") != QUALIFICATION_BRANCH:
        _raise_inconclusive("QUALIFICATION_BRANCH_REQUIRED")
    if os.environ.get("GITHUB_WORKFLOW") != QUALIFICATION_WORKFLOW:
        _raise_inconclusive("QUALIFICATION_WORKFLOW_REQUIRED")
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") or os.environ.get(
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
    ):
        _raise_inconclusive("ID_TOKEN_CONTEXT_FORBIDDEN")
    os_release = _parse_os_release()
    if os_release.get("ID") != "ubuntu" or os_release.get("VERSION_ID") != "24.04":
        _raise_inconclusive("UBUNTU_2404_REQUIRED")
    if not hasattr(socket, "SOCK_SEQPACKET") or not hasattr(socket, "SO_PEERCRED"):
        _raise_inconclusive("LINUX_IPC_PRIMITIVE_REQUIRED")
    if not Path("/proc").is_dir():
        _raise_inconclusive("PROC_IDENTITY_REQUIRED")
    try:
        configured_python = PYTHON.resolve(strict=True)
        invoked_python = Path(sys.executable).resolve(strict=True)
    except (OSError, RuntimeError):
        _raise_inconclusive("SYSTEM_PYTHON_REQUIRED")
    if invoked_python != configured_python:
        _raise_inconclusive("SYSTEM_PYTHON_REQUIRED")
    for tool in (PYTHON, SETPRIV, USERADD, USERDEL, GROUPADD, GROUPDEL):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            _raise_inconclusive("REQUIRED_HOST_COMMAND_MISSING")
    if not CLI.is_file() or CLI.is_symlink():
        _raise_inconclusive("CLIENT_CLI_UNAVAILABLE")


def _validate_result_target(raw_path: str) -> tuple[Path, Path, Path]:
    path = Path(raw_path)
    if not path.is_absolute():
        _raise_inconclusive("RESULT_PATH_MUST_BE_ABSOLUTE")
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        _raise_inconclusive("RUNNER_TEMP_REQUIRED")
    runner_temp = Path(runner_temp_raw)
    try:
        runner_temp_resolved = runner_temp.resolve(strict=True)
        parent_resolved = path.parent.resolve(strict=True)
    except OSError:
        _raise_inconclusive("RUNNER_TEMP_UNAVAILABLE")
    _assert_directory(runner_temp_resolved, "RUNNER_TEMP_INVALID")
    _assert_directory(parent_resolved, "RESULT_PARENT_INVALID")
    if parent_resolved.parent != runner_temp_resolved:
        _raise_inconclusive("RESULT_PARENT_NOT_FRESH_RUNNER_TEMP_CHILD")
    if path.exists() or path.is_symlink():
        _raise_inconclusive("RESULT_PATH_COLLISION")
    try:
        entries = tuple(parent_resolved.iterdir())
    except OSError:
        _raise_inconclusive("RESULT_PARENT_UNREADABLE")
    if entries:
        _raise_inconclusive("RESULT_PARENT_NOT_FRESH")
    # The workflow-created child remains owned by the runner for artifact read;
    # grant only traversal to non-owner roles, never read/list access.
    try:
        os.chmod(parent_resolved, 0o701)
    except OSError:
        _raise_inconclusive("RESULT_PARENT_PERMISSION_UNAVAILABLE")
    cursor = parent_resolved
    while cursor != cursor.parent:
        metadata = _lstat(cursor, "RUNNER_TEMP_PATH_UNAVAILABLE")
        if not stat.S_ISDIR(metadata.st_mode):
            _raise_inconclusive("RUNNER_TEMP_PATH_INVALID")
        if cursor == runner_temp_resolved:
            break
        cursor = cursor.parent
    return path, runner_temp_resolved, parent_resolved


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _raise_inconclusive("IDENTITY_DESCRIPTOR_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> Any:
    _raise_inconclusive("IDENTITY_DESCRIPTOR_JSON_INVALID")


def _validate_identity_descriptor(
    raw_path: str,
    result_parent: Path,
    runner_temp: Path,
) -> dict[str, Any]:
    path = Path(raw_path)
    if not path.is_absolute():
        _raise_inconclusive("IDENTITY_DESCRIPTOR_PATH_INVALID")
    try:
        raw_parent_metadata = path.parent.lstat()
        descriptor_parent = path.parent.resolve(strict=True)
        descriptor_resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_PATH_UNAVAILABLE")
    if stat.S_ISLNK(raw_parent_metadata.st_mode):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_DIRECTORY_INVALID")
    if descriptor_parent.parent != runner_temp or descriptor_parent == result_parent:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_DIRECTORY_INVALID")
    if descriptor_resolved.parent != descriptor_parent:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_PATH_INVALID")
    runner_metadata = _lstat(runner_temp, "RUNNER_TEMP_UNAVAILABLE")
    checkout_metadata = _lstat(ROOT, "CHECKOUT_UNAVAILABLE")
    parent_metadata = _lstat(descriptor_parent, "IDENTITY_DESCRIPTOR_DIRECTORY_UNAVAILABLE")
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or runner_metadata.st_uid == 0
        or runner_metadata.st_uid in FIXED_QUALIFICATION_UIDS
        or checkout_metadata.st_uid != runner_metadata.st_uid
        or parent_metadata.st_uid != runner_metadata.st_uid
    ):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_OWNER_INVALID")
    try:
        entries = tuple(descriptor_parent.iterdir())
    except OSError:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_DIRECTORY_UNREADABLE")
    if len(entries) != 1 or entries[0].name != path.name:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_DIRECTORY_NOT_FRESH")
    try:
        descriptor_lstat = path.lstat()
    except FileNotFoundError:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_UNAVAILABLE")
    except OSError:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_UNAVAILABLE")
    if (
        stat.S_ISLNK(descriptor_lstat.st_mode)
        or descriptor_lstat.st_uid != runner_metadata.st_uid
        or stat.S_IMODE(descriptor_lstat.st_mode) != 0o600
    ):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_OWNER_INVALID")
    try:
        raw, metadata = _read_regular(
            path,
            MAX_DESCRIPTOR_BYTES,
            "IDENTITY_DESCRIPTOR_INVALID",
            missing_code="IDENTITY_DESCRIPTOR_UNAVAILABLE",
        )
    except AssertionFailure:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_INVALID")
    if (
        metadata.st_uid != runner_metadata.st_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_OWNER_INVALID")
    try:
        decoded = raw.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_JSON_INVALID")
    except json.JSONDecodeError:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_JSON_INVALID")
    if not isinstance(value, dict) or set(value) != {"schema_version", "commit", "tree", "paths"}:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_SHAPE_INVALID")
    if value.get("schema_version") != IDENTITY_DESCRIPTOR_SCHEMA:
        _raise_inconclusive("IDENTITY_DESCRIPTOR_SCHEMA_INVALID")
    commit = value.get("commit")
    tree = value.get("tree")
    paths = value.get("paths")
    if not isinstance(commit, str) or not _HEX40.fullmatch(commit):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_COMMIT_INVALID")
    if not isinstance(tree, str) or not _HEX40.fullmatch(tree):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_TREE_INVALID")
    if not isinstance(paths, dict) or len(paths) != len(QUALIFICATION_PATHS) or set(paths) != set(QUALIFICATION_PATHS):
        _raise_inconclusive("IDENTITY_DESCRIPTOR_PATHS_INVALID")
    for relative in QUALIFICATION_PATHS:
        digest = paths.get(relative)
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            _raise_inconclusive("IDENTITY_DESCRIPTOR_HASH_INVALID")
    return {"commit": commit, "tree": tree, "paths": dict(paths)}


def _read_regular(
    path: Path,
    maximum: int,
    code: str,
    *,
    missing_code: str | None = None,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            _raise_failure(code)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                _raise_failure(code)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or total != after.st_size
        ):
            _raise_failure(code)
        return b"".join(chunks), after
    except FileNotFoundError:
        if missing_code is not None:
            _raise_inconclusive(missing_code)
        _raise_failure(code)
    except OSError:
        _raise_inconclusive(code)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    raise AssertionError("unreachable")


def _file_hash(relative: str) -> str:
    path = ROOT / relative
    raw, metadata = _read_regular(path, MAX_FILE_BYTES, "SOURCE_FILE_UNAVAILABLE")
    if metadata.st_size != len(raw):
        _raise_failure("SOURCE_FILE_SIZE_DRIFT")
    return hashlib.sha256(raw).hexdigest()


def _assert_checkout_permissions() -> None:
    runner_temp_raw = os.environ.get("RUNNER_TEMP")
    if not runner_temp_raw:
        _raise_inconclusive("RUNNER_TEMP_REQUIRED")
    try:
        runner_temp = Path(runner_temp_raw).resolve(strict=True)
        workspace_boundary = Path(
            os.path.commonpath((os.fspath(ROOT), os.fspath(runner_temp)))
        )
    except (OSError, RuntimeError, ValueError):
        _raise_inconclusive("RUNNER_TEMP_UNAVAILABLE")
    if workspace_boundary == workspace_boundary.parent:
        _raise_inconclusive("CHECKOUT_WORKSPACE_BOUNDARY_INVALID")
    checked_directories: set[Path] = set()
    for relative in QUALIFICATION_PATHS:
        path = ROOT / relative
        metadata = _lstat(path, "SOURCE_FILE_UNAVAILABLE")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid in FIXED_QUALIFICATION_UIDS
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            _raise_inconclusive("CHECKOUT_FILE_PERMISSIONS_INVALID")
        cursor = path.parent
        while True:
            if cursor in checked_directories:
                break
            directory_metadata = _lstat(cursor, "CHECKOUT_DIRECTORY_UNAVAILABLE")
            if (
                stat.S_ISLNK(directory_metadata.st_mode)
                or not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid in FIXED_QUALIFICATION_UIDS
                or stat.S_IMODE(directory_metadata.st_mode) & 0o022
            ):
                _raise_inconclusive("CHECKOUT_DIRECTORY_PERMISSIONS_INVALID")
            checked_directories.add(cursor)
            if cursor == workspace_boundary:
                break
            if (
                workspace_boundary not in cursor.parents
                and cursor != workspace_boundary
            ):
                _raise_inconclusive("CHECKOUT_DIRECTORY_BOUNDARY_INVALID")
            cursor = cursor.parent


def _source_hashes() -> dict[str, str]:
    _assert_checkout_permissions()
    return {relative: _file_hash(relative) for relative in QUALIFICATION_PATHS}


def _validate_source_preimages(descriptor_paths: dict[str, str]) -> dict[str, str]:
    values = _source_hashes()
    if values != descriptor_paths:
        _raise_failure("SOURCE_DESCRIPTOR_DRIFT")
    for relative, expected in ACCEPTED_438_HASHES.items():
        if values.get(relative) != expected:
            _raise_failure("ACCEPTED_438_SOURCE_DRIFT")
    return values


def _account_by_uid(uid: int) -> Any | None:
    if pwd is None:
        _raise_inconclusive("POSIX_IDENTITY_MODULE_REQUIRED")
    try:
        return pwd.getpwuid(uid)
    except KeyError:
        return None


def _account_by_name(name: str) -> Any | None:
    if pwd is None:
        _raise_inconclusive("POSIX_IDENTITY_MODULE_REQUIRED")
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def _group_by_gid(gid: int) -> Any | None:
    if grp is None:
        _raise_inconclusive("POSIX_IDENTITY_MODULE_REQUIRED")
    try:
        return grp.getgrgid(gid)
    except KeyError:
        return None


def _group_by_name(name: str) -> Any | None:
    if grp is None:
        _raise_inconclusive("POSIX_IDENTITY_MODULE_REQUIRED")
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def _check_identity_collisions() -> None:
    if len({SERVICE_UID, WORKLOAD_UID, PEER_UID}) != 3:
        _raise_inconclusive("IDENTITY_CONFIGURATION_INVALID")
    if any(uid <= 0 for uid in (SERVICE_UID, WORKLOAD_UID, PEER_UID)) or IPC_GID <= 0:
        _raise_inconclusive("IDENTITY_CONFIGURATION_INVALID")
    names = (SERVICE_NAME, WORKLOAD_NAME, PEER_NAME)
    if len(set(names)) != len(names) or IPC_GROUP_NAME in names:
        _raise_inconclusive("IDENTITY_CONFIGURATION_INVALID")
    for uid, name in zip((SERVICE_UID, WORKLOAD_UID, PEER_UID), names):
        if _account_by_uid(uid) is not None or _account_by_name(name) is not None:
            _raise_inconclusive("IDENTITY_COLLISION")
    if _group_by_gid(IPC_GID) is not None or _group_by_name(IPC_GROUP_NAME) is not None:
        _raise_inconclusive("IDENTITY_COLLISION")
    for uid in (SERVICE_UID, WORKLOAD_UID, PEER_UID):
        if _uid_pids(uid):
            _raise_inconclusive("IDENTITY_PROCESS_COLLISION")
    if _gid_pids(IPC_GID):
        _raise_inconclusive("IDENTITY_PROCESS_COLLISION")


def _fixed_command(
    executable: Path,
    arguments: list[str],
    *,
    timeout: float = 10.0,
) -> int:
    try:
        completed = subprocess.run(
            [os.fspath(executable), *arguments],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        _raise_inconclusive("IDENTITY_PROVISIONING_UNAVAILABLE")
    return completed.returncode


def _provision_identities(tracker: RunTracker, created: list[ProvisionedIdentity]) -> None:
    _check_identity_collisions()
    tracker.count("groupadd")
    if _fixed_command(GROUPADD, ["--gid", str(IPC_GID), IPC_GROUP_NAME]) != 0:
        _raise_inconclusive("IPC_GROUP_PROVISION_FAILED")
    tracker.group_created = True
    group = _group_by_name(IPC_GROUP_NAME)
    if group is None or group.gr_gid != IPC_GID or group.gr_name != IPC_GROUP_NAME:
        _raise_failure("IPC_GROUP_IDENTITY_MISMATCH")
    for uid, name in (
        (SERVICE_UID, SERVICE_NAME),
        (WORKLOAD_UID, WORKLOAD_NAME),
        (PEER_UID, PEER_NAME),
    ):
        tracker.count("useradd")
        code = _fixed_command(
            USERADD,
            [
                "--uid",
                str(uid),
                "--gid",
                str(IPC_GID),
                "--no-user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                name,
            ],
        )
        if code != 0:
            _raise_inconclusive("USER_PROVISION_FAILED")
        created.append(ProvisionedIdentity(name, uid, True))
        account = _account_by_name(name)
        if (
            account is None
            or account.pw_uid != uid
            or account.pw_gid != IPC_GID
            or account.pw_name != name
            or account.pw_dir != "/nonexistent"
            or account.pw_shell != "/usr/sbin/nologin"
        ):
            _raise_failure("USER_IDENTITY_MISMATCH")


def _prepare_owned_directory(
    path: Path,
    label: str,
    *,
    uid: int,
    gid: int,
    mode: int,
    owned: list[OwnedPath],
) -> None:
    if path.exists() or path.is_symlink():
        _raise_inconclusive("TASK_PATH_COLLISION")
    try:
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    except OSError:
        _raise_inconclusive("TASK_DIRECTORY_CREATE_FAILED")
    owned.append(_capture_owned(path, label, "directory", uid, gid, mode))


def _capture_owned(
    path: Path,
    label: str,
    kind: str,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> OwnedPath:
    metadata = _lstat(path, "TASK_OBJECT_UNAVAILABLE")
    if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        _raise_inconclusive("TASK_OBJECT_IDENTITY_INVALID")
    if kind == "directory" and not stat.S_ISDIR(metadata.st_mode):
        _raise_inconclusive("TASK_OBJECT_IDENTITY_INVALID")
    if kind == "file" and (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1):
        _raise_inconclusive("TASK_OBJECT_IDENTITY_INVALID")
    if kind == "socket" and not stat.S_ISSOCK(metadata.st_mode):
        _raise_inconclusive("TASK_OBJECT_IDENTITY_INVALID")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        _raise_inconclusive("TASK_OBJECT_PERMISSION_INVALID")
    return OwnedPath(
        label,
        path,
        kind,
        (metadata.st_dev, metadata.st_ino),
        expected_uid,
        expected_gid,
        expected_mode,
    )


def _track_state_and_socket(
    state: Path,
    socket_path: Path,
    socket_parent: Path,
    owned: list[OwnedPath],
) -> None:
    state_metadata = _lstat(state, "SERVICE_STATE_UNAVAILABLE")
    if (
        stat.S_ISLNK(state_metadata.st_mode)
        or not stat.S_ISDIR(state_metadata.st_mode)
        or state_metadata.st_uid != SERVICE_UID
        or state_metadata.st_gid != IPC_GID
        or stat.S_IMODE(state_metadata.st_mode) != STATE_DIRECTORY_MODE
    ):
        _raise_failure("SERVICE_STATE_NOT_PRIVATE")
    if not any(item.path == state for item in owned):
        owned.append(
            OwnedPath(
                "state",
                state,
                "directory",
                (state_metadata.st_dev, state_metadata.st_ino),
                SERVICE_UID,
                IPC_GID,
                STATE_DIRECTORY_MODE,
            )
        )
    for name in ("operator.anchor.json", "operator.journal", "operator.lock", "operator.witness.json"):
        path = state / name
        metadata = _lstat(path, "SERVICE_STATE_FILE_UNAVAILABLE")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != SERVICE_UID
            or metadata.st_gid != IPC_GID
            or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
        ):
            _raise_failure("SERVICE_STATE_FILE_NOT_PRIVATE")
        if not any(item.path == path for item in owned):
            owned.append(
                OwnedPath(
                    f"state_{name}",
                    path,
                    "file",
                    (metadata.st_dev, metadata.st_ino),
                    SERVICE_UID,
                    IPC_GID,
                    STATE_FILE_MODE,
                )
            )
    socket_metadata = _lstat(socket_path, "BROKER_SOCKET_UNAVAILABLE")
    if (
        stat.S_ISLNK(socket_metadata.st_mode)
        or not stat.S_ISSOCK(socket_metadata.st_mode)
        or socket_metadata.st_uid != SERVICE_UID
        or socket_metadata.st_gid != IPC_GID
        or stat.S_IMODE(socket_metadata.st_mode) != SOCKET_MODE
    ):
        _raise_failure("BROKER_SOCKET_IDENTITY_INVALID")
    parent_metadata = _lstat(socket_parent, "BROKER_SOCKET_PARENT_UNAVAILABLE")
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != SERVICE_UID
        or parent_metadata.st_gid != IPC_GID
        or stat.S_IMODE(parent_metadata.st_mode) != SOCKET_DIRECTORY_MODE
    ):
        _raise_failure("BROKER_SOCKET_PARENT_INVALID")
    if not any(item.path == socket_path for item in owned):
        owned.append(
            OwnedPath(
                "broker_socket",
                socket_path,
                "socket",
                (socket_metadata.st_dev, socket_metadata.st_ino),
                SERVICE_UID,
                IPC_GID,
                SOCKET_MODE,
            )
        )


def _proc_status(pid: int) -> str | None:
    status_path = Path("/proc") / str(pid) / "status"
    try:
        with status_path.open("rb") as stream:
            raw = stream.read(MAX_PROC_STATUS_BYTES + 1)
    except (FileNotFoundError, ProcessLookupError):
        raise
    except OSError:
        _raise_inconclusive("PROC_STATUS_UNAVAILABLE")
    if len(raw) > MAX_PROC_STATUS_BYTES:
        _raise_inconclusive("PROC_STATUS_MALFORMED")
    try:
        return raw.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        _raise_inconclusive("PROC_STATUS_MALFORMED")


def _proc_credentials(
    pid: int,
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    raw = _proc_status(pid)
    uid_values: tuple[int, ...] | None = None
    gid_values: tuple[int, ...] | None = None
    supplementary: tuple[int, ...] | None = None
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if uid_values is not None or len(fields) != 5:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
            try:
                uid_values = tuple(int(value) for value in fields[1:5])
            except ValueError:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
        elif line.startswith("Gid:"):
            fields = line.split()
            if gid_values is not None or len(fields) != 5:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
            try:
                gid_values = tuple(int(value) for value in fields[1:5])
            except ValueError:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
        elif line.startswith("Groups:"):
            if supplementary is not None:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
            fields = line.split()
            try:
                supplementary = tuple(int(value) for value in fields[1:])
            except ValueError:
                _raise_inconclusive("PROC_STATUS_MALFORMED")
    if uid_values is None or gid_values is None or supplementary is None:
        _raise_inconclusive("PROC_STATUS_MALFORMED")
    return uid_values, gid_values, supplementary


def _proc_identity(pid: int) -> tuple[int, int] | None:
    uid_values, gid_values, _ = _proc_credentials(pid)
    return uid_values[1], gid_values[1]


def _proc_uid_slots(pid: int) -> tuple[int, ...]:
    uid_values, _, _ = _proc_credentials(pid)
    return uid_values


def _proc_group_ids(pid: int) -> tuple[int, ...] | None:
    _, gid_values, supplementary = _proc_credentials(pid)
    return gid_values + supplementary


def _observe_child_identity(record: ChildRecord, tracker: RunTracker) -> None:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            observed = _proc_identity(record.process.pid)
        except (FileNotFoundError, ProcessLookupError):
            if record.process.poll() is not None:
                # A tracked fixed launcher may exit before /proc can be read.
                return
            _raise_inconclusive("CHILD_IDENTITY_UNAVAILABLE")
        if observed is not None:
            if observed == (record.uid, record.gid):
                record.identity_observed = True
                tracker.child_identity_observations += 1
                return
            # The fixed setpriv launcher is briefly root between fork and its
            # privilege transition.  Do not mistake that bounded launcher
            # window for root product execution; wait for the exec'd role.
            if record.process.poll() is None:
                time.sleep(0.01)
                continue
            return
        if record.process.poll() is not None:
            # setpriv is the fixed, non-shell launcher.  A very short-lived
            # command can finish before /proc can be inspected; its exact
            # launcher still prevents root product execution.
            return
        time.sleep(0.01)
    if record.process.poll() is None:
        _raise_inconclusive("CHILD_IDENTITY_UNOBSERVABLE")


def _role_environment() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}


def _spawn_fixed(
    label: str,
    uid: int,
    arguments: list[str],
    tracker: RunTracker,
    *,
    stdout: int,
    stderr: int,
) -> ChildRecord:
    if uid not in (SERVICE_UID, WORKLOAD_UID, PEER_UID):
        _raise_inconclusive("CHILD_ROLE_INVALID")
    try:
        process = subprocess.Popen(
            [
                os.fspath(SETPRIV),
                "--reuid",
                str(uid),
                "--regid",
                str(IPC_GID),
                "--clear-groups",
                os.fspath(PYTHON),
                "-I",
                "-S",
                *arguments,
            ],
            cwd=ROOT,
            env=_role_environment(),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
        )
    except OSError:
        _raise_inconclusive("FIXED_IDENTITY_LAUNCH_UNAVAILABLE")
    record = ChildRecord(label, uid, IPC_GID, process)
    tracker.add(record)
    tracker.count("setpriv")
    _observe_child_identity(record, tracker)
    return record


def _finish_child(record: ChildRecord, *, expected_zero: bool = True) -> tuple[bytes, bytes]:
    try:
        stdout, stderr = record.process.communicate(timeout=CHILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _raise_inconclusive("CHILD_TIMEOUT")
    stdout = stdout or b""
    stderr = stderr or b""
    if len(stdout) > MAX_CHILD_OUTPUT or len(stderr) > MAX_CHILD_OUTPUT:
        _raise_failure("CHILD_OUTPUT_BOUND_EXCEEDED")
    if expected_zero and record.process.returncode != 0:
        _raise_failure("FIXED_ROLE_FAILED")
    return stdout, stderr


def _start_service(
    state: Path,
    socket_path: Path,
    requests: int,
    tracker: RunTracker,
) -> ChildRecord:
    if not 1 <= requests <= 16:
        _raise_inconclusive("SERVICE_REQUEST_COUNT_INVALID")
    record = _spawn_fixed(
        "service_child",
        SERVICE_UID,
        [
            os.fspath(Path(__file__).resolve()),
            "--service-child",
            "--state-dir",
            os.fspath(state),
            "--socket",
            os.fspath(socket_path),
            "--requests",
            str(requests),
        ],
        tracker,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if record.process.stdout is None:
        _raise_inconclusive("SERVICE_READY_CHANNEL_UNAVAILABLE")
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    ready = b""
    selector = selectors.DefaultSelector()
    selector.register(record.process.stdout, selectors.EVENT_READ)
    try:
        while time.monotonic() < deadline:
            events = selector.select(max(0.0, deadline - time.monotonic()))
            if events:
                ready = record.process.stdout.readline()
                break
            if record.process.poll() is not None:
                break
    finally:
        selector.close()
    if ready != b"READY\n":
        if record.process.returncode == 70:
            _raise_inconclusive("SERVICE_IDENTITY_REQUIRED")
        _raise_failure("SERVICE_READY_FAILED")
    return record


def _finish_service(record: ChildRecord) -> None:
    stdout, _ = _finish_child(record)
    if stdout:
        _raise_failure("SERVICE_OUTPUT_NOT_FIXED")


def _run_cli(
    uid: int,
    mode: str,
    arguments: list[str],
    tracker: RunTracker,
    *,
    discard_output: bool = False,
) -> tuple[bytes, bytes]:
    if mode not in {"submit", "dispatch", "result", "recover", "stop", "snapshot"}:
        _raise_inconclusive("CLI_MODE_INVALID")
    fixed_arguments = [
        os.fspath(CLI),
        "--linux-ipc",
        mode,
        *arguments,
    ]
    if discard_output:
        stdout = subprocess.DEVNULL
        stderr = subprocess.DEVNULL
    else:
        stdout = subprocess.PIPE
        stderr = subprocess.PIPE
    record = _spawn_fixed(
        "operator_demo_client" if uid != SERVICE_UID else "operator_demo_service",
        uid,
        fixed_arguments,
        tracker,
        stdout=stdout,
        stderr=stderr,
    )
    out, err = _finish_child(record)
    return out, err


def _json_lines(raw: bytes) -> list[dict[str, Any]]:
    if not raw or len(raw) > MAX_CHILD_OUTPUT:
        _raise_failure("CLI_JSON_OUTPUT_INVALID")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _raise_failure("CLI_JSON_OUTPUT_INVALID")
    result: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            _raise_failure("CLI_JSON_OUTPUT_INVALID")
        if not isinstance(value, dict):
            _raise_failure("CLI_JSON_OUTPUT_INVALID")
        result.append(value)
    if not result:
        _raise_failure("CLI_JSON_OUTPUT_INVALID")
    return result


def _assert_no_sensitive_keys(value: Any) -> None:
    forbidden = {
        "capability",
        "dataset",
        "dataset_id",
        "dataset_sha256",
        "operation_id",
        "path",
        "payload",
        "request",
        "request_b64",
        "run_id",
    }
    if isinstance(value, dict):
        if forbidden.intersection(value):
            _raise_failure("RESPONSE_DISCLOSURE")
        for item in value.values():
            _assert_no_sensitive_keys(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_sensitive_keys(item)


def _receipt_from_output(raw: bytes, wrapper: str) -> dict[str, Any]:
    lines = _json_lines(raw)
    if len(lines) != 1 or set(lines[0]) != {wrapper}:
        _raise_failure("CLI_RESPONSE_ENVELOPE_INVALID")
    value = lines[0][wrapper]
    if not isinstance(value, dict):
        _raise_failure("CLI_RESPONSE_ENVELOPE_INVALID")
    _assert_no_sensitive_keys(value)
    return value


def _queue_id(receipt: dict[str, Any], phase: str, outcome: str, code: str) -> str:
    if (
        set(receipt) != {"receipt", "schema_version"}
        or receipt.get("schema_version") != "lumi-eggcracker.brokered-ipc.v1"
        or not isinstance(receipt.get("receipt"), dict)
    ):
        _raise_failure("RECEIPT_ENVELOPE_INVALID")
    value = receipt["receipt"]
    _assert_no_sensitive_keys(value)
    if (
        value.get("phase") != phase
        or value.get("outcome") != outcome
        or value.get("code") != code
        or value.get("effect_applied") is not False
        or not isinstance(value.get("queue_id"), str)
        or not _HEX32.fullmatch(value["queue_id"])
        or "run_id" in value
    ):
        _raise_failure("RECEIPT_VALUE_INVALID")
    return value["queue_id"]


def _assert_dispatch(raw: bytes, *, rejected: bool) -> dict[str, Any]:
    value = _receipt_from_output(raw, "dispatch")
    if set(value) != {"receipt", "schema_version"}:
        _raise_failure("DISPATCH_ENVELOPE_INVALID")
    receipt = value["receipt"]
    if not isinstance(receipt, dict):
        _raise_failure("DISPATCH_RECEIPT_INVALID")
    inner = receipt
    if set(inner) - {"code", "effect_applied", "generation", "outcome", "phase", "queue_id"}:
        _raise_failure("DISPATCH_DISCLOSURE")
    effect_applied = inner.get("effect_applied")
    if (
        inner.get("phase") != "dispatch"
        or not isinstance(inner.get("queue_id"), str)
        or not _HEX32.fullmatch(inner["queue_id"])
        or not isinstance(effect_applied, bool)
        or effect_applied != (not rejected)
        or inner.get("outcome") != ("DENIED" if rejected else "APPLIED")
        or inner.get("code") != ("STALE_GENERATION" if rejected else "EFFECT_APPLIED")
    ):
        _raise_failure("DISPATCH_RECEIPT_INVALID")
    return {"effect_applied": bool(inner["effect_applied"]), "queue_id_shape": True, "outcome": inner["outcome"], "code": inner["code"]}


def _assert_recovery(raw: bytes, expected_status: str | None) -> tuple[dict[str, Any], str | None]:
    value = _receipt_from_output(raw, "recovery")
    if set(value) != {"code", "outcome", "phase", "schema_version"} and set(value) != {
        "outcome",
        "phase",
        "queue_id",
        "schema_version",
        "status",
    }:
        _raise_failure("RECOVERY_ENVELOPE_INVALID")
    if value.get("schema_version") != "lumi-eggcracker.brokered-ipc.v1" or value.get("phase") != "recovery":
        _raise_failure("RECOVERY_ENVELOPE_INVALID")
    if "status" in value:
        if (
            set(value) != {"outcome", "phase", "queue_id", "schema_version", "status"}
            or value.get("outcome") != "AVAILABLE"
            or not isinstance(value.get("queue_id"), str)
            or not _HEX32.fullmatch(value["queue_id"])
            or value.get("status") != expected_status
        ):
            _raise_failure("RECOVERY_VALUE_INVALID")
        return {"outcome": "AVAILABLE", "status": value["status"], "queue_id_shape": True}, value["queue_id"]
    if (
        set(value) != {"code", "outcome", "phase", "schema_version"}
        or value.get("outcome") != "DENIED"
        or value.get("code") != "NOT_FOUND"
        or expected_status is not None
    ):
        _raise_failure("RECOVERY_NOT_FOUND_INVALID")
    return {"outcome": "DENIED", "status": "NOT_FOUND", "queue_id_shape": False}, None


def _assert_peer_denial(raw: bytes) -> dict[str, Any]:
    value = _receipt_from_output(raw, "recovery")
    if (
        set(value) != {"code", "outcome", "phase", "schema_version"}
        or value.get("schema_version") != "lumi-eggcracker.brokered-ipc.v1"
        or value.get("phase") != "protocol"
        or value.get("outcome") != "DENIED"
        or value.get("code") != "PEER_IDENTITY"
    ):
        _raise_failure("PEER_IDENTITY_NOT_DENIED")
    return {"outcome": "DENIED", "code": "PEER_IDENTITY"}


def _assert_pending_result(raw: bytes, queue_id: str) -> dict[str, Any]:
    value = _receipt_from_output(raw, "result")
    if (
        set(value) != {"code", "outcome", "phase", "queue_id", "schema_version"}
        or value.get("schema_version") != "lumi-eggcracker.brokered-ipc.v1"
        or value.get("phase") != "result"
        or value.get("outcome") != "DENIED"
        or value.get("code") != "NOT_FOUND"
        or value.get("queue_id") != queue_id
    ):
        _raise_failure("PENDING_RESULT_NOT_FOUND_INVALID")
    return {"outcome": "DENIED", "code": "NOT_FOUND", "queue_id_shape": True}


def _effect_snapshot(state: Path, tracker: RunTracker) -> dict[str, int]:
    output, _ = _run_cli(
        SERVICE_UID,
        "snapshot",
        ["--state-dir", os.fspath(state)],
        tracker,
    )
    lines = _json_lines(output)
    if len(lines) != 2 or set(lines[0]) != {"synthetic_world"} or set(lines[1]) != {"verified_process_stop"}:
        _raise_failure("EFFECT_SNAPSHOT_ENVELOPE_INVALID")
    world = lines[0]["synthetic_world"]
    if (
        not isinstance(world, dict)
        or set(world) != {"protected_effects", "unrelated_canary_allocation"}
        or type(world.get("protected_effects")) is not int
        or world["protected_effects"] < 0
        or world.get("unrelated_canary_allocation") != 73
    ):
        _raise_failure("EFFECT_SNAPSHOT_INVALID")
    return {
        "protected_effects": world["protected_effects"],
        "unrelated_canary_allocation": world["unrelated_canary_allocation"],
    }


def _journal_summary(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_JOURNAL_BYTES:
        _raise_failure("JOURNAL_SUMMARY_INVALID")
    lines = raw.splitlines(keepends=True)
    if not lines or any(not line.endswith(b"\n") or line.endswith(b"\r\n") for line in lines):
        _raise_failure("JOURNAL_SUMMARY_INVALID")
    if len(lines) > MAX_JOURNAL_EVENTS:
        _raise_failure("JOURNAL_EVENT_BUDGET_EXCEEDED")
    kinds: Counter[str] = Counter()
    first_seq: int | None = None
    last_seq: int | None = None
    for expected, line in enumerate(lines):
        try:
            value = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            _raise_failure("JOURNAL_SUMMARY_INVALID")
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str) or value.get("seq") != expected:
            _raise_failure("JOURNAL_SUMMARY_INVALID")
        kinds[value["kind"]] += 1
        if first_seq is None:
            first_seq = value["seq"]
        last_seq = value["seq"]
    return {
        "bytes": len(raw),
        "event_count": len(lines),
        "event_budget": {"used": len(lines), "max": MAX_JOURNAL_EVENTS},
        "first_seq": first_seq,
        "last_seq": last_seq,
        "kinds": dict(sorted(kinds.items())),
    }


def _durable_snapshot(state: Path) -> dict[str, Any]:
    files: dict[str, Any] = {}
    for name in ("operator.anchor.json", "operator.journal", "operator.lock", "operator.witness.json"):
        path = state / name
        raw, metadata = _read_regular(path, MAX_JOURNAL_BYTES, "DURABLE_STATE_UNAVAILABLE")
        if (
            metadata.st_uid != SERVICE_UID
            or metadata.st_gid != IPC_GID
            or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
            or metadata.st_nlink != 1
        ):
            _raise_failure("DURABLE_STATE_OWNERSHIP_DRIFT")
        entry: dict[str, Any] = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        if name == "operator.journal":
            entry["summary"] = _journal_summary(raw)
        elif name == "operator.witness.json":
            try:
                witness = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                _raise_failure("WITNESS_SUMMARY_INVALID")
            if not isinstance(witness, dict) or type(witness.get("seq")) is not int:
                _raise_failure("WITNESS_SUMMARY_INVALID")
            entry["summary"] = {"seq": witness["seq"]}
        files[name] = entry
    directory_metadata = _lstat(state, "DURABLE_STATE_UNAVAILABLE")
    if (
        stat.S_ISLNK(directory_metadata.st_mode)
        or not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != SERVICE_UID
        or directory_metadata.st_gid != IPC_GID
        or stat.S_IMODE(directory_metadata.st_mode) != STATE_DIRECTORY_MODE
    ):
        _raise_failure("DURABLE_STATE_DIRECTORY_DRIFT")
    return {
        "directory": {
            "device": directory_metadata.st_dev,
            "inode": directory_metadata.st_ino,
            "mode": stat.S_IMODE(directory_metadata.st_mode),
        },
        "files": files,
    }


def _same_recovery_state(before: dict[str, Any], after: dict[str, Any]) -> None:
    if before != after:
        _raise_failure("RECOVERY_DURABLE_STATE_CHANGED")


def _recovery_call(
    label: str,
    state: Path,
    tracker: RunTracker,
    invoke: Any,
    expected_status: str | None,
) -> dict[str, Any]:
    before_durable = _durable_snapshot(state)
    before_effect = _effect_snapshot(state, tracker)
    raw = invoke()
    after_durable = _durable_snapshot(state)
    after_effect = _effect_snapshot(state, tracker)
    _same_recovery_state(before_durable, after_durable)
    if before_effect != after_effect:
        _raise_failure("RECOVERY_EFFECT_CHANGED")
    response, queue_id = _assert_recovery(raw, expected_status)
    result = {
        "label": label,
        "response": response,
        "durable_unchanged": True,
        "effect_unchanged": True,
    }
    if queue_id is not None:
        result["status"] = response["status"]
    return result


def _remove_owned_path(item: OwnedPath) -> str:
    try:
        metadata = item.path.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unsafe"
    if (
        stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != item.identity
        or metadata.st_uid != item.uid
        or metadata.st_gid != item.gid
        or stat.S_IMODE(metadata.st_mode) != item.mode
    ):
        return "unsafe"
    try:
        if item.kind == "directory":
            if not stat.S_ISDIR(metadata.st_mode):
                return "unsafe"
            if any(item.path.iterdir()):
                return "unsafe"
            item.path.rmdir()
        else:
            if item.kind == "file" and not stat.S_ISREG(metadata.st_mode):
                return "unsafe"
            if item.kind == "socket" and not stat.S_ISSOCK(metadata.st_mode):
                return "unsafe"
            item.path.unlink()
    except OSError:
        return "unsafe"
    return "removed"


def _uid_pids(uid: int) -> list[int]:
    result: list[int] = []
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        _raise_inconclusive("PROC_CLEANUP_UNAVAILABLE")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            uid_values = _proc_uid_slots(pid)
        except (FileNotFoundError, ProcessLookupError):
            # The process disappeared after the bounded /proc listing.
            continue
        if uid in uid_values:
            result.append(int(entry.name))
    return result


def _gid_pids(gid: int) -> list[int]:
    result: list[int] = []
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        _raise_inconclusive("PROC_CLEANUP_UNAVAILABLE")
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            group_ids = _proc_group_ids(pid)
        except (FileNotFoundError, ProcessLookupError):
            # The process disappeared after the bounded /proc listing.
            continue
        if gid in group_ids:
            result.append(int(entry.name))
    return result


def _cleanup_children(tracker: RunTracker) -> list[str]:
    residual: list[str] = []
    for record in reversed(tracker.children):
        if record.process.poll() is not None:
            continue
        try:
            record.process.send_signal(signal.SIGTERM)
            record.process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                record.process.kill()
                record.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                residual.append(record.label)
    return residual


def _cleanup_identities(created: list[ProvisionedIdentity], tracker: RunTracker) -> list[str]:
    residual: list[str] = []
    created_names = {identity.name for identity in created}
    for identity in reversed(created):
        if not identity.created:
            continue
        account = _account_by_name(identity.name)
        if account is None:
            continue
        if account.pw_uid != identity.uid or account.pw_gid != IPC_GID:
            residual.append(identity.name)
            continue
        try:
            pids = [pid for pid in _uid_pids(identity.uid) if pid != os.getpid()]
        except Inconclusive:
            residual.append(identity.name)
            continue
        # Every tracked child has already been reaped.  Any remaining process
        # under the fixed UID is therefore unowned; never signal or delete it.
        if pids:
            residual.append(identity.name)
            continue
        tracker.count("userdel")
        if _fixed_command(USERDEL, [identity.name]) != 0:
            residual.append(identity.name)
            continue
        if _account_by_name(identity.name) is not None or _account_by_uid(identity.uid) is not None:
            residual.append(identity.name)
    for name in (SERVICE_NAME, WORKLOAD_NAME, PEER_NAME):
        if name not in created_names and _account_by_name(name) is not None:
            residual.append(name)
    if tracker.group_created:
        group = _group_by_name(IPC_GROUP_NAME)
        if group is not None:
            if group.gr_gid != IPC_GID or group.gr_name != IPC_GROUP_NAME or group.gr_mem:
                residual.append(IPC_GROUP_NAME)
            else:
                tracker.count("groupdel")
                if _fixed_command(GROUPDEL, [IPC_GROUP_NAME]) != 0 or _group_by_name(IPC_GROUP_NAME) is not None:
                    residual.append(IPC_GROUP_NAME)
    elif _group_by_name(IPC_GROUP_NAME) is not None:
        residual.append(IPC_GROUP_NAME)
    return residual


def _cleanup(owned: list[OwnedPath], created: list[ProvisionedIdentity], tracker: RunTracker) -> dict[str, Any]:
    residual = _cleanup_children(tracker)
    removed = 0
    missing = 0
    unsafe: list[str] = []
    for item in sorted(owned, key=lambda value: len(value.path.parts), reverse=True):
        outcome = _remove_owned_path(item)
        if outcome == "removed":
            removed += 1
        elif outcome == "missing":
            missing += 1
        else:
            unsafe.append(item.label)
    residual.extend(unsafe)
    residual.extend(_cleanup_identities(created, tracker))
    return {
        "safe": not residual,
        "tracked_children": len(tracker.children),
        "child_residuals": sorted(set(residual)),
        "owned_paths_removed": removed,
        "owned_paths_missing": missing,
        "owned_path_refusals": sorted(set(unsafe)),
        "identities_removed": not any(
            item in residual for item in (SERVICE_NAME, WORKLOAD_NAME, PEER_NAME, IPC_GROUP_NAME)
        ),
        "identity_observations": tracker.child_identity_observations,
    }


def _write_result(path: Path, value: dict[str, Any]) -> None:
    encoded = _canonical(value)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.fchmod(descriptor, 0o644)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _raise_inconclusive("RESULT_WRITE_FAILED")
            view = view[written:]
        os.fsync(descriptor)
    except FileExistsError:
        _raise_inconclusive("RESULT_PATH_COLLISION")
    except OSError:
        _raise_inconclusive("RESULT_WRITE_FAILED")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _service_child(arguments: argparse.Namespace) -> int:
    # This check deliberately precedes the product import: Windows and other
    # hosts cannot imitate the native service mode.
    if (
        sys.platform != "linux"
        or not hasattr(os, "geteuid")
        or os.geteuid() != SERVICE_UID
        or os.getuid() != SERVICE_UID
        or os.getegid() != IPC_GID
        or os.getgid() != IPC_GID
        or set(os.getgroups())
    ):
        return 70
    state = Path(arguments.state_dir)
    socket_path = Path(arguments.socket)
    if not state.is_absolute() or not socket_path.is_absolute() or arguments.requests < 1:
        return 70
    sys.path.insert(0, os.fspath(ROOT / "src"))
    try:
        # Importing the service here is intentional: identity is established
        # before any product authority is constructed.
        from lumi_eggcracker.brokered.linux_ipc import BrokeredLinuxService

        service = BrokeredLinuxService.open(
            state,
            socket_path,
            workload_uid=WORKLOAD_UID,
            workload_gid=IPC_GID,
        )
        service.start()
        print("READY", flush=True)
        served = 0
        while served < arguments.requests:
            if service.serve_once():
                served += 1
        service.close()
        return 0
    # The service child must convert every product/import/IPC failure into its
    # one bounded exit code so the parent never receives a raw traceback.
    except Exception:  # noqa: BLE001 - preserve the bounded child failure contract.
        try:
            service.close()  # type: ignore[name-defined]
        except Exception:  # noqa: BLE001, S110 - cleanup errors must not mask child failure.
            # There is no additional result channel in this child; the outer
            # bounded exit code remains the complete failure record.
            pass
        return 71


def _setup_store(
    label: str,
    state: Path,
    socket_path: Path,
    tracker: RunTracker,
    owned: list[OwnedPath],
    *,
    rejected: bool = False,
) -> dict[str, Any]:
    setup: dict[str, Any] = {"label": label, "rejected": rejected}
    rejected_queue: str | None = None
    request_count = 1 if rejected else 3
    service = _start_service(state, socket_path, request_count, tracker)
    try:
        _track_state_and_socket(state, socket_path, socket_path.parent, owned)
        if not rejected:
            _run_cli(
                WORKLOAD_UID,
                "submit",
                [
                    "--socket",
                    os.fspath(socket_path),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--operation-id",
                    OPERATION_IDS["lost_output"],
                ],
                tracker,
                discard_output=True,
            )
            applied_output, _ = _run_cli(
                WORKLOAD_UID,
                "submit",
                [
                    "--socket",
                    os.fspath(socket_path),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--operation-id",
                    OPERATION_IDS["applied"],
                ],
                tracker,
            )
            applied = _receipt_from_output(applied_output, "submission")
            applied_queue = _queue_id(applied, "admission", "QUEUED", "ADMITTED")
            dispatch_output, _ = _run_cli(
                WORKLOAD_UID,
                "dispatch",
                [
                    "--socket",
                    os.fspath(socket_path),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--queue-id",
                    applied_queue,
                ],
                tracker,
            )
            dispatch = _assert_dispatch(dispatch_output, rejected=False)
            setup["lost_output_submit"] = {"stdout_discarded": True, "completed": True}
            setup["applied_dispatch"] = dispatch
        else:
            rejected_output, _ = _run_cli(
                WORKLOAD_UID,
                "submit",
                [
                    "--socket",
                    os.fspath(socket_path),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--operation-id",
                    OPERATION_IDS["rejected"],
                ],
                tracker,
            )
            rejected_receipt = _receipt_from_output(rejected_output, "submission")
            rejected_queue = _queue_id(rejected_receipt, "admission", "QUEUED", "ADMITTED")
            setup["rejected_queue_shape"] = True
    finally:
        _finish_service(service)
    if rejected:
        # This is an explicit setup mutation, isolated from recovery evidence.
        _run_cli(
            SERVICE_UID,
            "stop",
            ["--state-dir", os.fspath(state)],
            tracker,
            discard_output=True,
        )
        service = _start_service(state, socket_path, 1, tracker)
        try:
            _track_state_and_socket(state, socket_path, socket_path.parent, owned)
            if rejected_queue is None:
                _raise_failure("REJECTED_QUEUE_UNAVAILABLE")
            dispatch_output, _ = _run_cli(
                WORKLOAD_UID,
                "dispatch",
                [
                    "--socket",
                    os.fspath(socket_path),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--queue-id",
                    rejected_queue,
                ],
                tracker,
            )
            setup["rejected_dispatch"] = _assert_dispatch(dispatch_output, rejected=True)
        finally:
            _finish_service(service)
    setup["effect_snapshot"] = _effect_snapshot(state, tracker)
    setup["durable_snapshot"] = _durable_snapshot(state)
    return setup


def _run_qualification(
    result_path: Path,
    identity_descriptor_path: Path,
) -> tuple[str, str, dict[str, Any]]:
    tracker = RunTracker()
    owned: list[OwnedPath] = []
    created: list[ProvisionedIdentity] = []
    started_at_utc = _utc_timestamp()
    cleanup: dict[str, Any] = {
        "safe": False,
        "tracked_children": 0,
        "child_residuals": [],
        "owned_paths_removed": 0,
        "owned_paths_missing": 0,
        "owned_path_refusals": [],
        "identities_removed": False,
        "identity_observations": 0,
    }
    evidence: dict[str, Any] = {
        "schema_version": "lumi-eggcracker.native-recovery-qualification.v1",
        "result": "INCONCLUSIVE",
        "reason_code": "NOT_STARTED",
        "timestamps": {
            "started_at_utc": started_at_utc,
            "completed_at_utc": None,
        },
        "invocation": _invocation_identity(),
        "candidate": None,
        "host": {
            "runner_environment": "github-hosted",
            "os": "ubuntu-24.04",
            "kernel_release": platform.release() if sys.platform == "linux" else None,
            "python_version": platform.python_version(),
            "python_executable": os.fspath(PYTHON),
        },
        "identities": {
            "service": {"uid": SERVICE_UID, "primary_gid": IPC_GID},
            "workload": {"uid": WORKLOAD_UID, "primary_gid": IPC_GID},
            "negative_peer": {"uid": PEER_UID, "primary_gid": IPC_GID},
            "ipc_group": {"gid": IPC_GID},
        },
        "network": {
            "product_harness_network": False,
            "control_plane": ["github_checkout", "github_artifact_upload"],
        },
        "source": {"pre": {}, "post": {}, "accepted_438_unchanged": False},
        "identity_evidence": {
            "checkout_owner_git_identity": {
                "label": "checkout_owner_git_identity",
                "commit": None,
                "tree": None,
                "descriptor_target": "RUNNER_TEMP/brokered-recovery-native-identity/descriptor.json",
            },
            "root_eight_file_bytes": {
                "label": "root_eight_file_bytes",
                "pre": {},
                "post": {},
            },
        },
        "setup": {},
        "recovery": {},
        "commands": {},
        "skips": [],
        "cleanup": cleanup,
    }
    status = "INCONCLUSIVE"
    reason = "NOT_STARTED"
    pre_hashes: dict[str, str] = {}
    descriptor_paths: dict[str, str] = {}
    try:
        _host_gate()
        _, runner_temp, result_parent = _validate_result_target(os.fspath(result_path))
        descriptor = _validate_identity_descriptor(
            os.fspath(identity_descriptor_path),
            result_parent,
            runner_temp,
        )
        descriptor_paths = descriptor["paths"]
        evidence["candidate"] = {
            "commit": descriptor["commit"],
            "tree": descriptor["tree"],
        }
        evidence["identity_evidence"]["checkout_owner_git_identity"].update(
            {"commit": descriptor["commit"], "tree": descriptor["tree"]}
        )
        pre_hashes = _validate_source_preimages(descriptor_paths)
        evidence["source"]["pre"] = pre_hashes
        evidence["identity_evidence"]["root_eight_file_bytes"]["pre"] = pre_hashes
        _provision_identities(tracker, created)
        task_root = result_path.parent / "work"
        _prepare_owned_directory(
            task_root,
            "task_root",
            uid=SERVICE_UID,
            gid=IPC_GID,
            mode=SOCKET_DIRECTORY_MODE,
            owned=owned,
        )
        stores_root = task_root / "stores"
        _prepare_owned_directory(
            stores_root,
            "stores_root",
            uid=SERVICE_UID,
            gid=IPC_GID,
            mode=SOCKET_DIRECTORY_MODE,
            owned=owned,
        )
        store_paths: dict[str, tuple[Path, Path]] = {}
        for store_label in ("store_a", "store_b"):
            store_parent = stores_root / store_label
            _prepare_owned_directory(
                store_parent,
                f"{store_label}_parent",
                uid=SERVICE_UID,
                gid=IPC_GID,
                mode=SOCKET_DIRECTORY_MODE,
                owned=owned,
            )
            socket_parent = store_parent / "ipc"
            _prepare_owned_directory(
                socket_parent,
                f"{store_label}_socket_parent",
                uid=SERVICE_UID,
                gid=IPC_GID,
                mode=SOCKET_DIRECTORY_MODE,
                owned=owned,
            )
            state = store_parent / "state"
            socket_path = socket_parent / "broker.sock"
            if state.exists() or state.is_symlink() or socket_path.exists() or socket_path.is_symlink():
                _raise_inconclusive("STORE_PATH_COLLISION")
            store_paths[store_label] = (state, socket_path)

        state_a, socket_a = store_paths["store_a"]
        state_b, socket_b = store_paths["store_b"]
        evidence["setup"]["store_a"] = _setup_store(
            "store_a",
            state_a,
            socket_a,
            tracker,
            owned,
        )
        evidence["setup"]["store_b"] = _setup_store(
            "store_b",
            state_b,
            socket_b,
            tracker,
            owned,
            rejected=True,
        )

        # Recovery is a separate phase.  The service is reopened on each
        # durable run and handles exactly the fixed number of fresh sockets.
        service_a = _start_service(state_a, socket_a, 7, tracker)
        try:
            _track_state_and_socket(state_a, socket_a, socket_a.parent, owned)
            recovery_a: list[dict[str, Any]] = []
            first = _recovery_call(
                "lost_output_pending",
                state_a,
                tracker,
                lambda: _run_cli(
                    WORKLOAD_UID,
                    "recover",
                    [
                        "--socket",
                        os.fspath(socket_a),
                        "--service-uid",
                        str(SERVICE_UID),
                        "--operation-id",
                        OPERATION_IDS["lost_output"],
                    ],
                    tracker,
                )[0],
                "PENDING",
            )
            recovery_a.append(first)
            pending_repeat_before_durable = _durable_snapshot(state_a)
            pending_repeat_before_effect = _effect_snapshot(state_a, tracker)
            pending_repeat_output, _ = _run_cli(
                WORKLOAD_UID,
                "recover",
                [
                    "--socket",
                    os.fspath(socket_a),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--operation-id",
                    OPERATION_IDS["lost_output"],
                ],
                tracker,
            )
            pending_repeat_after_durable = _durable_snapshot(state_a)
            pending_repeat_after_effect = _effect_snapshot(state_a, tracker)
            if pending_repeat_before_durable != pending_repeat_after_durable:
                _raise_failure("RECOVERY_DURABLE_STATE_CHANGED")
            if pending_repeat_before_effect != pending_repeat_after_effect:
                _raise_failure("RECOVERY_EFFECT_CHANGED")
            pending_response, pending_queue = _assert_recovery(pending_repeat_output, "PENDING")
            if pending_queue is None or pending_response.get("status") != "PENDING":
                _raise_failure("PENDING_RECOVERY_HANDLE_INVALID")
            recovery_a.append(
                {
                    "label": "lost_output_pending_repeat",
                    "response": pending_response,
                    "durable_unchanged": True,
                    "effect_unchanged": True,
                }
            )
            pending_result_before_durable = _durable_snapshot(state_a)
            pending_result_before_effect = _effect_snapshot(state_a, tracker)
            result_output, _ = _run_cli(
                WORKLOAD_UID,
                "result",
                [
                    "--socket",
                    os.fspath(socket_a),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--queue-id",
                    pending_queue,
                ],
                tracker,
            )
            pending_result_after_durable = _durable_snapshot(state_a)
            pending_result_after_effect = _effect_snapshot(state_a, tracker)
            if pending_result_before_durable != pending_result_after_durable:
                _raise_failure("RECOVERY_DURABLE_STATE_CHANGED")
            if pending_result_before_effect != pending_result_after_effect:
                _raise_failure("RECOVERY_EFFECT_CHANGED")
            pending_result_response = _assert_pending_result(result_output, pending_queue)
            recovery_a.append(
                {
                    "label": "pending_get_result",
                    "response": pending_result_response,
                    "durable_unchanged": True,
                    "effect_unchanged": True,
                }
            )
            applied = _recovery_call(
                "applied_confirmed",
                state_a,
                tracker,
                lambda: _run_cli(
                    WORKLOAD_UID,
                    "recover",
                    [
                        "--socket",
                        os.fspath(socket_a),
                        "--service-uid",
                        str(SERVICE_UID),
                        "--operation-id",
                        OPERATION_IDS["applied"],
                    ],
                    tracker,
                )[0],
                "CONFIRMED_APPLIED",
            )
            recovery_a.append(applied)
            unknown_result = _recovery_call(
                "truly_unknown_not_found",
                state_a,
                tracker,
                lambda: _run_cli(
                    WORKLOAD_UID,
                    "recover",
                    [
                        "--socket",
                        os.fspath(socket_a),
                        "--service-uid",
                        str(SERVICE_UID),
                        "--operation-id",
                        OPERATION_IDS["unknown"],
                    ],
                    tracker,
                )[0],
                None,
            )
            cross_result = _recovery_call(
                "cross_store_not_found",
                state_a,
                tracker,
                lambda: _run_cli(
                    WORKLOAD_UID,
                    "recover",
                    [
                        "--socket",
                        os.fspath(socket_a),
                        "--service-uid",
                        str(SERVICE_UID),
                        "--operation-id",
                        OPERATION_IDS["rejected"],
                    ],
                    tracker,
                )[0],
                None,
            )
            if unknown_result["response"] != cross_result["response"]:
                _raise_failure("CROSS_STORE_NOT_FOUND_NOT_INDISTINGUISHABLE")
            recovery_a.append(
                {
                    "label": "unknown_and_cross_store_not_found",
                    "response": unknown_result["response"],
                    "bounded_indistinguishable": True,
                    "durable_unchanged": unknown_result["durable_unchanged"] and cross_result["durable_unchanged"],
                    "effect_unchanged": unknown_result["effect_unchanged"] and cross_result["effect_unchanged"],
                }
            )
            peer_before_durable = _durable_snapshot(state_a)
            peer_before_effect = _effect_snapshot(state_a, tracker)
            peer_raw, _ = _run_cli(
                PEER_UID,
                "recover",
                [
                    "--socket",
                    os.fspath(socket_a),
                    "--service-uid",
                    str(SERVICE_UID),
                    "--operation-id",
                    OPERATION_IDS["unknown"],
                ],
                tracker,
            )
            peer_after_durable = _durable_snapshot(state_a)
            peer_after_effect = _effect_snapshot(state_a, tracker)
            _same_recovery_state(peer_before_durable, peer_after_durable)
            if peer_before_effect != peer_after_effect:
                _raise_failure("PEER_IDENTITY_EFFECT_CHANGED")
            peer = _assert_peer_denial(peer_raw)
            recovery_a.append(
                {
                    "label": "negative_peer",
                    "response": peer,
                    "durable_unchanged": peer_before_durable == peer_after_durable,
                    "effect_unchanged": True,
                }
            )
        finally:
            _finish_service(service_a)
        evidence["recovery"]["store_a"] = recovery_a

        service_b = _start_service(state_b, socket_b, 1, tracker)
        try:
            _track_state_and_socket(state_b, socket_b, socket_b.parent, owned)
            recovery_b = _recovery_call(
                "rejected_confirmed_not_applied",
                state_b,
                tracker,
                lambda: _run_cli(
                    WORKLOAD_UID,
                    "recover",
                    [
                        "--socket",
                        os.fspath(socket_b),
                        "--service-uid",
                        str(SERVICE_UID),
                        "--operation-id",
                        OPERATION_IDS["rejected"],
                    ],
                    tracker,
                )[0],
                "CONFIRMED_NOT_APPLIED",
            )
        finally:
            _finish_service(service_b)
        evidence["recovery"]["store_b"] = [recovery_b]

        post_hashes = _source_hashes()
        evidence["source"]["post"] = post_hashes
        evidence["identity_evidence"]["root_eight_file_bytes"]["post"] = post_hashes
        if post_hashes != pre_hashes:
            _raise_failure("SOURCE_DRIFT_DURING_RUN")
        if post_hashes != descriptor_paths:
            _raise_failure("SOURCE_DESCRIPTOR_DRIFT")
        evidence["source"]["accepted_438_unchanged"] = all(
            post_hashes.get(relative) == expected for relative, expected in ACCEPTED_438_HASHES.items()
        )
        if not evidence["source"]["accepted_438_unchanged"]:
            _raise_failure("ACCEPTED_438_SOURCE_DRIFT")
        status = "PASS"
        reason = "QUALIFICATION_PASSED"
    except Inconclusive as error:
        status = "INCONCLUSIVE"
        reason = error.code
    except AssertionFailure as error:
        status = "FAIL"
        reason = error.code
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        status = "INCONCLUSIVE"
        reason = "HARNESS_PRIMITIVE_UNAVAILABLE"
    # Unexpected qualification errors still need cleanup and a sanitized FAIL
    # classification rather than escaping to the workflow as raw output.
    except Exception:  # noqa: BLE001 - preserve fail classification and cleanup.
        status = "FAIL"
        reason = "UNEXPECTED_QUALIFICATION_FAILURE"
    finally:
        try:
            cleanup = _cleanup(owned, created, tracker)
        except Exception:  # noqa: BLE001 - cleanup is fail-closed and sanitized.
            cleanup = {
                "safe": False,
                "tracked_children": len(tracker.children),
                "child_residuals": ["cleanup_exception"],
                "owned_paths_removed": 0,
                "owned_paths_missing": 0,
                "owned_path_refusals": ["cleanup_exception"],
                "identities_removed": False,
                "identity_observations": tracker.child_identity_observations,
            }
        if not cleanup["safe"] and status == "PASS":
            status = "INCONCLUSIVE"
            reason = "CLEANUP_UNSAFE"
        try:
            if pre_hashes:
                evidence["source"]["post"] = _source_hashes()
                evidence["identity_evidence"]["root_eight_file_bytes"]["post"] = evidence["source"]["post"]
                if evidence["source"]["post"] != pre_hashes and status != "FAIL":
                    status = "FAIL"
                    reason = "SOURCE_DRIFT_DURING_RUN"
                if descriptor_paths and evidence["source"]["post"] != descriptor_paths and status != "FAIL":
                    status = "FAIL"
                    reason = "SOURCE_DESCRIPTOR_DRIFT"
        # Source post-hashing is evidence; an unexpected read/hash failure
        # must downgrade PASS without exposing the raw exception.
        except Exception:  # noqa: BLE001 - preserve sanitized posthash outcome.
            if status == "PASS":
                status = "INCONCLUSIVE"
                reason = "SOURCE_POSTHASH_UNAVAILABLE"
    evidence["result"] = status
    evidence["reason_code"] = reason
    evidence["timestamps"]["completed_at_utc"] = _utc_timestamp()
    evidence["cleanup"] = cleanup
    evidence["commands"] = {
        name: count for name, count in sorted(tracker.command_counts.items())
    }
    fixed_launches = tracker.command_counts.get("setpriv", 0)
    evidence["identity_evidence"].update(
        {
            "setpriv_fixed_launches": fixed_launches,
            "observed_non_root_children": tracker.child_identity_observations,
            "direct_observation_complete": tracker.child_identity_observations == fixed_launches,
        }
    )
    return status, reason, evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result")
    parser.add_argument("--service-child", action="store_true")
    parser.add_argument("--state-dir")
    parser.add_argument("--socket")
    parser.add_argument("--requests", type=int)
    parser.add_argument("--identity-descriptor")
    arguments = parser.parse_args(argv)
    if arguments.service_child:
        if (
            arguments.result
            or arguments.identity_descriptor is not None
            or arguments.state_dir is None
            or arguments.socket is None
            or arguments.requests is None
        ):
            return 70
        return _service_child(arguments)
    if arguments.result is None or arguments.identity_descriptor is None:
        return 70
    if (
        arguments.state_dir is not None
        or arguments.socket is not None
        or arguments.requests is not None
    ):
        return 70
    result_path = Path(arguments.result)
    try:
        _validate_result_target(os.fspath(result_path))
    except Inconclusive:
        return 2
    try:
        status, _, evidence = _run_qualification(
            result_path,
            Path(arguments.identity_descriptor),
        )
        _write_result(result_path, evidence)
    except Inconclusive as error:
        # A valid result target is required before the orchestrator can emit a
        # record.  This branch is intentionally silent: no raw paths/errors.
        try:
            if result_path.is_absolute() and result_path.parent.is_dir() and not result_path.exists():
                _write_result(
                    result_path,
                    {
                        "schema_version": "lumi-eggcracker.native-recovery-qualification.v1",
                        "result": "INCONCLUSIVE",
                        "reason_code": error.code,
                        "timestamps": {
                            "started_at_utc": _utc_timestamp(),
                            "completed_at_utc": _utc_timestamp(),
                        },
                        "invocation": _invocation_identity(),
                        "candidate": None,
                        "network": {"product_harness_network": False, "control_plane": ["github_checkout", "github_artifact_upload"]},
                        "skips": [],
                    },
                )
        except Exception:  # noqa: BLE001, S110 - result fallback must stay sanitized.
            # The target may be unwritable; do not emit raw paths/errors from
            # this fallback while retaining the bounded INCONCLUSIVE status.
            pass
        return 2
    # Keep the command-line contract bounded even for an unclassified failure.
    except Exception:  # noqa: BLE001 - return only the sanitized failure code.
        return 1
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
