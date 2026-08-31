"""Manifest-bound installer for Lumi Eggcracker's root supervisor."""

from __future__ import annotations

import sys as _bootstrap_sys

if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.flags.no_site:
    raise SystemExit(
        "privileged installer requires /usr/bin/python3 -I -S scripts/install.py"
    )

import posix as _bootstrap_posix

try:
    _bootstrap_posix.readlink(__file__)
except OSError:
    pass
else:
    raise SystemExit("refusing a symlinked privileged installer")

import argparse
import fcntl
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

LIB = Path("/usr/local/lib/lumi-eggcracker")
BIN = Path("/usr/local/bin/eggcracker")
ETC = Path("/etc/lumi-eggcracker")
UNIT = Path("/etc/systemd/system/lumi-eggcracker.service")
WATCHDOG_UNIT = Path("/etc/systemd/system/lumi-eggcracker-watchdog.service")
TMPFILES = Path("/etc/tmpfiles.d/lumi-eggcracker.conf")
STATE = Path("/var/lib/lumi-eggcracker")
RUNTIME = Path("/run/lumi-eggcracker")
NETNS_RUNTIME = Path("/run/netns")
QUERY_SOCKET = RUNTIME / "query.sock"
OPERATOR_SOCKET = RUNTIME / "operator.sock"
ADMIN_SOCKET = RUNTIME / "admin.sock"
WATCHDOG_RUNTIME = Path("/run/lumi-eggcracker-watchdog")
HEARTBEAT_SOCKET = WATCHDOG_RUNTIME / "heartbeat.sock"
WORKLOAD_NAME = "lumi-eggcracker-workload"
TARGETS = (
    LIB,
    BIN,
    ETC,
    UNIT,
    WATCHDOG_UNIT,
    TMPFILES,
    STATE,
    RUNTIME,
    WATCHDOG_RUNTIME,
)
INSTALLER_VERSION = "1.0.5"
MAX_RELEASE_MANIFEST_BYTES = 32 * 1024
INSTALL_JOURNAL = Path("/var/lib/lumi-eggcracker-install-journal.json")
LIFECYCLE_LOCK = Path("/run/lock/lumi-eggcracker-lifecycle.lock")
INSTALL_JOURNAL_SCHEMA = "lumi-eggcracker.install-transaction.v1"
MAX_INSTALL_JOURNAL_BYTES = 8 * 1024


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def digest_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while block := os.read(descriptor, 64 * 1024):
        value.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return value.hexdigest()


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


def acquire_lifecycle_lock() -> int:
    """Serialize privileged lifecycle mutation and survive a killed holder."""
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(LIFECYCLE_LOCK, flags, 0o600)
    except OSError as error:
        raise RuntimeError("cannot open the Eggcracker lifecycle lock") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError("Eggcracker lifecycle lock has unsafe metadata")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another Eggcracker lifecycle operation is active") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def release_lifecycle_lock(descriptor: int) -> None:
    """Remove only the exact lock inode after all lifecycle mutation ends."""
    try:
        held = os.fstat(descriptor)
        try:
            current = LIFECYCLE_LOCK.lstat()
        except FileNotFoundError:
            current = None
        if current is not None and (current.st_dev, current.st_ino) == (
            held.st_dev,
            held.st_ino,
        ):
            LIFECYCLE_LOCK.unlink()
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_install_journal(value: dict[str, Any]) -> None:
    """Durably publish recovery authority before the first install mutation."""
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(payload) > MAX_INSTALL_JOURNAL_BYTES:
        raise RuntimeError("install transaction journal is too large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(INSTALL_JOURNAL, flags, 0o600)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("install transaction write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        descriptor = -1
        if INSTALL_JOURNAL.exists() and not INSTALL_JOURNAL.is_symlink():
            INSTALL_JOURNAL.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    fsync_directory(INSTALL_JOURNAL.parent)


def remove_install_journal() -> None:
    INSTALL_JOURNAL.unlink(missing_ok=True)
    fsync_directory(INSTALL_JOURNAL.parent)


def read_install_journal(
    release: dict[str, Any], operator: pwd.struct_passwd, artifact_sha256: str
) -> dict[str, Any]:
    try:
        metadata = INSTALL_JOURNAL.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("install transaction journal disappeared") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= metadata.st_size <= MAX_INSTALL_JOURNAL_BYTES
    ):
        raise RuntimeError("install transaction journal has unsafe metadata")
    try:
        value = json.loads(INSTALL_JOURNAL.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("install transaction journal is invalid") from error
    expected_keys = {
        "artifact_sha256",
        "operator",
        "operator_uid",
        "schema_version",
        "source_commit",
        "version",
        "workload_account_preexisting",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema_version") != INSTALL_JOURNAL_SCHEMA
        or value.get("artifact_sha256") != artifact_sha256
        or value.get("source_commit") != release["source_commit"]
        or value.get("version") != release["version"]
        or value.get("operator") != operator.pw_name
        or value.get("operator_uid") != operator.pw_uid
        or not isinstance(value.get("workload_account_preexisting"), bool)
    ):
        raise RuntimeError(
            "interrupted installation requires the exact original candidate and operator"
        )
    return value


def validate_recovery_target(path: Path, operator: pwd.struct_passwd) -> None:
    """Reject aliases before removing a target authorised by a valid journal."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    directory_targets = {LIB, ETC, STATE, RUNTIME, WATCHDOG_RUNTIME}
    expected_type = stat.S_IFDIR if path in directory_targets else stat.S_IFREG
    allowed_gids = {0, operator.pw_gid} if path == RUNTIME else {0}
    if (
        stat.S_IFMT(metadata.st_mode) != expected_type
        or path.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_gid not in allowed_gids
        or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
    ):
        raise RuntimeError(f"interrupted install target has unsafe metadata: {path}")


def recover_workload_identity(preexisting: bool, operator: pwd.struct_passwd) -> None:
    if preexisting:
        return
    try:
        account = pwd.getpwnam(WORKLOAD_NAME)
    except KeyError:
        account = None
    if account is not None:
        supplementary = set(os.getgrouplist(account.pw_name, account.pw_gid))
        if (
            account.pw_uid in {0, operator.pw_uid}
            or account.pw_gid == operator.pw_gid
            or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
            or account.pw_dir != "/nonexistent"
            or supplementary != {account.pw_gid}
        ):
            raise RuntimeError("interrupted workload account has unsafe identity")
        result = run(["/usr/sbin/userdel", WORKLOAD_NAME])
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "cannot remove interrupted account")
    try:
        group = grp.getgrnam(WORKLOAD_NAME)
    except KeyError:
        return
    if group.gr_mem:
        raise RuntimeError("interrupted workload group has unexpected members")
    result = run(["/usr/sbin/groupdel", WORKLOAD_NAME])
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "cannot remove interrupted group")


def recover_interrupted_install(
    release: dict[str, Any], operator: pwd.struct_passwd, artifact_sha256: str
) -> None:
    journal = read_install_journal(release, operator, artifact_sha256)
    for path in TARGETS:
        validate_recovery_target(path, operator)
    run(["/usr/bin/systemctl", "disable", "--now", "lumi-eggcracker.service"])
    run(
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "lumi-eggcracker-watchdog.service",
        ]
    )
    for path in reversed(TARGETS):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() and not path.is_symlink():
            path.unlink()
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "reset-failed"])
    recover_workload_identity(journal["workload_account_preexisting"], operator)
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise RuntimeError("interrupted install cleanup left a product target")
    remove_install_journal()


def write_new(path: Path, data: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.write_bytes(data)
    os.chmod(path, mode)


def socket_contract_matches(path: Path, mode: int, gid: int) -> bool:
    """Return true only after a supervisor socket has its final metadata."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISSOCK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == mode
        and metadata.st_uid == 0
        and metadata.st_gid == gid
    )


def read_stable_regular(path: Path, *, maximum: int) -> bytes:
    """Read one bounded non-symlink file through a stable held descriptor."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"cannot open release file {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise RuntimeError(f"release file {path.name} is invalid")
        value = bytearray()
        while len(value) <= maximum:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(value)))
            if not block:
                break
            value.extend(block)
        after = os.fstat(descriptor)
        def identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
            return (
                item.st_dev,
                item.st_ino,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
        if len(value) > maximum or len(value) != before.st_size or identity(before) != identity(after):
            raise RuntimeError(f"release file {path.name} changed during validation")
        return bytes(value)
    finally:
        os.close(descriptor)


def artifact_source_commit(artifact: Path) -> str:
    try:
        with zipfile.ZipFile(artifact) as bundle:
            raw = bundle.read("lumi_eggcracker/build_info.py")
    except (KeyError, OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("release artifact lacks source identity") from error
    match = re.fullmatch(b'SOURCE_COMMIT = "([0-9a-f]{40})"\r?\n', raw)
    if match is None:
        raise RuntimeError("release artifact source identity is invalid")
    return match.group(1).decode("ascii")


def manifest_for(
    artifact: Path, descriptor: int, expected_sha256: str
) -> dict[str, Any]:
    path = artifact.parent / "release-manifest.json"
    try:
        value = json.loads(
            read_stable_regular(path, maximum=MAX_RELEASE_MANIFEST_BYTES).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("release manifest is invalid") from error
    expected = {"artifact", "sha256", "source_archive", "source_archive_sha256", "source_commit", "version"}
    actual_sha256 = digest_descriptor(descriptor)
    if (
        set(value) != expected
        or value["artifact"] != artifact.name
        or value["sha256"] != actual_sha256
        or actual_sha256 != expected_sha256
    ):
        raise RuntimeError("release artifact identity does not match manifest")
    if (
        not isinstance(value["version"], str)
        or not value["version"]
        or value["version"] != INSTALLER_VERSION
        or len(value["source_commit"]) != 40
        or artifact_source_commit(Path(f"/proc/self/fd/{descriptor}"))
        != value["source_commit"]
    ):
        raise RuntimeError("release manifest version or source identity is invalid")
    version_check = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            f"/proc/self/fd/{descriptor}",
            "version",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        pass_fds=(descriptor,),
    )
    if version_check.returncode or version_check.stdout.strip() != value["version"]:
        raise RuntimeError("release artifact version does not match manifest")
    return value


def workload_account() -> tuple[pwd.struct_passwd, bool]:
    try:
        account = pwd.getpwnam(WORKLOAD_NAME)
        if account.pw_uid == 0 or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"} or account.pw_dir != "/nonexistent":
            raise RuntimeError("existing workload account does not meet Eggcracker contract")
        return account, False
    except KeyError:
        nologin = "/usr/sbin/nologin" if Path("/usr/sbin/nologin").is_file() else "/sbin/nologin"
        result = run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", nologin, WORKLOAD_NAME])
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "cannot create workload account")
        return pwd.getpwnam(WORKLOAD_NAME), True


def service() -> bytes:
    return b"""[Unit]\nDescription=Lumi Eggcracker autonomous AI runtime supervisor\nAfter=lumi-eggcracker-watchdog.service\nRequires=lumi-eggcracker-watchdog.service\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -I -S /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz _supervisor --policy /etc/lumi-eggcracker/policy.json\nRestart=always\nRestartSec=0.1\nRuntimeDirectory=lumi-eggcracker\nRuntimeDirectoryMode=0710\nUMask=0077\nNoNewPrivileges=yes\nDelegate=yes\nMemoryMin=64M\nMemoryMax=256M\nCPUWeight=10000\nIOWeight=1000\nTasksMax=256\nLimitNOFILE=65536\nOOMScoreAdjust=-900\nProtectSystem=strict\nReadWritePaths=/var/lib/lumi-eggcracker /run/lumi-eggcracker\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictRealtime=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nSystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n"""


# The supervisor inspects model paths opened by unrelated host processes.  A
# private /tmp namespace would make those paths disappear from its view and
# silently disable content recognition, so only the release supervisor unit
# removes that hardening flag.  The watchdog remains private below.
_SERVICE_RELEASE = service().replace(b"PrivateTmp=yes\n", b"").replace(
    b"ReadWritePaths=/var/lib/lumi-eggcracker /run/lumi-eggcracker\n",
    b"ReadWritePaths=/var/lib/lumi-eggcracker /run/lumi-eggcracker /run/netns\n",
).replace(
    b"RestrictAddressFamilies=AF_UNIX AF_NETLINK\n",
    b"RestrictAddressFamilies=AF_UNIX AF_NETLINK\nMountFlags=shared\n",
)


def watchdog_service() -> bytes:
    return b"""[Unit]\nDescription=Lumi Eggcracker fail-closed watchdog\nBefore=lumi-eggcracker.service\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -I -S /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz _watchdog --policy /etc/lumi-eggcracker/policy.json\nRestart=always\nRestartSec=0.1\nRuntimeDirectory=lumi-eggcracker-watchdog\nRuntimeDirectoryMode=0700\nUMask=0077\nNoNewPrivileges=yes\nMemoryMin=16M\nMemoryMax=64M\nCPUWeight=10000\nIOWeight=1000\nTasksMax=32\nLimitNOFILE=4096\nOOMScoreAdjust=-1000\nProtectSystem=strict\nReadWritePaths=/var/lib/lumi-eggcracker /run/lumi-eggcracker-watchdog\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nRestrictRealtime=yes\nRestrictAddressFamilies=AF_UNIX\nSystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n"""


def tmpfiles() -> bytes:
    """Provision the standard volatile network-namespace mount directory."""
    return b"d /run/netns 0755 root root -\n"


def ensure_netns_runtime() -> None:
    """Create or validate /run/netns without taking ownership of its contents."""
    try:
        metadata = NETNS_RUNTIME.lstat()
    except FileNotFoundError:
        NETNS_RUNTIME.mkdir(mode=0o755)
        os.chown(NETNS_RUNTIME, 0, 0)
        os.chmod(NETNS_RUNTIME, 0o755)
        metadata = NETNS_RUNTIME.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RuntimeError("/run/netns must be a root-owned non-writable directory")


def autonomous_primitives_available() -> bool:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False
    unit = f"lumi-eggcracker-preflight-{secrets.token_hex(8)}.service"
    started = run(["/usr/bin/systemd-run", f"--unit={unit}", "--collect", "--property=Type=exec", "--property=Delegate=yes", "--", "/bin/sleep", "5"])
    if started.returncode:
        return False
    try:
        shown = run(["/usr/bin/systemctl", "show", unit, "--property=ControlGroup"])
        values = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
        cgroup = values.get("ControlGroup", "")
        root = Path("/sys/fs/cgroup").joinpath(*cgroup.lstrip("/").split("/"))
        child = root / f"lumi-eggcracker-probe-{secrets.token_hex(4)}"
        if not cgroup.startswith("/system.slice/") or not (root / "cgroup.kill").is_file():
            return False
        try:
            child.mkdir(mode=0o700)
            return (child / "cgroup.kill").is_file() and (child / "cgroup.procs").is_file()
        finally:
            if child.exists() and not child.is_symlink():
                child.rmdir()
    finally:
        run(["/usr/bin/systemctl", "stop", unit])


def offline_boundary_primitives_available() -> bool:
    """Check the fixed tools and one disposable namespace operation."""
    tools = (Path("/usr/sbin/ip"), Path("/usr/sbin/nft"), Path("/usr/bin/nsenter"))
    if not all(path.is_file() and os.access(path, os.X_OK) for path in tools):
        return False
    namespace = f"lumi-eggcracker-preflight-{secrets.token_hex(8)}"
    created = False
    try:
        created_result = run([str(tools[0]), "netns", "add", namespace])
        if created_result.returncode:
            return False
        created = True
        listed = run(
            [str(tools[0]), "netns", "exec", namespace, str(tools[1]), "-j", "list", "tables"]
        )
        return listed.returncode == 0
    finally:
        if created:
            run([str(tools[0]), "netns", "del", namespace])


def execution_boundary_primitives_available() -> bool:
    """Check native seccomp user-notification support before mutation."""
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        return False
    try:
        return "user_notif" in Path("/proc/sys/kernel/seccomp/actions_avail").read_text(encoding="ascii").split()
    except (OSError, UnicodeDecodeError):
        return False


def catalogue_from_artifact(artifact: Path) -> bytes:
    try:
        with zipfile.ZipFile(artifact) as bundle:
            value = bundle.read("lumi_eggcracker/detector_catalogue.json")
    except (KeyError, OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("release artifact lacks detector catalogue") from error
    if not 1 <= len(value) <= 32 * 1024:
        raise RuntimeError("detector catalogue size is invalid")
    try:
        parsed = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("detector catalogue is invalid") from error
    if not isinstance(parsed, dict) or parsed.get("schema_version") != "lumi-eggcracker.detectors.v3":
        raise RuntimeError("detector catalogue schema is invalid")
    return value


def cleanup(created: list[Path], created_user: bool, created_group: bool) -> None:
    run(["/usr/bin/systemctl", "disable", "--now", "lumi-eggcracker.service"])
    run(["/usr/bin/systemctl", "disable", "--now", "lumi-eggcracker-watchdog.service"])
    for path in reversed(created):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif path.exists() and not path.is_symlink():
            path.unlink()
    if created_user:
        run(["/usr/sbin/userdel", WORKLOAD_NAME])
    if created_group:
        run(["/usr/sbin/groupdel", WORKLOAD_NAME])
    run(["/usr/bin/systemctl", "daemon-reload"])


def cleanup_complete(created_user: bool, created_group: bool) -> bool:
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        return False
    if created_user:
        try:
            pwd.getpwnam(WORKLOAD_NAME)
        except KeyError:
            pass
        else:
            return False
    if created_group:
        try:
            grp.getgrnam(WORKLOAD_NAME)
        except KeyError:
            pass
        else:
            return False
    return True


def install(args: argparse.Namespace) -> int:
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        raise SystemExit("expected artifact SHA-256 is invalid")
    if args.artifact.is_symlink() or not args.artifact.is_file():
        raise SystemExit("artifact must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    artifact_descriptor = os.open(args.artifact, flags)
    artifact_metadata = os.fstat(artifact_descriptor)
    if not stat.S_ISREG(artifact_metadata.st_mode):
        raise SystemExit("artifact must be a regular file")
    release = manifest_for(args.artifact, artifact_descriptor, args.expected_sha256)
    operator = pwd.getpwnam(args.operator)
    if operator.pw_uid == 0:
        raise SystemExit("operator must be non-root")
    if INSTALL_JOURNAL.exists() or INSTALL_JOURNAL.is_symlink():
        recover_interrupted_install(release, operator, args.expected_sha256)
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise SystemExit("refusing pre-existing Eggcracker installation target")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if (
        not controllers.is_file()
        or "pids" not in controllers.read_text(encoding="ascii").split()
        or not autonomous_primitives_available()
        or not offline_boundary_primitives_available()
        or not execution_boundary_primitives_available()
    ):
        raise SystemExit(
            "unified cgroup v2, delegated child cgroups, cgroup.kill, pidfds, seccomp user-notification, iproute2 and nftables are required"
        )
    try:
        pwd.getpwnam(WORKLOAD_NAME)
        workload_account_preexisting = True
    except KeyError:
        workload_account_preexisting = False
    write_install_journal(
        {
            "artifact_sha256": args.expected_sha256,
            "operator": operator.pw_name,
            "operator_uid": operator.pw_uid,
            "schema_version": INSTALL_JOURNAL_SCHEMA,
            "source_commit": release["source_commit"],
            "version": release["version"],
            "workload_account_preexisting": workload_account_preexisting,
        }
    )
    created: list[Path] = []
    created_user = False
    created_group = False
    try:
        account, created_user = workload_account()
        group = grp.getgrgid(account.pw_gid)
        created_group = created_user and group.gr_name == WORKLOAD_NAME
        supplementary = set(os.getgrouplist(account.pw_name, account.pw_gid))
        if (
            account.pw_uid in {0, operator.pw_uid}
            or account.pw_gid == operator.pw_gid
            or supplementary != {account.pw_gid}
        ):
            raise RuntimeError(
                "workload identity must be isolated from the operator and have no supplementary groups"
            )
        LIB.mkdir(mode=0o755)
        created.append(LIB)
        ETC.mkdir(mode=0o700)
        created.append(ETC)
        STATE.mkdir(mode=0o700)
        created.append(STATE)
        shutil.copyfile(
            f"/proc/self/fd/{artifact_descriptor}", LIB / "lumi-eggcracker.pyz"
        )
        os.chmod(LIB / "lumi-eggcracker.pyz", 0o755)
        write_new(BIN, b"#!/bin/sh\nexec /usr/bin/python3 -I -S /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz \"$@\"\n", 0o755)
        created.append(BIN)
        catalogue = catalogue_from_artifact(Path(f"/proc/self/fd/{artifact_descriptor}"))
        catalogue_path = ETC / "detector_catalogue.json"
        write_new(catalogue_path, catalogue, 0o644)
        policy = {"admin_socket_path": str(ADMIN_SOCKET), "catalogue_path": str(catalogue_path), "catalogue_sha256": hashlib.sha256(catalogue).hexdigest(), "network_mode": "offline", "operator_gid": operator.pw_gid, "operator_socket_path": str(OPERATOR_SOCKET), "operator_uid": operator.pw_uid, "query_socket_path": str(QUERY_SOCKET), "schema_version": "lumi-eggcracker.policy.v5", "source_commit": release["source_commit"], "state_dir": str(STATE), "unit_prefix": "lumi-eggcracker-workload-", "version": release["version"], "watchdog_socket_path": str(HEARTBEAT_SOCKET), "workload_gid": account.pw_gid, "workload_uid": account.pw_uid}
        write_new(ETC / "policy.json", (json.dumps(policy, sort_keys=True) + "\n").encode(), 0o600)
        write_new(UNIT, _SERVICE_RELEASE.replace(b"Requires=lumi-eggcracker-watchdog.service\n\n", b"Requires=lumi-eggcracker-watchdog.service\nStartLimitIntervalSec=0\n\n"), 0o644)
        created.append(UNIT)
        write_new(WATCHDOG_UNIT, watchdog_service().replace(b"Before=lumi-eggcracker.service\n\n", b"Before=lumi-eggcracker.service\nStartLimitIntervalSec=0\n\n"), 0o644)
        created.append(WATCHDOG_UNIT)
        write_new(TMPFILES, tmpfiles(), 0o644)
        created.append(TMPFILES)
        ensure_netns_runtime()
        manifest = {"created_workload_group": created_group, "created_workload_user": created_user, "files": {str(BIN): digest(BIN), str(catalogue_path): digest(catalogue_path), str(ETC / "policy.json"): digest(ETC / "policy.json"), str(LIB / "lumi-eggcracker.pyz"): digest(LIB / "lumi-eggcracker.pyz"), str(TMPFILES): digest(TMPFILES), str(UNIT): digest(UNIT), str(WATCHDOG_UNIT): digest(WATCHDOG_UNIT)}, "operator": operator.pw_name, "operator_uid": operator.pw_uid, "schema_version": "lumi-eggcracker.install.v5", "targets": [str(path) for path in TARGETS], "version": release["version"], "workload_gid": account.pw_gid, "workload_group": group.gr_name, "workload_uid": account.pw_uid, "workload_user": account.pw_name}
        write_new(STATE / "install-manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode(), 0o600)
        checked = run(["/usr/bin/systemctl", "daemon-reload"])
        started_watchdog = run(["/usr/bin/systemctl", "enable", "--now", "lumi-eggcracker-watchdog.service"])
        started = run(["/usr/bin/systemctl", "enable", "--now", "lumi-eggcracker.service"])
        if checked.returncode or started.returncode or started_watchdog.returncode:
            raise RuntimeError((checked.stderr + started.stderr + started_watchdog.stderr).strip() or "cannot start supervisor")
        # A cold bounded discovery scan may take several seconds on a loaded
        # qualification host.  Wait long enough for the supervisor to complete
        # that startup scan, while still failing before an operator mistakes a
        # non-starting installation for a ready one.
        socket_contract = (
            (QUERY_SOCKET, 0o660, operator.pw_gid),
            (OPERATOR_SOCKET, 0o660, operator.pw_gid),
            (ADMIN_SOCKET, 0o600, 0),
            (HEARTBEAT_SOCKET, 0o600, 0),
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if all(socket_contract_matches(*item) for item in socket_contract):
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("required Eggcracker sockets did not reach their ownership contract")
        remove_install_journal()
        print(json.dumps({"result": "INSTALLED", "service": "lumi-eggcracker.service", "workload_uid": account.pw_uid}, sort_keys=True))
        return 0
    except Exception:
        cleanup(created, created_user, created_group)
        if cleanup_complete(created_user, created_group):
            remove_install_journal()
        raise


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("installer must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    lifecycle_lock = acquire_lifecycle_lock()
    try:
        return install(args)
    finally:
        release_lifecycle_lock(lifecycle_lock)


if __name__ == "__main__":
    raise SystemExit(main())
