"""Exact manifest-bound uninstaller for Lumi Eggcracker."""

from __future__ import annotations

import sys as _bootstrap_sys

if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.flags.no_site:
    raise SystemExit(
        "privileged uninstaller requires /usr/bin/python3 -I -S scripts/uninstall.py"
    )

import posix as _bootstrap_posix

try:
    _bootstrap_posix.readlink(__file__)
except OSError:
    pass
else:
    raise SystemExit("refusing a symlinked privileged uninstaller")

import argparse
import grp
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import time
from pathlib import Path

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in _bootstrap_sys.path:
    _bootstrap_sys.path.insert(0, str(_SCRIPT_ROOT))
import install as installer

LIB = Path("/usr/local/lib/lumi-eggcracker")
BIN = Path("/usr/local/bin/eggcracker")
ETC = Path("/etc/lumi-eggcracker")
UNIT = Path("/etc/systemd/system/lumi-eggcracker.service")
WATCHDOG_UNIT = Path("/etc/systemd/system/lumi-eggcracker-watchdog.service")
TMPFILES = Path("/etc/tmpfiles.d/lumi-eggcracker.conf")
STATE = Path("/var/lib/lumi-eggcracker")
RUNTIME = Path("/run/lumi-eggcracker")
WATCHDOG_RUNTIME = Path("/run/lumi-eggcracker-watchdog")
UNINSTALL_JOURNAL = Path("/var/lib/lumi-eggcracker-uninstall-journal.json")
UNINSTALL_JOURNAL_SCHEMA = "lumi-eggcracker.uninstall-transaction.v1"
MAX_UNINSTALL_JOURNAL_BYTES = 64 * 1024
PREFIX = "lumi-eggcracker-workload-"
SUPERVISOR = "lumi-eggcracker.service"
WATCHDOG = "lumi-eggcracker-watchdog.service"
SYSTEM_SLICE = Path("/sys/fs/cgroup/system.slice")
SERVICE_CGROUPS = (
    SYSTEM_SLICE / SUPERVISOR,
    SYSTEM_SLICE / WATCHDOG,
)
TARGETS = (
    UNIT,
    WATCHDOG_UNIT,
    TMPFILES,
    BIN,
    LIB,
    ETC,
    STATE,
    RUNTIME,
    WATCHDOG_RUNTIME,
)
DIRECTORY_TARGETS = {LIB, ETC, STATE, RUNTIME, WATCHDOG_RUNTIME}
MANIFEST_FILES = {
    BIN,
    ETC / "detector_catalogue.json",
    ETC / "policy.json",
    LIB / "lumi-eggcracker.pyz",
    TMPFILES,
    UNIT,
    WATCHDOG_UNIT,
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_uninstall_journal(manifest: dict[str, object]) -> int:
    account = pwd.getpwnam(str(manifest["workload_user"]))
    workload_gid = account.pw_gid
    value = {
        "manifest": manifest,
        "schema_version": UNINSTALL_JOURNAL_SCHEMA,
        "uninstaller_sha256": digest(Path(__file__)),
        "workload_gid": workload_gid,
    }
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(payload) > MAX_UNINSTALL_JOURNAL_BYTES:
        raise SystemExit("uninstall transaction journal is too large")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(UNINSTALL_JOURNAL, flags, 0o600)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("uninstall transaction write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        descriptor = -1
        if UNINSTALL_JOURNAL.exists() and not UNINSTALL_JOURNAL.is_symlink():
            UNINSTALL_JOURNAL.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    installer.fsync_directory(UNINSTALL_JOURNAL.parent)
    return workload_gid


def remove_uninstall_journal() -> None:
    UNINSTALL_JOURNAL.unlink(missing_ok=True)
    installer.fsync_directory(UNINSTALL_JOURNAL.parent)


def validate_manifest_structure(manifest: object) -> dict[str, object]:
    if not isinstance(manifest, dict):
        raise SystemExit("installed manifest is invalid")
    if manifest.get("schema_version") != "lumi-eggcracker.install.v5":
        raise SystemExit("installed manifest schema is invalid")
    files = manifest.get("files")
    targets = manifest.get("targets")
    if (
        not isinstance(files, dict)
        or any(not isinstance(name, str) for name in files)
        or {Path(name) for name in files} != MANIFEST_FILES
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in files.values()
        )
        or not isinstance(targets, list)
        or len(targets) != len(TARGETS)
        or {Path(value) for value in targets if isinstance(value, str)} != set(TARGETS)
    ):
        raise SystemExit("installed manifest inventory is invalid")
    if (
        not isinstance(manifest.get("operator"), str)
        or not isinstance(manifest.get("operator_uid"), int)
        or not isinstance(manifest.get("workload_user"), str)
        or not isinstance(manifest.get("workload_group"), str)
        or not isinstance(manifest.get("workload_uid"), int)
        or not isinstance(manifest.get("created_workload_user"), bool)
        or not isinstance(manifest.get("created_workload_group"), bool)
    ):
        raise SystemExit("installed manifest identity is invalid")
    return manifest


def read_uninstall_journal() -> tuple[dict[str, object], int]:
    try:
        metadata = UNINSTALL_JOURNAL.lstat()
    except FileNotFoundError as error:
        raise SystemExit("uninstall transaction journal disappeared") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= metadata.st_size <= MAX_UNINSTALL_JOURNAL_BYTES
    ):
        raise SystemExit("uninstall transaction journal has unsafe metadata")
    try:
        value = json.loads(UNINSTALL_JOURNAL.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("uninstall transaction journal is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value)
        != {"manifest", "schema_version", "uninstaller_sha256", "workload_gid"}
        or value.get("schema_version") != UNINSTALL_JOURNAL_SCHEMA
        or value.get("uninstaller_sha256") != digest(Path(__file__))
        or not isinstance(value.get("workload_gid"), int)
    ):
        raise SystemExit("uninstall transaction journal identity is invalid")
    return validate_manifest_structure(value.get("manifest")), value["workload_gid"]


def validate_remaining_targets(manifest: dict[str, object], allow_missing: bool) -> None:
    files = manifest["files"]
    if not isinstance(files, dict):
        raise SystemExit("installed manifest inventory is invalid")
    for name, expected in files.items():
        path = Path(name)
        if not path.exists() and not path.is_symlink():
            if allow_missing:
                continue
            raise SystemExit(f"refusing uninstall because installed file drifted: {path}")
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise SystemExit(f"refusing uninstall because installed file drifted: {path}")
    operator = pwd.getpwnam(str(manifest["operator"]))
    if operator.pw_uid != manifest["operator_uid"] or operator.pw_uid == 0:
        raise SystemExit("installed operator identity changed")
    for path in TARGETS:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        expected_type = stat.S_IFDIR if path in DIRECTORY_TARGETS else stat.S_IFREG
        allowed_gids = {0, operator.pw_gid} if path == RUNTIME else {0}
        if (
            stat.S_IFMT(metadata.st_mode) != expected_type
            or path.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_gid not in allowed_gids
            or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
        ):
            raise SystemExit(f"refusing unsafe uninstall target: {path}")


def systemctl_allow_absent(action: str, unit: str) -> None:
    result = run(["/usr/bin/systemctl", action, unit])
    detail = (result.stderr + result.stdout).lower()
    absent = any(
        marker in detail
        for marker in ("not loaded", "not found", "does not exist", "no such file")
    )
    if result.returncode and not absent:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or "systemctl failed")


def remove_manifest_identity(manifest: dict[str, object], workload_gid: int) -> None:
    if manifest["created_workload_user"]:
        try:
            account = pwd.getpwnam(str(manifest["workload_user"]))
        except KeyError:
            account = None
        if account is not None:
            supplementary = set(os.getgrouplist(account.pw_name, account.pw_gid))
            if (
                account.pw_uid != manifest["workload_uid"]
                or account.pw_uid == 0
                or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
                or account.pw_dir != "/nonexistent"
                or supplementary != {account.pw_gid}
            ):
                raise SystemExit("refusing to remove changed workload identity")
            require_success(["/usr/sbin/userdel", account.pw_name])
    if manifest["created_workload_group"]:
        try:
            group = grp.getgrnam(str(manifest["workload_group"]))
        except KeyError:
            group = None
        if group is not None:
            if group.gr_gid != workload_gid or group.gr_mem:
                raise SystemExit("refusing to remove changed workload group")
            if any(account.pw_gid == group.gr_gid for account in pwd.getpwall()):
                raise SystemExit("refusing to remove a workload group still in use")
            require_success(["/usr/sbin/groupdel", group.gr_name])


def recover_uninstall() -> int:
    manifest, workload_gid = read_uninstall_journal()
    validate_remaining_targets(manifest, allow_missing=True)
    systemctl_allow_absent("stop", SUPERVISOR)
    systemctl_allow_absent("disable", SUPERVISOR)
    systemctl_allow_absent("stop", WATCHDOG)
    systemctl_allow_absent("disable", WATCHDOG)
    for service_cgroup in SERVICE_CGROUPS:
        empty_stopped_service_cgroup(service_cgroup)
    if not owned_cgroups_empty() or not quarantine_empty():
        raise SystemExit("refusing recovery because Eggcracker cgroups remain populated")
    for path in TARGETS:
        if path.exists() and not path.is_symlink():
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    remove_manifest_identity(manifest, workload_gid)
    require_success(["/usr/bin/systemctl", "daemon-reload"])
    require_success(["/usr/bin/systemctl", "reset-failed"])
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise SystemExit("uninstall recovery left an Eggcracker target")
    remove_uninstall_journal()
    print(json.dumps({"recovered": True, "result": "UNINSTALLED"}, sort_keys=True))
    return 0


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


def require_success(argv: list[str]) -> None:
    result = run(argv)
    if result.returncode:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"command failed: {argv[1]}")


def reset_failed(unit: str) -> None:
    result = run(["/usr/bin/systemctl", "reset-failed", unit])
    if result.returncode and "not loaded" not in result.stderr.lower():
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or "cannot reset unit state")


def owned_cgroups_empty() -> bool:
    root = Path("/sys/fs/cgroup/system.slice")
    if not root.is_dir():
        return False
    for path in root.glob(f"{PREFIX}*.service"):
        if not path.is_dir() or path.is_symlink():
            return False
        events = path / "cgroup.events"
        try:
            populated = dict(line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()).get("populated")
        except OSError:
            return False
        if populated != "0":
            return False
    return True


def quarantine_empty() -> bool:
    root = Path("/sys/fs/cgroup/system.slice/lumi-eggcracker.service/quarantine")
    if not root.exists():
        return True
    if root.is_symlink() or not root.is_dir():
        return False
    events = root / "cgroup.events"
    try:
        populated = dict(
            line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()
        ).get("populated")
    except OSError:
        return False
    if populated != "0":
        return False
    for path in root.iterdir():
        if not path.is_dir():
            continue
        if path.is_symlink() or len(path.name) != 24 or any(
            item not in "0123456789abcdef" for item in path.name
        ):
            return False
        events = path / "cgroup.events"
        try:
            populated = dict(line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()).get("populated")
        except OSError:
            return False
        if populated != "0":
            return False
    return True


def empty_stopped_service_cgroup(path: Path) -> None:
    """Empty one exact Eggcracker service cgroup after systemd stopped it."""
    if path not in SERVICE_CGROUPS:
        raise SystemExit("refusing to empty an unexpected service cgroup")
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"invalid stopped service cgroup: {path}")
    events = path / "cgroup.events"
    kill = path / "cgroup.kill"
    try:
        populated = dict(
            line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()
        ).get("populated")
    except OSError as exc:
        raise SystemExit(f"cannot inspect stopped service cgroup: {path}") from exc
    if populated == "1":
        try:
            kill.write_text("1\n", encoding="ascii")
        except OSError as exc:
            raise SystemExit(f"cannot empty stopped service cgroup: {path}") from exc
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not path.exists():
            return
        try:
            populated = dict(
                line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()
            ).get("populated")
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SystemExit(f"cannot recheck stopped service cgroup: {path}") from exc
        if populated == "0":
            return
        time.sleep(0.01)
    raise SystemExit(f"stopped service cgroup remained populated: {path}")


def uninstall() -> int:
    if UNINSTALL_JOURNAL.exists() or UNINSTALL_JOURNAL.is_symlink():
        return recover_uninstall()
    manifest_path = STATE / "install-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit("installed manifest is missing")
    manifest = validate_manifest_structure(
        json.loads(manifest_path.read_text(encoding="utf-8"))
    )
    validate_remaining_targets(manifest, allow_missing=False)
    if not owned_cgroups_empty() or not quarantine_empty():
        raise SystemExit("refusing uninstall with populated or uncertain Eggcracker cgroups")
    workload_gid = write_uninstall_journal(manifest)
    supervisor_stopped = False
    watchdog_stopped = False
    try:
        require_success(["/usr/bin/systemctl", "stop", SUPERVISOR])
        supervisor_stopped = True
        require_success(["/usr/bin/systemctl", "disable", SUPERVISOR])
        require_success(["/usr/bin/systemctl", "stop", WATCHDOG])
        watchdog_stopped = True
        require_success(["/usr/bin/systemctl", "disable", WATCHDOG])
        for service_cgroup in SERVICE_CGROUPS:
            empty_stopped_service_cgroup(service_cgroup)
        if not owned_cgroups_empty() or not quarantine_empty():
            raise SystemExit("refusing uninstall because cgroups remained populated after stop")
        reset_failed(SUPERVISOR)
        reset_failed(WATCHDOG)
        for path in TARGETS:
            if path.exists() and not path.is_symlink():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        remove_manifest_identity(manifest, workload_gid)
        require_success(["/usr/bin/systemctl", "daemon-reload"])
        # Removing the unit files can leave transient ``not-found`` objects in
        # the manager.  A global reset after the daemon reload lets systemd
        # garbage-collect them.  Naming a removed unit here would recreate the
        # very not-found object the uninstall verifier rejects.
        require_success(["/usr/bin/systemctl", "reset-failed"])
        remove_uninstall_journal()
    except BaseException:
        # A refused or interrupted transaction must not leave protection
        # disabled.  Best-effort restoration is deliberately attempted for
        # both units, regardless of which stop/disable operation failed.
        if supervisor_stopped or watchdog_stopped:
            run(["/usr/bin/systemctl", "daemon-reload"])
            run(["/usr/bin/systemctl", "enable", "--now", WATCHDOG])
            run(["/usr/bin/systemctl", "enable", "--now", SUPERVISOR])
        raise
    print(json.dumps({"result": "UNINSTALLED"}, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove a manifest-verified Lumi Eggcracker installation"
    )
    parser.parse_args(argv)
    if os.geteuid() != 0:
        raise SystemExit("uninstaller must run as root")
    lifecycle_lock = installer.acquire_lifecycle_lock()
    try:
        return uninstall()
    finally:
        installer.release_lifecycle_lock(lifecycle_lock)


if __name__ == "__main__":
    raise SystemExit(main())
