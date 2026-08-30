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
PREFIX = "lumi-eggcracker-workload-"
SUPERVISOR = "lumi-eggcracker.service"
WATCHDOG = "lumi-eggcracker-watchdog.service"
SYSTEM_SLICE = Path("/sys/fs/cgroup/system.slice")
SERVICE_CGROUPS = (
    SYSTEM_SLICE / SUPERVISOR,
    SYSTEM_SLICE / WATCHDOG,
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


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
    manifest_path = STATE / "install-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit("installed manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "lumi-eggcracker.install.v5":
        raise SystemExit("installed manifest schema is invalid")
    for name, expected in manifest.get("files", {}).items():
        path = Path(name)
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise SystemExit(f"refusing uninstall because installed file drifted: {path}")
    if not owned_cgroups_empty() or not quarantine_empty():
        raise SystemExit("refusing uninstall with populated or uncertain Eggcracker cgroups")
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
        for path in (UNIT, WATCHDOG_UNIT, TMPFILES, BIN, LIB, ETC, STATE, RUNTIME, WATCHDOG_RUNTIME):
            if path.exists() and not path.is_symlink():
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        if manifest.get("created_workload_user"):
            try:
                account = pwd.getpwnam(str(manifest["workload_user"]))
            except KeyError:
                account = None
            if account and account.pw_uid == manifest.get("workload_uid"):
                require_success(["/usr/sbin/userdel", account.pw_name])
        if manifest.get("created_workload_group"):
            try:
                group = grp.getgrnam(str(manifest.get("workload_group", "")))
            except KeyError:
                group = None
            if group:
                require_success(["/usr/sbin/groupdel", group.gr_name])
        require_success(["/usr/bin/systemctl", "daemon-reload"])
        # Removing the unit files can leave transient ``not-found`` objects in
        # the manager.  A global reset after the daemon reload lets systemd
        # garbage-collect them.  Naming a removed unit here would recreate the
        # very not-found object the uninstall verifier rejects.
        require_success(["/usr/bin/systemctl", "reset-failed"])
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
