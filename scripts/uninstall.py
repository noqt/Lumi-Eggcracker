"""Exact manifest-bound uninstaller for Lumi Eggcracker."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

LIB = Path("/usr/local/lib/lumi-eggcracker")
BIN = Path("/usr/local/bin/eggcracker")
ETC = Path("/etc/lumi-eggcracker")
UNIT = Path("/etc/systemd/system/lumi-eggcracker.service")
STATE = Path("/var/lib/lumi-eggcracker")
RUNTIME = Path("/run/lumi-eggcracker")
PREFIX = "lumi-eggcracker-workload-"
SUPERVISOR = "lumi-eggcracker.service"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


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
    for path in root.iterdir():
        if path.is_symlink() or not path.is_dir() or len(path.name) != 24 or any(item not in "0123456789abcdef" for item in path.name):
            return False
        events = path / "cgroup.events"
        try:
            populated = dict(line.split(" ", 1) for line in events.read_text(encoding="ascii").splitlines()).get("populated")
        except OSError:
            return False
        if populated != "0":
            return False
    return True


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("uninstaller must run as root")
    manifest_path = STATE / "install-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit("installed manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "lumi-eggcracker.install.v3":
        raise SystemExit("installed manifest schema is invalid")
    for name, expected in manifest.get("files", {}).items():
        path = Path(name)
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise SystemExit(f"refusing uninstall because installed file drifted: {path}")
    run(["/usr/bin/systemctl", "disable", "--now", SUPERVISOR])
    if not owned_cgroups_empty() or not quarantine_empty():
        raise SystemExit("refusing uninstall with populated or uncertain Eggcracker cgroups")
    run(["/usr/bin/systemctl", "reset-failed", SUPERVISOR])
    for path in (UNIT, BIN, LIB, ETC, STATE, RUNTIME):
        if path.exists() and not path.is_symlink():
            shutil.rmtree(path) if path.is_dir() else path.unlink()
    if manifest.get("created_workload_user"):
        try:
            account = pwd.getpwnam(str(manifest["workload_user"]))
        except KeyError:
            account = None
        if account and account.pw_uid == manifest.get("workload_uid"):
            result = run(["/usr/sbin/userdel", account.pw_name])
            if result.returncode:
                raise SystemExit(result.stderr.strip() or "cannot remove created workload account")
    if manifest.get("created_workload_group"):
        try:
            group = grp.getgrnam(str(manifest.get("workload_group", "")))
        except KeyError:
            group = None
        if group:
            result = run(["/usr/sbin/groupdel", group.gr_name])
            if result.returncode:
                raise SystemExit(result.stderr.strip() or "cannot remove created workload group")
    run(["/usr/bin/systemctl", "daemon-reload"])
    print(json.dumps({"result": "UNINSTALLED"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
