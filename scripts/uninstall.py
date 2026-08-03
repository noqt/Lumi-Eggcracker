"""Exact manifest-bound uninstaller for Lumi Nutcracker."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path


LIB = Path("/usr/local/lib/lumi-nutcracker")
BIN = Path("/usr/local/bin/nutcracker")
ETC = Path("/etc/lumi-nutcracker")
UNIT = Path("/etc/systemd/system/lumi-nutcracker.service")
STATE = Path("/var/lib/lumi-nutcracker")
RUNTIME = Path("/run/lumi-nutcracker")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("uninstaller must run as root")
    manifest_path = STATE / "install-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit("installed manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "lumi-nutcracker.install.v1":
        raise SystemExit("installed manifest schema is invalid")
    for name, expected in manifest.get("files", {}).items():
        path = Path(name)
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise SystemExit(f"refusing uninstall because installed file drifted: {path}")
    active = run(["/usr/bin/systemctl", "list-units", "lumi-nutcracker-workload-*", "--type=service", "--state=active", "--no-legend", "--no-pager"])
    if active.stdout.strip():
        raise SystemExit("refusing uninstall with active Nutcracker workloads")
    run(["/usr/bin/systemctl", "disable", "--now", "lumi-nutcracker.service"])
    run(["/usr/bin/systemctl", "reset-failed", "lumi-nutcracker.service"])
    for path in (UNIT, BIN, LIB, ETC, STATE, RUNTIME):
        if path.exists() and not path.is_symlink():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
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
        group_name = str(manifest.get("workload_group", ""))
        try:
            group = grp.getgrnam(group_name)
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
