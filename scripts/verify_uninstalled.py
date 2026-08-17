"""Verify that a clean-install test left no Eggcracker paths behind."""

from __future__ import annotations

import sys as _bootstrap_sys

if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.flags.no_site:
    raise SystemExit(
        "privileged verifier requires /usr/bin/python3 -I -S scripts/verify_uninstalled.py"
    )

import posix as _bootstrap_posix

try:
    _bootstrap_posix.readlink(__file__)
except OSError:
    pass
else:
    raise SystemExit("refusing a symlinked privileged verifier")

import grp
import os
import pwd
import subprocess
from pathlib import Path

PATHS = (
    Path("/usr/local/lib/lumi-eggcracker"), Path("/usr/local/bin/eggcracker"),
    Path("/etc/lumi-eggcracker"), Path("/etc/systemd/system/lumi-eggcracker.service"),
    Path("/etc/systemd/system/lumi-eggcracker-watchdog.service"),
    Path("/var/lib/lumi-eggcracker"), Path("/run/lumi-eggcracker"),
    Path("/run/lumi-eggcracker-watchdog"),
)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("uninstall verifier must run as root")
    if any(path.exists() or path.is_symlink() for path in PATHS):
        raise SystemExit("Eggcracker installation path remains")
    units = subprocess.run(["/usr/bin/systemctl", "list-units", "lumi-eggcracker*", "--all", "--plain", "--no-legend"], capture_output=True, text=True, check=False)
    if units.stdout.strip():
        raise SystemExit("Eggcracker unit remains")
    try:
        pwd.getpwnam("lumi-eggcracker-workload")
    except KeyError:
        pass
    else:
        raise SystemExit("created workload account remains")
    try:
        grp.getgrnam("lumi-eggcracker-workload")
    except KeyError:
        print('{"result":"PASS"}')
        return 0
    raise SystemExit("created workload group remains")


if __name__ == "__main__":
    raise SystemExit(main())
