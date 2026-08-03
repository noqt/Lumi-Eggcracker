"""Verify that a clean-install test left no Nutcracker service or paths behind."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
from pathlib import Path


PATHS = (Path("/usr/local/lib/lumi-nutcracker"), Path("/usr/local/bin/nutcracker"), Path("/etc/lumi-nutcracker"), Path("/etc/systemd/system/lumi-nutcracker.service"), Path("/var/lib/lumi-nutcracker"), Path("/run/lumi-nutcracker"))


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("uninstall verifier must run as root")
    if any(path.exists() or path.is_symlink() for path in PATHS):
        raise SystemExit("Nutcracker installation path remains")
    units = subprocess.run(["/usr/bin/systemctl", "list-units", "lumi-nutcracker*", "--all", "--plain", "--no-legend"], capture_output=True, text=True, check=False)
    if units.stdout.strip():
        raise SystemExit("Nutcracker unit remains")
    try:
        pwd.getpwnam("lumi-nutcracker-workload")
    except KeyError:
        pass
    else:
        raise SystemExit("created workload account remains")
    try:
        grp.getgrnam("lumi-nutcracker-workload")
    except KeyError:
        print('{"result":"PASS"}')
        return 0
    raise SystemExit("created workload group remains")


if __name__ == "__main__":
    raise SystemExit(main())
