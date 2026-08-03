"""Verify that a clean-install test left no Eggcracker paths behind."""

from __future__ import annotations

import grp
import os
import pwd
import subprocess
from pathlib import Path

PATHS = (Path("/usr/local/lib/lumi-eggcracker"), Path("/usr/local/bin/eggcracker"), Path("/etc/lumi-eggcracker"), Path("/etc/systemd/system/lumi-eggcracker.service"), Path("/var/lib/lumi-eggcracker"), Path("/run/lumi-eggcracker"))


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
