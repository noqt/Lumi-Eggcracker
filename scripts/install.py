"""Manifest-bound installer for Lumi Eggcracker's root supervisor."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

VERSION = "0.2.0"
LIB = Path("/usr/local/lib/lumi-eggcracker")
BIN = Path("/usr/local/bin/eggcracker")
ETC = Path("/etc/lumi-eggcracker")
UNIT = Path("/etc/systemd/system/lumi-eggcracker.service")
STATE = Path("/var/lib/lumi-eggcracker")
RUNTIME = Path("/run/lumi-eggcracker")
SOCKET = RUNTIME / "control.sock"
WORKLOAD_NAME = "lumi-eggcracker-workload"
TARGETS = (LIB, BIN, ETC, UNIT, STATE, RUNTIME)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


def write_new(path: Path, data: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"refusing to overwrite {path}")
    path.write_bytes(data)
    os.chmod(path, mode)


def manifest_for(artifact: Path) -> dict[str, Any]:
    path = artifact.parent / "release-manifest.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("release manifest is missing")
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = {"artifact", "sha256", "source_archive", "source_archive_sha256", "source_commit", "version"}
    if set(value) != expected or value["artifact"] != artifact.name or value["sha256"] != digest(artifact):
        raise RuntimeError("release artifact identity does not match manifest")
    if value["version"] != VERSION or len(value["source_commit"]) != 40:
        raise RuntimeError("release manifest version or source identity is invalid")
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
    return b"""[Unit]\nDescription=Lumi Eggcracker autonomous AI runtime supervisor\nAfter=multi-user.target\nStartLimitIntervalSec=60\nStartLimitBurst=60\n\n[Service]\nType=simple\nExecStart=/usr/bin/python3 /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz _supervisor --policy /etc/lumi-eggcracker/policy.json\nRestart=always\nRestartSec=0.1\nRuntimeDirectory=lumi-eggcracker\nRuntimeDirectoryMode=0710\nUMask=0077\nNoNewPrivileges=yes\nDelegate=yes\n\n[Install]\nWantedBy=multi-user.target\n"""


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
    if not isinstance(parsed, dict) or parsed.get("schema_version") != "lumi-eggcracker.detectors.v1":
        raise RuntimeError("detector catalogue schema is invalid")
    return value


def cleanup(created: list[Path], created_user: bool, created_group: bool) -> None:
    run(["/usr/bin/systemctl", "disable", "--now", "lumi-eggcracker.service"])
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


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("installer must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    args = parser.parse_args()
    if args.artifact.is_symlink() or not args.artifact.is_file():
        raise SystemExit("artifact must be a regular file")
    release = manifest_for(args.artifact)
    operator = pwd.getpwnam(args.operator)
    if operator.pw_uid == 0:
        raise SystemExit("operator must be non-root")
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise SystemExit("refusing pre-existing Eggcracker installation target")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if not controllers.is_file() or "pids" not in controllers.read_text(encoding="ascii").split() or not autonomous_primitives_available():
        raise SystemExit("unified cgroup v2, delegated child cgroups, cgroup.kill and pidfds are required")
    account, created_user = workload_account()
    group = grp.getgrgid(account.pw_gid)
    created_group = created_user and group.gr_name == WORKLOAD_NAME
    supplementary = set(os.getgrouplist(account.pw_name, account.pw_gid))
    if account.pw_uid in {0, operator.pw_uid} or account.pw_gid == operator.pw_gid or supplementary != {account.pw_gid}:
        cleanup([], created_user, created_group)
        raise SystemExit("workload identity must be isolated from the operator and have no supplementary groups")
    created: list[Path] = []
    try:
        LIB.mkdir(mode=0o755); created.append(LIB)
        ETC.mkdir(mode=0o700); created.append(ETC)
        STATE.mkdir(mode=0o700); created.append(STATE)
        shutil.copyfile(args.artifact, LIB / "lumi-eggcracker.pyz")
        os.chmod(LIB / "lumi-eggcracker.pyz", 0o755)
        write_new(BIN, b"#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz \"$@\"\n", 0o755); created.append(BIN)
        catalogue = catalogue_from_artifact(args.artifact)
        catalogue_path = ETC / "detector_catalogue.json"
        write_new(catalogue_path, catalogue, 0o644)
        policy = {"catalogue_path": str(catalogue_path), "catalogue_sha256": hashlib.sha256(catalogue).hexdigest(), "operator_gid": operator.pw_gid, "operator_uid": operator.pw_uid, "schema_version": "lumi-eggcracker.policy.v3", "socket_path": str(SOCKET), "source_commit": release["source_commit"], "state_dir": str(STATE), "unit_prefix": "lumi-eggcracker-workload-", "version": release["version"], "workload_gid": account.pw_gid, "workload_uid": account.pw_uid}
        write_new(ETC / "policy.json", (json.dumps(policy, sort_keys=True) + "\n").encode(), 0o600)
        write_new(UNIT, service(), 0o644); created.append(UNIT)
        manifest = {"created_workload_group": created_group, "created_workload_user": created_user, "files": {str(BIN): digest(BIN), str(catalogue_path): digest(catalogue_path), str(ETC / "policy.json"): digest(ETC / "policy.json"), str(LIB / "lumi-eggcracker.pyz"): digest(LIB / "lumi-eggcracker.pyz"), str(UNIT): digest(UNIT)}, "operator": operator.pw_name, "operator_uid": operator.pw_uid, "schema_version": "lumi-eggcracker.install.v3", "targets": [str(path) for path in TARGETS], "workload_group": group.gr_name, "workload_uid": account.pw_uid, "workload_user": account.pw_name}
        write_new(STATE / "install-manifest.json", (json.dumps(manifest, sort_keys=True) + "\n").encode(), 0o600)
        checked = run(["/usr/bin/systemctl", "daemon-reload"])
        started = run(["/usr/bin/systemctl", "enable", "--now", "lumi-eggcracker.service"])
        if checked.returncode or started.returncode:
            raise RuntimeError((checked.stderr + started.stderr).strip() or "cannot start supervisor")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not SOCKET.exists():
            time.sleep(0.02)
        metadata = SOCKET.stat()
        if not SOCKET.exists() or stat.S_IMODE(metadata.st_mode) != 0o660 or metadata.st_uid != 0 or metadata.st_gid != operator.pw_gid:
            raise RuntimeError("control socket ownership contract failed")
        print(json.dumps({"result": "INSTALLED", "service": "lumi-eggcracker.service", "workload_uid": account.pw_uid}, sort_keys=True))
        return 0
    except Exception:
        cleanup(created, created_user, created_group)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
