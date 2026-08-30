"""Transactional local upgrade and recovery for a Lumi Eggcracker install."""

from __future__ import annotations

import sys as _bootstrap_sys

if not _bootstrap_sys.flags.isolated or not _bootstrap_sys.flags.no_site:
    raise SystemExit("privileged upgrader requires /usr/bin/python3 -I -S scripts/upgrade.py")

import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_SCRIPT_ROOT = Path(__file__).resolve().parent
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))
import install as installer

STATE = installer.STATE
RUNS = STATE / "runs"
JOURNAL = STATE / "upgrade-journal.json"
BACKUPS = STATE / "upgrade-backups"
HISTORY = STATE / "upgrade-history"
ACTIVE_STATES = {"STARTING", "RUNNING"}
SUPPORTED_SOURCES = {"0.5.0", "0.8.0", "0.8.1", "0.9.0", installer.INSTALLER_VERSION}


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=60)


def atomic_bytes(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, mode)
        pending = memoryview(value)
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("upgrade write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required upgrade record is missing: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"upgrade record is not an object: {path}")
    return value


def write_journal(value: dict[str, Any]) -> None:
    atomic_bytes(JOURNAL, (json.dumps(value, sort_keys=True) + "\n").encode())


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def validate_existing(manifest: dict[str, Any], operator_name: str) -> pwd.struct_passwd:
    if manifest.get("schema_version") not in {"lumi-eggcracker.install.v4", "lumi-eggcracker.install.v5"}:
        raise RuntimeError("existing install manifest schema is unsupported")
    if manifest.get("operator") != operator_name:
        raise RuntimeError("upgrade operator does not match the installed operator")
    operator = pwd.getpwnam(operator_name)
    if manifest.get("operator_uid") != operator.pw_uid or operator.pw_uid == 0:
        raise RuntimeError("installed operator identity changed")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("existing install manifest has no file inventory")
    for raw_path, expected in files.items():
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file() or not isinstance(expected, str) or digest(path) != expected:
            raise RuntimeError(f"existing installed file drifted: {path}")
    if manifest.get("workload_uid") == 0 or not isinstance(manifest.get("workload_user"), str):
        raise RuntimeError("installed workload identity is invalid")
    account = pwd.getpwnam(manifest["workload_user"])
    if account.pw_uid != manifest["workload_uid"] or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"} or account.pw_dir != "/nonexistent":
        raise RuntimeError("installed workload identity no longer meets the contract")
    return operator


def active_runs(operator: str) -> list[dict[str, Any]]:
    result = run(["/usr/sbin/runuser", "-u", operator, "--", str(installer.BIN), "list"])
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "cannot enumerate active Eggcracker workloads")
    value = json.loads(result.stdout)
    runs = value.get("runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise TypeError("installed workload list response is invalid")
    return [item for item in runs if isinstance(item, dict) and item.get("state") in ACTIVE_STATES]


def drain(operator: str, transaction: str) -> None:
    for item in active_runs(operator):
        name = item.get("name")
        if not isinstance(name, str):
            raise TypeError("active workload name is invalid")
        receipt = Path("/run/lumi-eggcracker") / f"upgrade-{transaction}-{item.get('run_id', 'unknown')}.json"
        result = run(["/usr/sbin/runuser", "-u", operator, "--", str(installer.BIN), "kill", "--name", name, "--receipt", str(receipt)])
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"cannot contain active workload {name}")
        value = json.loads(result.stdout)
        proof = value.get("containment") if isinstance(value, dict) else None
        if value.get("result") != "TERMINATED" or not isinstance(proof, dict) or proof.get("surviving_pids"):
            raise RuntimeError(f"active workload {name} did not produce an empty containment receipt")
        receipt.unlink(missing_ok=True)


def snapshot_files(manifest: dict[str, Any], backup: Path) -> dict[str, Any]:
    files: dict[str, Any] = {}
    paths = {Path(path) for path in manifest["files"]}
    paths.update({installer.BIN, installer.LIB / "lumi-eggcracker.pyz", installer.ETC / "detector_catalogue.json", installer.ETC / "policy.json", installer.TMPFILES, installer.UNIT, installer.WATCHDOG_UNIT, STATE / "install-manifest.json"})
    target = backup / "files"
    target.mkdir(mode=0o700, parents=True)
    for index, path in enumerate(sorted(paths, key=str)):
        if path.is_symlink():
            raise RuntimeError(f"upgrade snapshot target is a symlink: {path}")
        if not path.exists():
            files[str(path)] = {"absent": True}
            continue
        if not path.is_file():
            raise RuntimeError(f"upgrade snapshot target is not a file: {path}")
        stored = target / f"{index:03d}.bin"
        shutil.copyfile(path, stored)
        metadata = path.stat()
        files[str(path)] = {"absent": False, "stored": stored.name, "mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}
    if RUNS.is_dir() and not RUNS.is_symlink():
        shutil.copytree(RUNS, backup / "runs")
    return files


def restore_snapshot(backup: Path, files: dict[str, Any]) -> None:
    for raw_path, metadata in files.items():
        path = Path(raw_path)
        if metadata.get("absent") is True:
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise RuntimeError(f"upgrade rollback target changed type: {path}")
            path.unlink(missing_ok=True)
            continue
        stored = backup / "files" / str(metadata["stored"])
        if not stored.is_file() or path.is_symlink():
            raise RuntimeError(f"upgrade backup is incomplete for {path}")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = path.parent / f".{path.name}.restore-{secrets.token_hex(6)}"
        shutil.copyfile(stored, temporary)
        os.chmod(temporary, int(metadata["mode"]))
        os.chown(temporary, int(metadata["uid"]), int(metadata["gid"]))
        os.replace(temporary, path)
    old_runs = backup / "runs"
    if old_runs.is_dir():
        if RUNS.exists() and not RUNS.is_symlink():
            shutil.rmtree(RUNS)
        shutil.copytree(old_runs, RUNS)


def migrate_runs() -> int:
    migrated = 0
    if not RUNS.is_dir() or RUNS.is_symlink():
        return migrated
    for path in sorted(RUNS.glob("*.json")):
        value = read_json(path)
        if value.get("schema_version") != "lumi-eggcracker.run.v3":
            continue
        if value.get("state") in ACTIVE_STATES:
            raise RuntimeError(f"active legacy run cannot be migrated safely: {path.name}")
        converted = dict(value)
        converted.update({"boundary": None, "network_mode": "none", "schema_version": "lumi-eggcracker.run.v4"})
        atomic_bytes(path, (json.dumps(converted, sort_keys=True) + "\n").encode())
        migrated += 1
    return migrated


def new_policy(release: dict[str, Any], operator: pwd.struct_passwd, manifest: dict[str, Any]) -> dict[str, Any]:
    workload_uid = int(manifest["workload_uid"])
    return {
        "admin_socket_path": str(installer.ADMIN_SOCKET),
        "catalogue_path": str(installer.ETC / "detector_catalogue.json"),
        "catalogue_sha256": digest(installer.ETC / "detector_catalogue.json"),
        "network_mode": "offline",
        "operator_gid": operator.pw_gid,
        "operator_socket_path": str(installer.OPERATOR_SOCKET),
        "operator_uid": operator.pw_uid,
        "query_socket_path": str(installer.QUERY_SOCKET),
        "schema_version": "lumi-eggcracker.policy.v5",
        "source_commit": release["source_commit"],
        "state_dir": str(STATE),
        "unit_prefix": "lumi-eggcracker-workload-",
        "version": release["version"],
        "watchdog_socket_path": str(installer.HEARTBEAT_SOCKET),
        "workload_gid": int(manifest.get("workload_gid", workload_uid)),
        "workload_uid": workload_uid,
    }


def replace_install(release: dict[str, Any], operator: pwd.struct_passwd, manifest: dict[str, Any], descriptor: int) -> dict[str, Any]:
    catalogue = installer.catalogue_from_artifact(Path(f"/proc/self/fd/{descriptor}"))
    os.makedirs(installer.ETC, mode=0o700, exist_ok=True)
    os.makedirs(installer.LIB, mode=0o755, exist_ok=True)
    atomic_bytes(installer.LIB / "lumi-eggcracker.pyz", os.read(descriptor, 0) or Path(f"/proc/self/fd/{descriptor}").read_bytes(), 0o755)
    atomic_bytes(installer.BIN, b"#!/bin/sh\nexec /usr/bin/python3 -I -S /usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz \"$@\"\n", 0o755)
    atomic_bytes(installer.ETC / "detector_catalogue.json", catalogue, 0o644)
    policy = new_policy(release, operator, manifest)
    atomic_bytes(installer.ETC / "policy.json", (json.dumps(policy, sort_keys=True) + "\n").encode())
    atomic_bytes(installer.TMPFILES, installer.tmpfiles(), 0o644)
    atomic_bytes(installer.UNIT, installer._SERVICE_RELEASE.replace(b"Requires=lumi-eggcracker-watchdog.service\n\n", b"Requires=lumi-eggcracker-watchdog.service\nStartLimitIntervalSec=0\n\n"), 0o644)
    atomic_bytes(installer.WATCHDOG_UNIT, installer.watchdog_service().replace(b"Before=lumi-eggcracker.service\n\n", b"Before=lumi-eggcracker.service\nStartLimitIntervalSec=0\n\n"), 0o644)
    updated = {
        "created_workload_group": bool(manifest.get("created_workload_group")),
        "created_workload_user": bool(manifest.get("created_workload_user")),
        "files": {str(path): digest(path) for path in (installer.BIN, installer.ETC / "detector_catalogue.json", installer.ETC / "policy.json", installer.LIB / "lumi-eggcracker.pyz", installer.TMPFILES, installer.UNIT, installer.WATCHDOG_UNIT)},
        "operator": operator.pw_name,
        "operator_uid": operator.pw_uid,
        "schema_version": "lumi-eggcracker.install.v5",
        "targets": [str(path) for path in installer.TARGETS],
        "workload_group": manifest.get("workload_group", installer.WORKLOAD_NAME),
        "workload_uid": manifest["workload_uid"],
        "workload_user": manifest["workload_user"],
    }
    atomic_bytes(STATE / "install-manifest.json", (json.dumps(updated, sort_keys=True) + "\n").encode())
    return updated


def socket_ready(operator_gid: int) -> bool:
    # All control sockets are created by the root supervisor.  The operator
    # sockets are group-readable/writable by the resolved operator group; the
    # admin and watchdog sockets remain root-only.  Keep uid and gid as
    # separate contract fields so a non-root operator gid is never mistaken
    # for the socket owner uid.
    contracts = (
        (installer.QUERY_SOCKET, 0o660, 0, operator_gid),
        (installer.OPERATOR_SOCKET, 0o660, 0, operator_gid),
        (installer.ADMIN_SOCKET, 0o600, 0, 0),
        (installer.HEARTBEAT_SOCKET, 0o600, 0, 0),
    )
    return all(
        path.is_socket()
        and stat.S_IMODE(path.stat().st_mode) == mode
        and path.stat().st_uid == uid
        and path.stat().st_gid == gid
        for path, mode, uid, gid in contracts
    )


def start_services(operator: str) -> None:
    operator_account = pwd.getpwnam(operator)
    installer.ensure_netns_runtime()
    for unit in ("lumi-eggcracker-watchdog.service", "lumi-eggcracker.service"):
        result = run(["/usr/bin/systemctl", "enable", "--now", unit])
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"cannot start {unit}")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if socket_ready(operator_account.pw_gid):
            doctor = run(["/usr/sbin/runuser", "-u", operator, "--", str(installer.BIN), "doctor"])
            if doctor.returncode == 0:
                return
        time.sleep(0.05)
    raise RuntimeError("upgraded supervisor did not reach a healthy socket contract")


def recover() -> int:
    journal = read_json(JOURNAL)
    backup = Path(str(journal.get("backup", "")))
    files = journal.get("files")
    if not backup.is_dir() or not isinstance(files, dict):
        raise RuntimeError("upgrade journal has no complete rollback snapshot")
    run(["/usr/bin/systemctl", "stop", "lumi-eggcracker.service"])
    run(["/usr/bin/systemctl", "stop", "lumi-eggcracker-watchdog.service"])
    restore_snapshot(backup, files)
    run(["/usr/bin/systemctl", "daemon-reload"])
    start_services(str(journal["operator"]))
    JOURNAL.unlink(missing_ok=True)
    print(json.dumps({"result": "RECOVERED", "version": journal.get("previous_version")}, sort_keys=True))
    return 0


def upgrade(args: argparse.Namespace) -> int:
    if JOURNAL.exists():
        raise RuntimeError("interrupted upgrade requires --recover before another upgrade")
    manifest = read_json(STATE / "install-manifest.json")
    previous_version = manifest.get("version")
    if not isinstance(previous_version, str):
        try:
            previous_version = str(read_json(installer.ETC / "policy.json").get("version", "0.5.0"))
        except (RuntimeError, json.JSONDecodeError):
            previous_version = "0.5.0"
    if previous_version not in SUPPORTED_SOURCES:
        raise RuntimeError(f"unsupported installed version for upgrade: {previous_version}")
    operator = validate_existing(manifest, args.operator)
    if args.artifact.is_symlink() or not args.artifact.is_file() or not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        raise RuntimeError("upgrade artifact identity is invalid")
    descriptor = os.open(args.artifact, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        release = installer.manifest_for(args.artifact, descriptor, args.expected_sha256)
        start_services(operator.pw_name)
        transaction = secrets.token_hex(8)
        backup = BACKUPS / transaction
        backup.mkdir(mode=0o700, parents=True)
        files = snapshot_files(manifest, backup)
        write_journal({"backup": str(backup), "files": files, "operator": operator.pw_name, "phase": "SNAPSHOT", "previous_version": previous_version, "target_version": release["version"], "transaction": transaction})
        drain(operator.pw_name, transaction)
        write_journal({"backup": str(backup), "files": files, "operator": operator.pw_name, "phase": "QUIESCED", "previous_version": previous_version, "target_version": release["version"], "transaction": transaction})
        run(["/usr/bin/systemctl", "stop", "lumi-eggcracker.service"])
        run(["/usr/bin/systemctl", "stop", "lumi-eggcracker-watchdog.service"])
        write_journal({"backup": str(backup), "files": files, "operator": operator.pw_name, "phase": "STOPPED", "previous_version": previous_version, "target_version": release["version"], "transaction": transaction})
        # Migrate only terminal v3 records; active legacy records were rejected
        # before mutation by migrate_runs/validate, so authority cannot widen.
        migrated = migrate_runs()
        replace_install(release, operator, manifest, descriptor)
        write_journal({"backup": str(backup), "files": files, "operator": operator.pw_name, "phase": "ACTIVATED", "previous_version": previous_version, "target_version": release["version"], "transaction": transaction, "migrated_runs": migrated})
        result = run(["/usr/bin/systemctl", "daemon-reload"])
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "systemd daemon-reload failed")
        start_services(operator.pw_name)
        HISTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_bytes(HISTORY / f"{transaction}.json", (json.dumps({"from": previous_version, "migrated_runs": migrated, "phase": "COMPLETED", "to": release["version"], "transaction": transaction}, sort_keys=True) + "\n").encode())
        JOURNAL.unlink(missing_ok=True)
        shutil.rmtree(backup)
        print(json.dumps({"result": "UPGRADED", "from": previous_version, "to": release["version"], "migrated_runs": migrated}, sort_keys=True))
        return 0
    except BaseException:
        # Leave the journal in place if rollback itself cannot complete.  The
        # explicit --recover path then has a deterministic snapshot to use.
        try:
            if JOURNAL.exists():
                journal = read_json(JOURNAL)
                backup = Path(str(journal.get("backup", "")))
                files = journal.get("files")
                if backup.is_dir() and isinstance(files, dict):
                    run(["/usr/bin/systemctl", "stop", "lumi-eggcracker.service"])
                    run(["/usr/bin/systemctl", "stop", "lumi-eggcracker-watchdog.service"])
                    restore_snapshot(backup, files)
                    run(["/usr/bin/systemctl", "daemon-reload"])
                    start_services(str(journal["operator"]))
                    JOURNAL.unlink(missing_ok=True)
                    shutil.rmtree(backup)
        except (OSError, RuntimeError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as rollback_error:
            print(f"Eggcracker upgrade rollback could not complete: {rollback_error}", file=sys.stderr)
        raise
    finally:
        os.close(descriptor)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("upgrader must run as root")
    parser = argparse.ArgumentParser()
    action = parser.add_subparsers(dest="action", required=True)
    update = action.add_parser("upgrade")
    update.add_argument("--operator", required=True)
    update.add_argument("--artifact", required=True, type=Path)
    update.add_argument("--expected-sha256", required=True)
    action.add_parser("recover")
    args = parser.parse_args()
    lifecycle_lock = installer.acquire_lifecycle_lock()
    try:
        if args.action == "recover":
            return recover()
        return upgrade(args)
    finally:
        installer.release_lifecycle_lock(lifecycle_lock)


if __name__ == "__main__":
    raise SystemExit(main())
