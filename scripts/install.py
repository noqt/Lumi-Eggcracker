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
import grp
import hashlib
import json
import os
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
STATE = Path("/var/lib/lumi-eggcracker")
RUNTIME = Path("/run/lumi-eggcracker")
QUERY_SOCKET = RUNTIME / "query.sock"
OPERATOR_SOCKET = RUNTIME / "operator.sock"
ADMIN_SOCKET = RUNTIME / "admin.sock"
WATCHDOG_RUNTIME = Path("/run/lumi-eggcracker-watchdog")
HEARTBEAT_SOCKET = WATCHDOG_RUNTIME / "heartbeat.sock"
WORKLOAD_NAME = "lumi-eggcracker-workload"
TARGETS = (LIB, BIN, ETC, UNIT, WATCHDOG_UNIT, STATE, RUNTIME, WATCHDOG_RUNTIME)
INSTALLER_VERSION = "0.6.0"
MAX_RELEASE_MANIFEST_BYTES = 32 * 1024


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
    tools = (Path("/usr/sbin/ip"), Path("/usr/sbin/nft"))
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


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("installer must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
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
    if any(path.exists() or path.is_symlink() for path in TARGETS):
        raise SystemExit("refusing pre-existing Eggcracker installation target")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if (
        not controllers.is_file()
        or "pids" not in controllers.read_text(encoding="ascii").split()
        or not autonomous_primitives_available()
        or not offline_boundary_primitives_available()
    ):
        raise SystemExit(
            "unified cgroup v2, delegated child cgroups, cgroup.kill, pidfds, iproute2 and nftables are required"
        )
    account, created_user = workload_account()
    group = grp.getgrgid(account.pw_gid)
    created_group = created_user and group.gr_name == WORKLOAD_NAME
    supplementary = set(os.getgrouplist(account.pw_name, account.pw_gid))
    if account.pw_uid in {0, operator.pw_uid} or account.pw_gid == operator.pw_gid or supplementary != {account.pw_gid}:
        cleanup([], created_user, created_group)
        raise SystemExit("workload identity must be isolated from the operator and have no supplementary groups")
    created: list[Path] = []
    try:
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
        manifest = {"created_workload_group": created_group, "created_workload_user": created_user, "files": {str(BIN): digest(BIN), str(catalogue_path): digest(catalogue_path), str(ETC / "policy.json"): digest(ETC / "policy.json"), str(LIB / "lumi-eggcracker.pyz"): digest(LIB / "lumi-eggcracker.pyz"), str(UNIT): digest(UNIT), str(WATCHDOG_UNIT): digest(WATCHDOG_UNIT)}, "operator": operator.pw_name, "operator_uid": operator.pw_uid, "schema_version": "lumi-eggcracker.install.v5", "targets": [str(path) for path in TARGETS], "workload_group": group.gr_name, "workload_uid": account.pw_uid, "workload_user": account.pw_name}
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
        print(json.dumps({"result": "INSTALLED", "service": "lumi-eggcracker.service", "workload_uid": account.pw_uid}, sort_keys=True))
        return 0
    except Exception:
        cleanup(created, created_user, created_group)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
