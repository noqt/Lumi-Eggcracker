"""Small root watchdog that fails closed for Eggcracker-owned cgroups."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from .jsonio import JsonInputError, load_regular_json
from .records import write_atomic

HEARTBEAT_SOCKET = Path("/run/lumi-eggcracker-watchdog/heartbeat.sock")
STATE = Path("/var/lib/lumi-eggcracker")
POLICY_SCHEMA = "lumi-eggcracker.policy.v4"
UNIT_RE = re.compile(r"^lumi-eggcracker-workload-[0-9a-f]{24}\.service$")
HEARTBEAT = struct.Struct("!4sIQ")
HEARTBEAT_MAGIC = b"LEHB"
STARTUP_GRACE_SECONDS = 10.0
# A clean systemd restart briefly removes the heartbeat producer.  This is a
# fail-closed availability bound, not containment latency: normal enforcement
# remains immediate and the watchdog still kills owned workloads if recovery
# does not restore a heartbeat within this window.
HEARTBEAT_TIMEOUT_SECONDS = 30.0
INTEGRITY_INTERVAL_SECONDS = 5.0


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _events(path: Path) -> dict[str, str]:
    try:
        return dict(
            line.split(" ", 1)
            for line in (path / "cgroup.events").read_text(encoding="ascii").splitlines()
            if " " in line
        )
    except OSError as error:
        raise JsonInputError("cannot inspect watchdog cgroup") from error


def _write(path: Path, name: str, value: bytes) -> None:
    target = path / name
    if target.is_symlink() or not target.is_file():
        raise JsonInputError("watchdog cgroup control is unavailable")
    descriptor = os.open(target, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if os.write(descriptor, value) != len(value):
            raise JsonInputError("short watchdog cgroup write")
    finally:
        os.close(descriptor)


def _valid_target(path: Path) -> bool:
    return (
        path.parent == Path("/sys/fs/cgroup/system.slice")
        and UNIT_RE.fullmatch(path.name) is not None
        and path.is_dir()
        and not path.is_symlink()
    )


def _targets() -> tuple[Path, ...]:
    root = Path("/sys/fs/cgroup/system.slice")
    values = [path for path in root.glob("lumi-eggcracker-workload-*.service") if _valid_target(path)]
    quarantine = root / "lumi-eggcracker.service" / "quarantine"
    if quarantine.is_dir() and not quarantine.is_symlink() and (quarantine / "cgroup.kill").is_file():
        values.append(quarantine)
    return tuple(values)


def _kill_target(path: Path) -> dict[str, object]:
    before = time.monotonic_ns()
    frozen = False
    if (path / "cgroup.freeze").is_file():
        _write(path, "cgroup.freeze", b"1\n")
        frozen = True
    _write(path, "cgroup.kill", b"1\n")
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if _events(path).get("populated") == "0":
            return {"cgroup": str(path), "frozen": frozen, "populated": 0, "started_ns": before}
        time.sleep(0.005)
    value = _events(path)
    return {
        "cgroup": str(path),
        "frozen": frozen,
        "populated": int(value.get("populated", "1")),
        "started_ns": before,
    }


class Watchdog:
    def __init__(self, policy_path: Path) -> None:
        if os.geteuid() != 0:
            raise JsonInputError("watchdog must run as root")
        policy = load_regular_json(policy_path)
        if policy.get("schema_version") != POLICY_SCHEMA or policy.get("watchdog_socket_path") != str(
            HEARTBEAT_SOCKET
        ):
            raise JsonInputError("watchdog policy is invalid")
        self.policy = policy
        self.last_heartbeat = time.monotonic()
        self.sequence = -1
        self.started = time.monotonic()
        self.last_integrity_check = 0.0

    def _installation_is_intact(self) -> bool:
        manifest_path = STATE / "install-manifest.json"
        try:
            manifest = load_regular_json(manifest_path)
            files = manifest["files"]
            if manifest.get("schema_version") != "lumi-eggcracker.install.v4" or not isinstance(files, dict):
                return False
            for raw_path, expected in files.items():
                path = Path(raw_path)
                if not isinstance(expected, str) or path.is_symlink() or not path.is_file() or _digest(path) != expected:
                    return False
        except (JsonInputError, KeyError, OSError):
            return False
        return True

    def _receipt(self, trigger: str, targets: list[dict[str, object]]) -> None:
        value: dict[str, Any] = {
            "event_id": os.urandom(12).hex(),
            "result": "TERMINATED" if all(item["populated"] == 0 for item in targets) else "CONTAINMENT_FAILED",
            "schema_version": "lumi-eggcracker.watchdog-receipt.v1",
            "source_commit": self.policy["source_commit"],
            "targets": targets,
            "trigger": {"kind": trigger, "observed_monotonic_ns": time.monotonic_ns()},
            "version": self.policy["version"],
            "receipt_written_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        }
        write_atomic(STATE / "watchdog-receipts" / f"{value['event_id']}.json", value)

    def _fail_closed(self, trigger: str) -> None:
        values: list[dict[str, object]] = []
        for path in _targets():
            try:
                values.append(_kill_target(path))
            except (JsonInputError, OSError) as error:
                values.append({"cgroup": str(path), "error": str(error), "frozen": False, "populated": 1})
        self._receipt(trigger, values)
        subprocess.run(
            ["/usr/bin/systemctl", "kill", "--kill-who=main", "-s", "SIGKILL", "lumi-eggcracker.service"],
            capture_output=True,
            check=False,
            timeout=10,
        )

    def serve(self) -> int:
        HEARTBEAT_SOCKET.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(HEARTBEAT_SOCKET.parent, 0, 0)
        os.chmod(HEARTBEAT_SOCKET.parent, 0o700)
        if HEARTBEAT_SOCKET.exists() or HEARTBEAT_SOCKET.is_symlink():
            raise JsonInputError("watchdog heartbeat socket already exists")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            listener.bind(str(HEARTBEAT_SOCKET))
            os.chown(HEARTBEAT_SOCKET, 0, 0)
            os.chmod(HEARTBEAT_SOCKET, 0o600)
            listener.settimeout(0.25)
            while True:
                try:
                    payload, ancillary, _flags, _address = listener.recvmsg(64, socket.CMSG_SPACE(12))
                    credentials = next(
                        (
                            struct.unpack("3i", data[:12])
                            for level, kind, data in ancillary
                            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
                        ),
                        None,
                    )
                    if credentials is None or credentials[1] != 0 or len(payload) != HEARTBEAT.size:
                        continue
                    magic, version, sequence = HEARTBEAT.unpack(payload)
                    if magic != HEARTBEAT_MAGIC or version != 1 or sequence <= self.sequence:
                        continue
                    self.sequence = sequence
                    self.last_heartbeat = time.monotonic()
                except TimeoutError:
                    pass
                now = time.monotonic()
                if now - self.last_integrity_check >= INTEGRITY_INTERVAL_SECONDS:
                    self.last_integrity_check = now
                    if not self._installation_is_intact():
                        self._fail_closed("INSTALLATION_DIGEST_MISMATCH")
                        self.last_heartbeat = now
                        continue
                if now - self.started < STARTUP_GRACE_SECONDS:
                    continue
                if now - self.last_heartbeat > HEARTBEAT_TIMEOUT_SECONDS:
                    self._fail_closed("SUPERVISOR_HEARTBEAT_LOST")
                    self.last_heartbeat = time.monotonic()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eggcracker internal-watchdog")
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args(argv)
    return Watchdog(args.policy).serve()


if __name__ == "__main__":
    raise SystemExit(main())
