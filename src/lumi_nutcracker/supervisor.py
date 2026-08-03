"""Root-owned single-backend supervisor for explicit protected workloads."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__
from .containment import capture_identity, kill_path, pids_max_event, validate_identity, verify_empty
from .jsonio import JsonInputError, load_regular_json
from .records import RUN_SCHEMA, identity_from_run, load_run, make_receipt, record_path, validate_run, write_atomic


MAX_FRAME = 32 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
POLICY_SCHEMA = "lumi-nutcracker.policy.v1"
SOCKET_PATH = Path("/run/lumi-nutcracker/control.sock")
STATE_DIR = Path("/var/lib/lumi-nutcracker")
UNIT_PREFIX = "lumi-nutcracker-workload-"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise JsonInputError("duplicate JSON key")
        value[key] = item
    return value


def _receive(connection: socket.socket) -> dict[str, Any]:
    def exact(length: int) -> bytes:
        chunks: list[bytes] = []
        while length:
            chunk = connection.recv(length)
            if not chunk:
                raise JsonInputError("truncated request")
            chunks.append(chunk)
            length -= len(chunk)
        return b"".join(chunks)

    length = struct.unpack("!I", exact(4))[0]
    if not 1 <= length <= MAX_FRAME:
        raise JsonInputError("invalid request frame size")
    try:
        value = json.loads(exact(length).decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, JsonInputError) as error:
        raise JsonInputError(f"invalid request JSON: {error}") from error
    if not isinstance(value, dict):
        raise JsonInputError("request root must be an object")
    return value


def _send(connection: socket.socket, value: dict[str, Any]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise JsonInputError("response is too large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


class Supervisor:
    def __init__(self, policy_path: Path) -> None:
        if os.geteuid() != 0:
            raise JsonInputError("supervisor must run as root")
        policy = load_regular_json(policy_path)
        expected = {"operator_gid", "operator_uid", "schema_version", "socket_path", "source_commit", "state_dir", "unit_prefix", "version", "workload_gid", "workload_uid"}
        if set(policy) != expected or policy["schema_version"] != POLICY_SCHEMA:
            raise JsonInputError("supervisor policy schema is invalid")
        for key in ("operator_gid", "operator_uid", "workload_gid", "workload_uid"):
            if isinstance(policy[key], bool) or not isinstance(policy[key], int) or policy[key] < 1:
                raise JsonInputError("supervisor policy identity is invalid")
        if policy["operator_uid"] == policy["workload_uid"] or policy["workload_uid"] == 0:
            raise JsonInputError("operator and workload identities must be distinct non-root users")
        if Path(policy["socket_path"]) != SOCKET_PATH or Path(policy["state_dir"]) != STATE_DIR or policy["unit_prefix"] != UNIT_PREFIX:
            raise JsonInputError("supervisor policy path is invalid")
        if policy["version"] != __version__ or not isinstance(policy["source_commit"], str):
            raise JsonInputError("supervisor build identity is invalid")
        self.policy = policy
        self.runs = STATE_DIR / "runs"
        self.receipts = STATE_DIR / "receipts"
        self.stop_event = threading.Event()
        self.locks: dict[str, threading.Lock] = {}
        self.completed: dict[str, dict[str, Any]] = {}
        self.operations: list[str] = []  # Test-visible in-memory ordering only.

    @property
    def operator_uid(self) -> int:
        return self.policy["operator_uid"]

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10)

    def _show(self, unit: str) -> dict[str, str]:
        if not unit.startswith(UNIT_PREFIX) or not unit.endswith(".service"):
            raise JsonInputError("unit is outside Nutcracker namespace")
        result = self._run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--property=ControlGroup", "--property=TasksMax"])
        if result.returncode:
            return {"ActiveState": "inactive", "ControlGroup": "", "TasksMax": ""}
        return {key: value for key, value in (line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)}

    def _store(self, record: dict[str, Any]) -> None:
        self.operations.append("durable-state")
        write_atomic(record_path(self.runs, record["name"]), validate_run(record))

    def _load(self, name: str) -> dict[str, Any]:
        return load_run(self.runs, name)

    def _receipt_path(self, event_id: str) -> Path:
        return self.receipts / f"{event_id}.json"

    def _prepare(self) -> None:
        for path, mode, gid in ((SOCKET_PATH.parent, 0o710, self.policy["operator_gid"]), (STATE_DIR, 0o700, 0), (self.runs, 0o700, 0), (self.receipts, 0o700, 0)):
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            os.chown(path, 0, gid)
            os.chmod(path, mode)
        if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
            raise JsonInputError("control socket already exists")
        self._recover()

    def _new_lock(self, name: str) -> threading.Lock:
        if name not in self.locks:
            self.locks[name] = threading.Lock()
        return self.locks[name]

    def _cleanup(self, unit: str) -> dict[str, Any]:
        result = self._run(["/usr/bin/systemctl", "stop", unit])
        return {"systemctl_stop_attempted": True, "systemctl_stop_returncode": result.returncode, "systemctl_stop_stderr": result.stderr.strip()}

    def _complete_allowed(self, record: dict[str, Any]) -> bool:
        """Persist normal completion only after systemd reports the unit inactive."""
        lock = self._new_lock(record["name"])
        with lock:
            if record["run_id"] in self.completed or record["state"] != "RUNNING":
                return False
            if self._show(record["unit"])["ActiveState"] == "active":
                return False
            record["state"] = "COMPLETED_ALLOWED"
            self._store(record)
            return True

    def _contain(self, record: dict[str, Any], trigger: str, trigger_ns: int | None = None) -> dict[str, Any]:
        """Contain exactly one verified cgroup. First trigger-side effect is cgroup.kill."""
        lock = self._new_lock(record["name"])
        with lock:
            if record["run_id"] in self.completed:
                return self.completed[record["run_id"]]
            identity = identity_from_run(record)
            # Identity validation completes before the trigger is declared.
            path = validate_identity(identity)
            observed = trigger_ns if trigger_ns is not None else time.monotonic_ns()
            try:
                self.operations.append("cgroup.kill")
                kill_started, kill_completed = kill_path(path)
                empty_ns, proof = verify_empty(identity)
                if not proof.complete:
                    raise JsonInputError("owned cgroup did not become empty after direct kill")
            except Exception as error:
                record["state"] = "CONTAINMENT_FAILED"
                self._store(record)
                raise JsonInputError(f"containment failed: {error}") from error
            cleanup = self._cleanup(record["unit"])
            event_id = os.urandom(12).hex()
            receipt = make_receipt(record=record, trigger=trigger, trigger_ns=observed, kill_started_ns=kill_started, kill_complete_ns=kill_completed, empty_ns=empty_ns, proof=proof, version=__version__, source_commit=self.policy["source_commit"], cleanup=cleanup, event_id=event_id)
            receipt["receipt_written_utc"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
            try:
                self.operations.append("durable-receipt")
                write_atomic(self._receipt_path(event_id), receipt)
                record["state"] = "TERMINATED"
                self._store(record)
            except Exception as error:
                record["state"] = "CONTAINED_RECEIPT_FAILED"
                self._store(record)
                raise JsonInputError(f"contained but receipt persistence failed: {error}") from error
            receipt["receipt_path"] = str(self._receipt_path(event_id))
            self.completed[record["run_id"]] = receipt
            return receipt

    def _watch(self, record: dict[str, Any]) -> None:
        identity = identity_from_run(record)
        try:
            baseline = pids_max_event(identity)
            descriptor = os.open(validate_identity(identity) / "pids.events", os.O_RDONLY | os.O_CLOEXEC)
            poller = select.poll()
            poller.register(descriptor, select.POLLPRI | select.POLLERR | select.POLLIN)
            while not self.stop_event.is_set():
                if not poller.poll(250):
                    if self._complete_allowed(record):
                        return
                    continue
                # --collect may remove the cgroup between poll wake-up and the
                # pids.events read.  An already inactive unit completed normally;
                # do not turn that lifecycle race into a false containment failure.
                if self._complete_allowed(record):
                    return
                os.lseek(descriptor, 0, os.SEEK_SET)
                if pids_max_event(identity) > baseline:
                    self._contain(record, "PID_LIMIT", time.monotonic_ns())
                    return
        except Exception:
            # A lost watcher must not leave an active owned workload running.
            try:
                self._contain(record, "SUPERVISOR_RESTART_FAIL_CLOSED", time.monotonic_ns())
            except JsonInputError:
                pass
        finally:
            if "descriptor" in locals():
                os.close(descriptor)

    def _start(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) != {"argv", "max_pids", "name"}:
            raise JsonInputError("start arguments are invalid")
        name, argv, maximum = args["name"], args["argv"], args["max_pids"]
        if not isinstance(name, str) or not NAME.fullmatch(name) or record_path(self.runs, name).exists():
            raise JsonInputError("workload name is unavailable")
        if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
            raise JsonInputError("workload argv is invalid")
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 4 <= maximum <= 4096:
            raise JsonInputError("max_pids must be from 4 to 4096")
        run_id = os.urandom(12).hex()
        unit = f"{UNIT_PREFIX}{run_id}.service"
        result = self._run(["/usr/bin/systemd-run", f"--unit={unit}", "--collect", f"--uid={self.policy['workload_uid']}", f"--gid={self.policy['workload_gid']}", "--property=Type=exec", "--property=ExitType=cgroup", "--property=KillMode=control-group", "--property=NoNewPrivileges=yes", "--property=UMask=0077", f"--property=TasksMax={maximum}", "--", *argv])
        if result.returncode:
            raise JsonInputError(result.stderr.strip() or "system workload launch failed")
        deadline = time.monotonic() + 2.0
        props: dict[str, str] = {}
        while time.monotonic() < deadline:
            props = self._show(unit)
            if props["ActiveState"] == "active" and props["ControlGroup"]:
                break
            time.sleep(0.01)
        if props.get("ActiveState") != "active" or not props.get("ControlGroup"):
            self._run(["/usr/bin/systemctl", "stop", unit])
            raise JsonInputError("workload did not become active")
        identity = capture_identity(props["ControlGroup"], run_id, unit)
        record = {"argv": argv, "boot_id": identity.boot_id, "cgroup": identity.cgroup, "cgroup_device": identity.device, "cgroup_inode": identity.inode, "created_monotonic_ns": time.monotonic_ns(), "max_pids": maximum, "name": name, "operator_uid": self.operator_uid, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": unit, "workload_gid": self.policy["workload_gid"], "workload_uid": self.policy["workload_uid"]}
        self._store(record)
        threading.Thread(target=self._watch, args=(record,), daemon=True).start()
        return {"name": name, "state": "RUNNING", "unit": unit, "workload_uid": record["workload_uid"]}

    def _orphan_record(self, unit: str, cgroup: str) -> dict[str, Any]:
        run_id = unit.removeprefix(UNIT_PREFIX).removesuffix(".service")
        if not RUN_ID.fullmatch(run_id):
            raise JsonInputError("orphan unit identity is invalid")
        identity = capture_identity(cgroup, run_id, unit)
        return {"argv": ["<orphaned-owned-unit>"], "boot_id": identity.boot_id, "cgroup": identity.cgroup, "cgroup_device": identity.device, "cgroup_inode": identity.inode, "created_monotonic_ns": time.monotonic_ns(), "max_pids": 0, "name": f"orphan-{run_id}", "operator_uid": self.operator_uid, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": unit, "workload_gid": self.policy["workload_gid"], "workload_uid": self.policy["workload_uid"]}

    def _active_units(self) -> list[str]:
        result = self._run(["/usr/bin/systemctl", "list-units", f"{UNIT_PREFIX}*", "--type=service", "--all", "--plain", "--no-legend"])
        if result.returncode:
            raise JsonInputError("cannot enumerate owned units")
        return [line.split()[0] for line in result.stdout.splitlines() if line.split() and line.split()[0].startswith(UNIT_PREFIX)]

    def _recover(self) -> None:
        records: dict[str, dict[str, Any]] = {}
        for path in self.runs.glob("*.json"):
            try:
                record = load_run(self.runs, path.stem)
                records[record["unit"]] = record
            except JsonInputError:
                continue
        for unit in self._active_units():
            props = self._show(unit)
            if props["ActiveState"] != "active" or not props["ControlGroup"]:
                continue
            record = records.get(unit) or self._orphan_record(unit, props["ControlGroup"])
            self._contain(record, "SUPERVISOR_RESTART_FAIL_CLOSED")

    def handle(self, value: dict[str, Any]) -> dict[str, Any]:
        if set(value) != {"action", "args"} or not isinstance(value["action"], str) or not isinstance(value["args"], dict):
            raise JsonInputError("request contract is invalid")
        action, args = value["action"], value["args"]
        if action == "doctor" and not args:
            available = Path("/sys/fs/cgroup/cgroup.controllers").is_file() and "pids" in Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="ascii").split()
            return {"backend": "root-supervisor", "cgroup_v2": available, "result": "PASS" if available else "UNSUPPORTED", "version": __version__, "workload_uid": self.policy["workload_uid"]}
        if action == "start":
            return self._start(args)
        if action == "status" and set(args) == {"name"}:
            record = self._load(args["name"])
            if record["state"] == "RUNNING":
                self._complete_allowed(record)
            props = self._show(record["unit"])
            return {"active_state": props["ActiveState"], "name": record["name"], "state": record["state"], "unit": record["unit"], "workload_uid": record["workload_uid"]}
        if action == "list" and not args:
            return {"runs": [self.handle({"action": "status", "args": {"name": path.stem}}) for path in sorted(self.runs.glob("*.json"))]}
        if action == "kill" and set(args) == {"name"}:
            return self._contain(self._load(args["name"]), "OPERATOR")
        raise JsonInputError("unsupported supervisor action")

    def serve(self) -> int:
        self._prepare()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(SOCKET_PATH))
            os.chown(SOCKET_PATH, 0, self.policy["operator_gid"])
            os.chmod(SOCKET_PATH, 0o660)
            listener.listen(16)
            listener.settimeout(0.5)
            while not self.stop_event.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(3.0)
                    try:
                        _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if uid not in {0, self.operator_uid}:
                            raise JsonInputError("peer uid is not authorized")
                        _send(connection, {"ok": True, "value": self.handle(_receive(connection))})
                    except (JsonInputError, OSError, struct.error) as error:
                        try:
                            _send(connection, {"ok": False, "value": str(error)})
                        except OSError:
                            pass
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nutcracker internal-supervisor")
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args(argv)
    supervisor = Supervisor(args.policy)
    signal.signal(signal.SIGTERM, lambda *_: supervisor.stop_event.set())
    return supervisor.serve()


if __name__ == "__main__":
    raise SystemExit(main())
