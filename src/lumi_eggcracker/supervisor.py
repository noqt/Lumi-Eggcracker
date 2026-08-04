"""Root-owned, fail-closed supervisor for one explicit protected workload."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__
from .adoption import AdoptionResult, contain, pidfd_available
from .approvals import approved, revoke
from .approvals import create as create_approval
from .approvals import load_all as load_approvals
from .approvals import public as public_approval
from .artifacts import ArtifactEvidence
from .artifacts import from_snapshot as artifacts_from_snapshot
from .containment import (
    capture_identity,
    events_from_fd,
    kill_path,
    validate_identity,
    verify_empty,
)
from .detectors import Catalogue, DetectionMatch, load_catalogue, match, public_catalogue
from .discovery import ProcessIdentity, ProcessSnapshot, executable_digest, scan
from .elfmarkers import RuntimeEvidence
from .elfmarkers import from_snapshot as runtime_from_snapshot
from .jsonio import JsonInputError, load_regular_json
from .observation import ObservationStore
from .records import (
    ACTIVE_STATES,
    RUN_ID,
    RUN_SCHEMA,
    command_summary,
    identity_from_run,
    load_run,
    make_receipt,
    name_path,
    run_path,
    validate_run,
    write_atomic,
)
from .watchdog import HEARTBEAT, HEARTBEAT_MAGIC, HEARTBEAT_SOCKET

MAX_FRAME = 32 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
POLICY_SCHEMA = "lumi-eggcracker.policy.v4"
QUERY_SOCKET = Path("/run/lumi-eggcracker/query.sock")
OPERATOR_SOCKET = Path("/run/lumi-eggcracker/operator.sock")
ADMIN_SOCKET = Path("/run/lumi-eggcracker/admin.sock")
LEGACY_SOCKET = Path("/run/lumi-eggcracker/control.sock")
SOCKET_ACTIONS = {
    QUERY_SOCKET: frozenset({"approvals", "detections", "doctor", "list", "status"}),
    OPERATOR_SOCKET: frozenset({"kill", "start"}),
    ADMIN_SOCKET: frozenset({"approve", "revoke"}),
}
STATE_DIR = Path("/var/lib/lumi-eggcracker")
UNIT_PREFIX = "lumi-eggcracker-workload-"
GATES_DIR = Path("/run/lumi-eggcracker/gates")
MAX_TERMINAL_RECORDS = 128
DETECTION_LIMIT = 1000
RECENT_DISCOVERY_NS = 5_000_000_000
CONTENT_SCAN_INTERVAL = 2


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
        expected = {
            "admin_socket_path",
            "catalogue_path",
            "catalogue_sha256",
            "operator_gid",
            "operator_socket_path",
            "operator_uid",
            "query_socket_path",
            "schema_version",
            "source_commit",
            "state_dir",
            "unit_prefix",
            "version",
            "watchdog_socket_path",
            "workload_gid",
            "workload_uid",
        }
        if set(policy) != expected or policy["schema_version"] != POLICY_SCHEMA:
            raise JsonInputError("supervisor policy schema is invalid")
        for key in ("operator_gid", "operator_uid", "workload_gid", "workload_uid"):
            if isinstance(policy[key], bool) or not isinstance(policy[key], int) or policy[key] < 1:
                raise JsonInputError("supervisor policy identity is invalid")
        if policy["operator_uid"] == policy["workload_uid"] or policy["workload_uid"] == 0:
            raise JsonInputError("operator and workload identities must be distinct non-root users")
        if (
            Path(policy["query_socket_path"]) != QUERY_SOCKET
            or Path(policy["operator_socket_path"]) != OPERATOR_SOCKET
            or Path(policy["admin_socket_path"]) != ADMIN_SOCKET
            or Path(policy["watchdog_socket_path"]) != HEARTBEAT_SOCKET
            or Path(policy["state_dir"]) != STATE_DIR
            or policy["unit_prefix"] != UNIT_PREFIX
        ):
            raise JsonInputError("supervisor policy path is invalid")
        if policy["version"] != __version__ or not isinstance(policy["source_commit"], str):
            raise JsonInputError("supervisor build identity is invalid")
        catalogue_path = Path(policy["catalogue_path"])
        if (
            catalogue_path != Path("/etc/lumi-eggcracker/detector_catalogue.json")
            or catalogue_path.is_symlink()
            or not catalogue_path.is_file()
        ):
            raise JsonInputError("supervisor detector catalogue path is invalid")
        self.catalogue: Catalogue = load_catalogue(
            catalogue_path.read_bytes(), expected_digest=policy["catalogue_sha256"]
        )
        self.policy = policy
        self.runs = STATE_DIR / "runs"
        self.names = STATE_DIR / "names"
        self.receipts = STATE_DIR / "receipts"
        self.approvals = STATE_DIR / "approvals"
        self.detections = STATE_DIR / "detections"
        self.quarantine_root: Path | None = None
        self.stop_event = threading.Event()
        self.locks: dict[str, threading.Lock] = {}
        self.lock_guard = threading.Lock()
        self.start_lock = threading.Lock()
        self.completed: dict[str, dict[str, Any]] = {}
        self.operations: list[str] = []  # Test-visible ordering only.
        self.discovery_lock = threading.Lock()
        self.discovery_active: set[ProcessIdentity] = set()
        self.discovery_done: dict[ProcessIdentity, int] = {}
        self.discovery_thread: threading.Thread | None = None
        self.digest_cache: dict[tuple[int, int, int, int], str] = {}
        self.observations = ObservationStore()
        self.content_scan_tick = 0
        self.last_scan_completed_ns = time.monotonic_ns()
        self.discovery_failures = 0
        self.heartbeat_sequence = 0
        self.last_heartbeat_sent = 0.0
        self.heartbeat_thread: threading.Thread | None = None

    @property
    def operator_uid(self) -> int:
        return self.policy["operator_uid"]

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10)

    def _show(self, unit: str) -> dict[str, str]:
        if not unit.startswith(UNIT_PREFIX) or not unit.endswith(".service"):
            raise JsonInputError("unit is outside Eggcracker namespace")
        result = self._run(
            [
                "/usr/bin/systemctl",
                "show",
                unit,
                "--property=ActiveState",
                "--property=ControlGroup",
                "--property=TasksMax",
            ]
        )
        if result.returncode:
            return {"ActiveState": "unknown", "ControlGroup": "", "TasksMax": ""}
        return {
            key: value
            for key, value in (
                line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
            )
        }

    def _new_lock(self, name: str) -> threading.Lock:
        with self.lock_guard:
            return self.locks.setdefault(name, threading.Lock())

    def _store(self, record: dict[str, Any]) -> None:
        record = validate_run(record)
        self.operations.append("durable-state")
        write_atomic(run_path(self.runs, record["run_id"]), record)
        pointer = name_path(self.names, record["name"])
        if record["state"] in ACTIVE_STATES:
            write_atomic(pointer, {"run_id": record["run_id"]})
        elif pointer.exists():
            try:
                current = load_regular_json(pointer)
                if current == {"run_id": record["run_id"]}:
                    pointer.unlink()
            except JsonInputError:
                raise JsonInputError("workload name index is invalid")
        self._prune_terminal_records()

    def _prune_terminal_records(self) -> None:
        records: list[tuple[int, Path]] = []
        for path in self.runs.glob("*.json"):
            try:
                value = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            if value["state"] not in ACTIVE_STATES:
                records.append((int(value["created_monotonic_ns"]), path))
        for _, path in sorted(records, reverse=True)[MAX_TERMINAL_RECORDS:]:
            path.unlink(missing_ok=True)

    def _load(self, name: str) -> dict[str, Any]:
        pointer = load_regular_json(name_path(self.names, name))
        if set(pointer) != {"run_id"}:
            raise JsonInputError("workload name index is invalid")
        record = load_run(self.runs, pointer["run_id"])
        if record["name"] != name or record["state"] not in ACTIVE_STATES:
            raise JsonInputError("workload name is unavailable")
        return record

    def _latest_by_name(self, name: str) -> dict[str, Any]:
        """Resolve a completed run only when its name is no longer active."""
        candidates: list[dict[str, Any]] = []
        for path in self.runs.glob("*.json"):
            try:
                record = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            if record["name"] == name:
                candidates.append(record)
        if not candidates:
            raise JsonInputError("workload name is unavailable")
        return max(candidates, key=lambda item: int(item["created_monotonic_ns"]))

    def _receipt_path(self, event_id: str) -> Path:
        return self.receipts / f"{event_id}.json"

    def _prepare(self) -> None:
        # Workloads need traversal only to their group-readable gate.  The
        # control socket remains a root/operator 0660 inode, so traversal does
        # not grant control-socket access or directory listing.
        for path, mode, gid in (
            (QUERY_SOCKET.parent, 0o711, self.policy["operator_gid"]),
            (GATES_DIR, 0o710, self.policy["workload_gid"]),
            (STATE_DIR, 0o700, 0),
            (self.runs, 0o700, 0),
            (self.names, 0o700, 0),
            (self.receipts, 0o700, 0),
            (self.approvals, 0o700, 0),
            (self.detections, 0o700, 0),
        ):
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            os.chown(path, 0, gid)
            os.chmod(path, mode)
        for path in (*SOCKET_ACTIONS, LEGACY_SOCKET):
            if path.exists() or path.is_symlink():
                raise JsonInputError("Eggcracker socket already exists")
        self._recover()
        self.quarantine_root = self._prepare_quarantine()
        self._scan_once(synchronous=True)

    def _prepare_quarantine(self) -> Path:
        """Create only the delegated child cgroup root of this exact service."""
        cgroup = ""
        for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
            if line.startswith("0::"):
                cgroup = line.removeprefix("0::")
                break
        if not cgroup.startswith("/system.slice/lumi-eggcracker.service"):
            raise JsonInputError("supervisor is outside its expected systemd cgroup")
        parent = Path("/sys/fs/cgroup").joinpath(*cgroup.lstrip("/").split("/"))
        if parent.is_symlink() or not parent.is_dir():
            raise JsonInputError("supervisor cgroup is unavailable")
        root = parent / "quarantine"
        if root.is_symlink():
            raise JsonInputError("quarantine root is a symlink")
        root.mkdir(mode=0o700, exist_ok=True)
        if not root.is_dir() or not all(
            (root / name).is_file() for name in ("cgroup.events", "cgroup.procs")
        ):
            raise JsonInputError("delegated quarantine cgroup is unavailable")
        return root

    def _managed(self, snapshot: ProcessSnapshot) -> bool:
        for path in self.runs.glob("*.json"):
            try:
                record = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            if record["state"] in ACTIVE_STATES and any(
                line.endswith(":" + record["cgroup"]) for line in snapshot.cgroups
            ):
                return True
        return False

    def _cached_executable_digest(self, snapshot: ProcessSnapshot) -> str:
        path = Path(snapshot.exe_path)
        metadata = path.stat(follow_symlinks=False)
        key = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        value = self.digest_cache.get(key)
        if value is None:
            value = executable_digest(path)
            self.digest_cache = {key: value}
        return value

    def _detection_path(self, event_id: str) -> Path:
        if not RUN_ID.fullmatch(event_id):
            raise JsonInputError("detection event identity is invalid")
        return self.detections / f"{event_id}.json"

    def _store_detection(self, value: dict[str, Any]) -> None:
        write_atomic(self._detection_path(value["event_id"]), value)
        records = sorted(
            self.detections.glob("*.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True
        )
        for path in records[DETECTION_LIMIT:]:
            path.unlink(missing_ok=True)

    def _detection_receipt(
        self,
        *,
        event_id: str,
        snapshot: ProcessSnapshot,
        detected: DetectionMatch,
        content: tuple[ArtifactEvidence, ...],
        runtimes: tuple[RuntimeEvidence, ...],
        first_seen_ns: int,
        qualified_ns: int,
        executable_sha256: str,
        result: AdoptionResult | None,
        error: str | None,
    ) -> dict[str, Any]:
        detector: dict[str, Any] = {
            "catalogue_schema": "lumi-eggcracker.detectors.v2",
            "detection_path": detected.path,
            "matched_evidence": list(detected.evidence),
            "matched_predicates": list(detected.evidence),
            "profile": detected.profile,
        }
        if detected.path == "CONTENT":
            detector["model"] = content[0].public() if content else {}
            detector["runtime"] = runtimes[0].public() if runtimes else {}
            detector["observation"] = {
                "first_seen_monotonic_ns": first_seen_ns,
                "qualified_monotonic_ns": qualified_ns,
            }
        value: dict[str, Any] = {
            "catalogue_sha256": self.catalogue.digest,
            "detector": detector,
            "event_id": event_id,
            "executable": {"basename": snapshot.exe_basename, "sha256": executable_sha256},
            "observed": {
                "argv_count": len(snapshot.argv),
                "argv_sha256": hashlib.sha256("\0".join(snapshot.argv).encode("utf-8")).hexdigest(),
                "pid": snapshot.identity.pid,
                "start_time": snapshot.identity.start_time,
                "uid": snapshot.uid,
            },
            "receipt_written_utc": None,
            "schema_version": "lumi-eggcracker.detection-receipt.v2",
            "source_commit": self.policy["source_commit"],
            "trigger": {"kind": "UNAPPROVED_AI_MATCH"},
            "version": __version__,
        }
        if result is None:
            value["result"] = "CONTAINMENT_FAILED"
            value["error"] = (error or "containment failed")[:160]
            return value
        value.update(
            {
                "result": "TERMINATED",
                "capture": {
                    "captured_processes": len(result.captured),
                    "fixed_point_scans": result.fixed_point_scans,
                    "quarantine_cgroup": str(result.identity.path),
                    "quarantine_device": result.identity.device,
                    "quarantine_inode": result.identity.inode,
                },
                "containment": {
                    "empty_verified_monotonic_ns": result.empty_ns,
                    "first_stop_monotonic_ns": result.first_stop_ns,
                    "kill_write_completed_monotonic_ns": result.kill_complete_ns,
                    "kill_write_started_monotonic_ns": result.kill_started_ns,
                    "primitive": "pidfd-stop+cgroup.kill",
                    "qualification_to_first_stop_ms": (result.first_stop_ns - qualified_ns)
                    / 1_000_000,
                    "root_populated": result.proof.root_populated,
                    "surviving_pids": result.proof.surviving_pids,
                    "trigger_to_empty_ms": (result.empty_ns - result.first_stop_ns) / 1_000_000,
                },
                "trigger": {
                    "kind": "UNAPPROVED_AI_MATCH",
                    "observed_monotonic_ns": result.first_stop_ns,
                },
            }
        )
        return value

    def _enforce_discovery(
        self,
        snapshot: ProcessSnapshot,
        detected: DetectionMatch,
        content: tuple[ArtifactEvidence, ...],
        runtimes: tuple[RuntimeEvidence, ...],
        first_seen_ns: int,
        qualified_ns: int,
        executable_sha256: str,
        event_id: str,
    ) -> None:
        try:
            if self.quarantine_root is None:
                raise JsonInputError("quarantine root is unavailable")
            self.operations.append("pidfd.stop")
            result = contain(snapshot.identity, self.quarantine_root, event_id)
            self.operations.append("cgroup.kill")
            receipt = self._detection_receipt(
                event_id=event_id,
                snapshot=snapshot,
                detected=detected,
                content=content,
                runtimes=runtimes,
                first_seen_ns=first_seen_ns,
                qualified_ns=qualified_ns,
                executable_sha256=executable_sha256,
                result=result,
                error=None,
            )
            receipt["receipt_written_utc"] = (
                dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
            )
            self._store_detection(receipt)
        except (JsonInputError, OSError, RuntimeError, ProcessLookupError) as error:
            receipt = self._detection_receipt(
                event_id=event_id,
                snapshot=snapshot,
                detected=detected,
                content=content,
                runtimes=runtimes,
                first_seen_ns=first_seen_ns,
                qualified_ns=qualified_ns,
                executable_sha256=executable_sha256,
                result=None,
                error=str(error),
            )
            receipt["receipt_written_utc"] = (
                dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
            )
            try:
                self._store_detection(receipt)
            except (JsonInputError, OSError):
                pass
        finally:
            with self.discovery_lock:
                self.discovery_active.discard(snapshot.identity)
                now = time.monotonic_ns()
                self.discovery_done[snapshot.identity] = now
                self.discovery_done = {
                    identity: completed
                    for identity, completed in self.discovery_done.items()
                    if now - completed <= RECENT_DISCOVERY_NS
                }

    def _scan_once(self, *, synchronous: bool = False) -> None:
        self.content_scan_tick += 1
        content_due = synchronous or self.content_scan_tick % CONTENT_SCAN_INTERVAL == 0
        try:
            approvals = load_approvals(self.approvals)
        except JsonInputError:
            approvals = []  # A corrupt approval never authorizes a matching workload.
        for snapshot in scan(
            exclude=lambda item: item.identity.pid == os.getpid() or self._managed(item)
        ):
            detected = match(self.catalogue, snapshot)
            content: tuple[ArtifactEvidence, ...] = ()
            runtimes: tuple[RuntimeEvidence, ...] = ()
            first_seen_ns = time.monotonic_ns()
            if detected is None and content_due:
                content = artifacts_from_snapshot(snapshot)
                runtimes = runtime_from_snapshot(snapshot) if content else ()
                supplied = {
                    "MODEL_CONTENT": {item.evidence_id for item in content},
                    "INFERENCE_RUNTIME": {item.evidence_id for item in runtimes},
                }
                observation = self.observations.observe(
                    snapshot.identity, set().union(*supplied.values())
                )
                first_seen_ns = observation.first_seen_ns
                # Both groups must be valid in this snapshot. Observations only
                # provide bounded timing, never stale evidence joining.
                detected = match(self.catalogue, snapshot, evidence=supplied)
            if detected is None:
                continue
            qualified_ns = time.monotonic_ns()
            try:
                executable_sha256 = self._cached_executable_digest(snapshot)
            except (JsonInputError, OSError):
                continue
            if approved(snapshot, executable_sha256, approvals):
                continue
            with self.discovery_lock:
                now = time.monotonic_ns()
                self.discovery_done = {
                    identity: completed
                    for identity, completed in self.discovery_done.items()
                    if now - completed <= RECENT_DISCOVERY_NS
                }
                if snapshot.identity in self.discovery_active or snapshot.identity in self.discovery_done:
                    continue
                self.discovery_active.add(snapshot.identity)
            event_id = os.urandom(12).hex()
            if synchronous:
                self._enforce_discovery(
                    snapshot,
                    detected,
                    content,
                    runtimes,
                    first_seen_ns,
                    qualified_ns,
                    executable_sha256,
                    event_id,
                )
            else:
                threading.Thread(
                    target=self._enforce_discovery,
                    args=(
                        snapshot,
                        detected,
                        content,
                        runtimes,
                        first_seen_ns,
                        qualified_ns,
                        executable_sha256,
                        event_id,
                    ),
                    daemon=True,
                ).start()

    def _discovery_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self._scan_once()
                self.last_scan_completed_ns = time.monotonic_ns()
                self.discovery_failures = 0
            except (JsonInputError, OSError) as error:
                self.discovery_failures += 1
                print(f"eggcracker discovery scan failed: {error}", file=sys.stderr, flush=True)
            self.stop_event.wait(0.1)

    def _heartbeat(self) -> None:
        now = time.monotonic()
        if now - self.last_heartbeat_sent < 0.25:
            return
        thread = self.discovery_thread
        if (
            thread is None
            or not thread.is_alive()
            or time.monotonic_ns() - self.last_scan_completed_ns > 5_000_000_000
            or self.discovery_failures >= 3
        ):
            return
        self.heartbeat_sequence += 1
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as value:
                value.connect(str(HEARTBEAT_SOCKET))
                value.sendall(HEARTBEAT.pack(HEARTBEAT_MAGIC, 1, self.heartbeat_sequence))
            self.last_heartbeat_sent = now
        except OSError:
            # The independent watchdog decides whether the missing heartbeat is fatal.
            pass

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            self._heartbeat()
            self.stop_event.wait(0.05)

    def _cleanup(self, unit: str) -> dict[str, Any]:
        result = self._run(["/usr/bin/systemctl", "stop", unit])
        return {
            "attempted": True,
            "systemctl_stop_returncode": result.returncode,
            "systemctl_stop_stderr": result.stderr.strip(),
        }

    def _write_receipt(self, receipt: dict[str, Any], event_id: str) -> None:
        receipt["receipt_written_utc"] = dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
        self.operations.append("durable-receipt")
        write_atomic(self._receipt_path(event_id), receipt)

    def _contain(
        self, record: dict[str, Any], trigger: str, trigger_ns: int | None = None
    ) -> dict[str, Any]:
        """Direct cgroup.kill is the first trigger-side effect; cleanup is post-proof only."""
        lock = self._new_lock(record["run_id"])
        with lock:
            if record["run_id"] in self.completed:
                return self.completed[record["run_id"]]
            identity = identity_from_run(record)
            observed = trigger_ns if trigger_ns is not None else time.monotonic_ns()
            try:
                path = validate_identity(identity)
                self.operations.append("cgroup.kill")
                kill_started, kill_completed = kill_path(path)
                empty_ns, proof = verify_empty(identity)
                if not proof.complete:
                    raise JsonInputError("owned cgroup did not become empty after direct kill")
            except Exception as error:
                record["state"] = "CONTAINMENT_FAILED"
                self._store(record)
                raise JsonInputError(f"containment failed: {error}") from error
            event_id = os.urandom(12).hex()
            receipt = make_receipt(
                record=record,
                trigger=trigger,
                trigger_ns=observed,
                kill_started_ns=kill_started,
                kill_complete_ns=kill_completed,
                empty_ns=empty_ns,
                proof=proof,
                version=__version__,
                source_commit=self.policy["source_commit"],
                event_id=event_id,
            )
            try:
                self._write_receipt(receipt, event_id)
                record["state"] = "TERMINATED"
                self._store(record)
            except Exception as error:
                record["state"] = "CONTAINED_RECEIPT_FAILED"
                self._store(record)
                raise JsonInputError(
                    f"contained but receipt persistence failed: {error}"
                ) from error
            # Cleanup is deliberately not in the enforcement or proof path.
            cleanup = self._cleanup(record["unit"])
            receipt["cleanup"] = cleanup
            try:
                write_atomic(self._receipt_path(event_id), receipt)
            except (OSError, JsonInputError):
                receipt["cleanup_update_error"] = True
            receipt["receipt_path"] = str(self._receipt_path(event_id))
            self.completed[record["run_id"]] = receipt
            return receipt

    def _complete_allowed(self, record: dict[str, Any], cgroup_events_fd: int) -> bool:
        """Only exact cgroup population, not systemd state, permits completion."""
        events = events_from_fd(cgroup_events_fd)
        if events.get("populated") != 0:
            return False
        return self._mark_completed(record)

    def _mark_completed(self, record: dict[str, Any]) -> bool:
        lock = self._new_lock(record["run_id"])
        with lock:
            if record["state"] not in ACTIVE_STATES:
                return False
            record["state"] = "COMPLETED_ALLOWED"
            self._store(record)
            return True

    def _watch_once(self, record: dict[str, Any], ready: threading.Event | None = None) -> None:
        identity = identity_from_run(record)
        path = validate_identity(identity)
        pids_fd = os.open(path / "pids.events", os.O_RDONLY | os.O_CLOEXEC)
        cgroup_fd = os.open(path / "cgroup.events", os.O_RDONLY | os.O_CLOEXEC)
        try:
            baseline = events_from_fd(pids_fd).get("max")
            if baseline is None:
                raise JsonInputError("pids.events lacks max counter")
            poller = select.poll()
            poller.register(pids_fd, select.POLLPRI)
            poller.register(cgroup_fd, select.POLLPRI)
            if ready is not None:
                ready.set()
            while not self.stop_event.is_set():
                poller.poll(250)
                current = events_from_fd(pids_fd).get("max")
                if current is None:
                    raise JsonInputError("pids.events lacks max counter")
                if current > baseline:
                    self._contain(record, "PID_LIMIT", time.monotonic_ns())
                    return
                if self._complete_allowed(record, cgroup_fd):
                    return
        finally:
            os.close(pids_fd)
            os.close(cgroup_fd)

    def _watch(self, record: dict[str, Any], ready: threading.Event | None = None) -> None:
        failure: BaseException | None = None
        for attempt in range(2):
            try:
                self._watch_once(record, ready)
                return
            except (JsonInputError, OSError, RuntimeError) as error:
                # A collected transient unit is accepted only through the same
                # exact-empty proof used after a direct cgroup kill.  It is
                # not inferred from systemd's inactive state.
                if "owned cgroup is unavailable" in str(error):
                    _empty_ns, proof = verify_empty(identity_from_run(record))
                    if proof.complete:
                        self._mark_completed(record)
                        return
                failure = error
                if attempt == 0:
                    continue
        try:
            self._contain(record, "SUPERVISOR_FAILURE", time.monotonic_ns())
        except JsonInputError:
            # A failed containment is intentionally left as a durable failure state.
            pass
        if failure is not None:
            print(f"eggcracker watcher failed closed: {failure}", file=sys.stderr, flush=True)

    def _make_gate(self, run_id: str) -> Path:
        gate = GATES_DIR / run_id
        if gate.exists() or gate.is_symlink():
            raise JsonInputError("launch gate already exists")
        os.mkfifo(gate, 0o640)
        os.chown(gate, 0, self.policy["workload_gid"])
        os.chmod(gate, 0o640)
        return gate

    def _release_gate(self, gate: Path) -> None:
        deadline = time.monotonic() + 1.5
        try:
            while True:
                try:
                    descriptor = os.open(gate, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                    break
                except OSError as error:
                    if error.errno != errno.ENXIO or time.monotonic() >= deadline:
                        raise JsonInputError("workload gate did not attach") from error
                    time.sleep(0.01)
            try:
                if os.write(descriptor, b"GO\n") != 3:
                    raise JsonInputError("short launch-gate release")
            finally:
                os.close(descriptor)
        finally:
            gate.unlink(missing_ok=True)

    def _active_exists(self) -> bool:
        for path in self.runs.glob("*.json"):
            try:
                if load_run(self.runs, path.stem)["state"] in ACTIVE_STATES:
                    return True
            except JsonInputError:
                raise JsonInputError("run record is invalid")
        return False

    def _start(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) != {"argv", "cpu_quota_percent", "max_memory_mib", "max_pids", "name"}:
            raise JsonInputError("start arguments are invalid")
        name, argv, maximum = args["name"], args["argv"], args["max_pids"]
        memory_mib, cpu_quota = args["max_memory_mib"], args["cpu_quota_percent"]
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise JsonInputError("workload name is invalid")
        summary = command_summary(argv)
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 4 <= maximum <= 4096:
            raise JsonInputError("max_pids must be from 4 to 4096")
        if isinstance(memory_mib, bool) or not isinstance(memory_mib, int) or not 64 <= memory_mib <= 131_072:
            raise JsonInputError("max_memory_mib must be from 64 to 131072")
        if isinstance(cpu_quota, bool) or not isinstance(cpu_quota, int) or not 10 <= cpu_quota <= 10_000:
            raise JsonInputError("cpu_quota_percent must be from 10 to 10000")
        with self.start_lock:
            if name_path(self.names, name).exists() or self._active_exists():
                raise JsonInputError(
                    "one protected workload is already active or name is unavailable"
                )
            run_id = os.urandom(12).hex()
            unit = f"{UNIT_PREFIX}{run_id}.service"
            gate = self._make_gate(run_id)
            result = self._run(
                [
                    "/usr/bin/systemd-run",
                    "--no-block",
                    f"--unit={unit}",
                    "--collect",
                    f"--uid={self.policy['workload_uid']}",
                    f"--gid={self.policy['workload_gid']}",
                    "--property=Type=exec",
                    "--property=ExitType=cgroup",
                    "--property=KillMode=control-group",
                    "--property=NoNewPrivileges=yes",
                    "--property=UMask=0077",
                    f"--property=TasksMax={maximum}",
                    f"--property=MemoryMax={memory_mib}M",
                    f"--property=CPUQuota={cpu_quota}%",
                    "--property=IOWeight=10",
                    "--property=LimitNOFILE=1024",
                    "--",
                    "/usr/bin/python3",
                    "/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz",
                    "_gate",
                    "--fifo",
                    str(gate),
                    "--",
                    *argv,
                ]
            )
            if result.returncode:
                gate.unlink(missing_ok=True)
                raise JsonInputError(result.stderr.strip() or "system workload launch failed")
            try:
                deadline = time.monotonic() + 2.0
                props: dict[str, str] = {}
                while time.monotonic() < deadline:
                    props = self._show(unit)
                    if props["ActiveState"] == "active" and props["ControlGroup"]:
                        break
                    time.sleep(0.01)
                if props.get("ActiveState") != "active" or not props.get("ControlGroup"):
                    raise JsonInputError("gated workload did not become active")
                identity = capture_identity(props["ControlGroup"], run_id, unit)
                record = {
                    **summary,
                    "boot_id": identity.boot_id,
                    "cgroup": identity.cgroup,
                    "cgroup_device": identity.device,
                    "cgroup_inode": identity.inode,
                    "created_monotonic_ns": time.monotonic_ns(),
                    "cpu_quota_percent": cpu_quota,
                    "max_memory_mib": memory_mib,
                    "max_pids": maximum,
                    "name": name,
                    "operator_uid": self.operator_uid,
                    "run_id": run_id,
                    "schema_version": RUN_SCHEMA,
                    "state": "STARTING",
                    "unit": unit,
                    "workload_gid": self.policy["workload_gid"],
                    "workload_uid": self.policy["workload_uid"],
                }
                self._store(record)
                ready = threading.Event()
                watcher = threading.Thread(target=self._watch, args=(record, ready), daemon=True)
                watcher.start()
                if not ready.wait(2.0):
                    raise JsonInputError("watcher did not become ready before target release")
                # The gated target has not executed yet.  The watcher has opened
                # both event descriptors and captured the PID baseline.
                self._release_gate(gate)
                if record["state"] in ACTIVE_STATES:
                    record["state"] = "RUNNING"
                    self._store(record)
                return {
                    "name": name,
                    "run_id": run_id,
                    "state": record["state"],
                    "unit": unit,
                    "cpu_quota_percent": cpu_quota,
                    "max_memory_mib": memory_mib,
                    "workload_uid": record["workload_uid"],
                }
            except Exception:
                gate.unlink(missing_ok=True)
                try:
                    # Best effort rollback after a launch failure; direct kill is still authoritative.
                    identity = capture_identity(props["ControlGroup"], run_id, unit)
                    kill_path(validate_identity(identity))
                    verify_empty(identity)
                except (JsonInputError, OSError, RuntimeError):
                    self._run(["/usr/bin/systemctl", "stop", unit])
                raise

    def _orphan_record(self, cgroup: str) -> dict[str, Any]:
        unit = Path(cgroup).name
        run_id = unit.removeprefix(UNIT_PREFIX).removesuffix(".service")
        if not RUN_ID.fullmatch(run_id):
            raise JsonInputError("orphan cgroup identity is invalid")
        identity = capture_identity(cgroup, run_id, unit)
        return {
            "argv_count": 0,
            "argv_sha256": "0" * 64,
            "boot_id": identity.boot_id,
            "cgroup": identity.cgroup,
            "cgroup_device": identity.device,
            "cgroup_inode": identity.inode,
            "created_monotonic_ns": time.monotonic_ns(),
            "cpu_quota_percent": 0,
            "executable": "<orphaned-owned-cgroup>",
            "max_pids": 0,
            "max_memory_mib": 0,
            "name": f"orphan-{run_id}",
            "operator_uid": self.operator_uid,
            "run_id": run_id,
            "schema_version": RUN_SCHEMA,
            "state": "RUNNING",
            "unit": unit,
            "workload_gid": self.policy["workload_gid"],
            "workload_uid": self.policy["workload_uid"],
        }

    def _recover(self) -> None:
        recorded_ids: set[str] = set()
        for path in self.runs.glob("*.json"):
            try:
                record = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            recorded_ids.add(record["run_id"])
            if record["state"] in ACTIVE_STATES:
                try:
                    self._contain(record, "SUPERVISOR_RESTART_FAIL_CLOSED")
                except JsonInputError as error:
                    # The transient unit may have been collected after its
                    # cgroup was proven empty but before the restart scan.
                    # It is not a live workload and must not crash recovery.
                    if "owned cgroup is unavailable" not in str(error):
                        raise
                    _empty_ns, proof = verify_empty(identity_from_run(record))
                    if not proof.complete:
                        raise
                    self._mark_completed(record)
        root = Path("/sys/fs/cgroup/system.slice")
        if not root.is_dir():
            return
        for path in root.glob(f"{UNIT_PREFIX}*.service"):
            if not path.is_dir() or path.is_symlink():
                continue
            run_id = path.name.removeprefix(UNIT_PREFIX).removesuffix(".service")
            if RUN_ID.fullmatch(run_id) and run_id not in recorded_ids:
                self._contain(
                    self._orphan_record("/system.slice/" + path.name),
                    "SUPERVISOR_RESTART_FAIL_CLOSED",
                )

    def handle(self, value: dict[str, Any]) -> dict[str, Any]:
        if (
            set(value) != {"action", "args"}
            or not isinstance(value["action"], str)
            or not isinstance(value["args"], dict)
        ):
            raise JsonInputError("request contract is invalid")
        action, args = value["action"], value["args"]
        if action == "doctor" and not args:
            available = (
                Path("/sys/fs/cgroup/cgroup.controllers").is_file()
                and "pids"
                in Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="ascii").split()
            )
            ready = available and pidfd_available() and self.quarantine_root is not None
            return {
                "autonomous_discovery": ready,
                "backend": "root-supervisor",
                "catalogue": public_catalogue(self.catalogue),
                "cgroup_v2": available,
                "pidfd": pidfd_available(),
                "result": "PASS" if ready else "UNSUPPORTED",
                "version": __version__,
                "workload_uid": self.policy["workload_uid"],
            }
        if action == "start":
            return self._start(args)
        if action == "status" and set(args) == {"name"}:
            try:
                record = self._load(args["name"])
            except JsonInputError:
                record = self._latest_by_name(args["name"])
            return {
                "name": record["name"],
                "run_id": record["run_id"],
                "state": record["state"],
                "unit": record["unit"],
                "workload_uid": record["workload_uid"],
            }
        if action == "list" and not args:
            runs = [
                self.handle({"action": "status", "args": {"name": path.stem}})
                for path in sorted(self.names.glob("*.json"))
            ]
            return {"runs": runs}
        if action == "approve" and set(args) == {"argv", "name", "uid"}:
            value = create_approval(
                self.approvals,
                name=args["name"],
                uid=args["uid"],
                argv=args["argv"],
                administrator_uid=0,
            )
            return {"approval": public_approval(value), "result": "APPROVED"}
        if action == "revoke" and set(args) == {"name"}:
            return revoke(self.approvals, args["name"])
        if action == "approvals" and not args:
            return {
                "approvals": [public_approval(value) for value in load_approvals(self.approvals)]
            }
        if action == "detections" and not args:
            values: list[dict[str, Any]] = []
            for path in sorted(self.detections.glob("*.json"), reverse=True):
                try:
                    value = load_regular_json(path)
                    values.append(
                        {
                            key: value[key]
                            for key in ("detector", "event_id", "result", "trigger", "version")
                        }
                    )
                except (JsonInputError, KeyError):
                    continue
            return {"detections": values[:100]}
        if action == "kill" and set(args) == {"name"}:
            return self._contain(self._load(args["name"]), "OPERATOR")
        raise JsonInputError("unsupported supervisor action")

    def _serve_connection(self, connection: socket.socket, path: Path) -> None:
        with connection:
            connection.settimeout(0.25)
            try:
                _pid, uid, _gid = struct.unpack(
                    "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if path == ADMIN_SOCKET:
                    if uid != 0:
                        raise JsonInputError("administrative authority is required")
                elif uid not in {0, self.operator_uid}:
                    raise JsonInputError("peer uid is not authorized")
                value = _receive(connection)
                action = value.get("action") if isinstance(value, dict) else None
                if action not in SOCKET_ACTIONS[path]:
                    raise JsonInputError("action is not permitted on this socket")
                _send(connection, {"ok": True, "value": self.handle(value)})
            except (JsonInputError, OSError, struct.error) as error:
                try:
                    _send(connection, {"ok": False, "value": str(error)})
                except OSError:
                    pass

    def serve(self) -> int:
        self._prepare()
        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
        listeners: dict[socket.socket, Path] = {}
        try:
            for path in SOCKET_ACTIONS:
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path))
                os.chown(path, 0, 0 if path == ADMIN_SOCKET else self.policy["operator_gid"])
                os.chmod(path, 0o600 if path == ADMIN_SOCKET else 0o660)
                listener.listen(32)
                listener.setblocking(False)
                listeners[listener] = path
            while not self.stop_event.is_set():
                ready, _, _ = select.select(listeners, [], [], 0.25)
                for listener in ready:
                    try:
                        connection, _ = listener.accept()
                    except BlockingIOError:
                        continue
                    self._serve_connection(connection, listeners[listener])
        finally:
            for listener in listeners:
                listener.close()
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eggcracker internal-supervisor")
    parser.add_argument("--policy", required=True, type=Path)
    args = parser.parse_args(argv)
    supervisor = Supervisor(args.policy)

    def stop(*_: object) -> None:
        supervisor.stop_event.set()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    return supervisor.serve()


if __name__ == "__main__":
    raise SystemExit(main())
