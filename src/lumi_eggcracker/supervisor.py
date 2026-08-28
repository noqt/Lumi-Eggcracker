"""Root-owned, fail-closed supervisor for one explicit protected workload."""

from __future__ import annotations

import argparse
import array
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from . import incidents as incident_store
from .adoption import AdoptionResult, contain_many, open_pidfd, pidfd_available
from .approvals import create as create_approval
from .approvals import load_all as load_approvals
from .approvals import match_launch, revoke, stage_launch
from .approvals import public as public_approval
from .artifacts import MAX_FD_PROBES_PER_SCAN, MAX_MAP_PROBES_PER_SCAN, ArtifactEvidence
from .artifacts import from_snapshot as artifacts_from_snapshot
from .containment import (
    capture_identity,
    events_from_fd,
    kill_path,
    validate_identity,
    verify_empty,
)
from .detectors import Catalogue, DetectionMatch, load_catalogue, match, public_catalogue
from .discovery import (
    ProcessIdentity,
    ProcessSnapshot,
    argv_digest,
    executable_digest_for_identity,
    executable_metadata_for_identity,
    scan,
)
from .discovery import (
    identity as process_identity,
)
from .discovery import snapshot as process_snapshot
from .elfmarkers import (
    MAX_RUNTIME_CANDIDATES,
    OLLAMA_LAUNCHER_EVIDENCE_ID,
    VLLM_PAIR_EVIDENCE_ID,
    RuntimeEvidence,
    with_pytorch_pair,
    with_vllm_pair,
)
from .elfmarkers import from_snapshot as runtime_from_snapshot
from .execution_policy import STATE_DIR as EXEC_POLICY_DIR
from .execution_policy import create as create_execution_policy
from .execution_policy import ephemeral as ephemeral_execution_policy
from .execution_policy import load as load_execution_policy
from .execution_policy import load_all as load_execution_policies
from .execution_policy import public as public_execution_policy
from .execution_policy import revoke as revoke_execution_policy
from .jsonio import JsonInputError, load_regular_json
from .launches import authorizes as launch_authorizes
from .launches import create as create_launch_provenance
from .launches import load_all as load_launch_provenance
from .launches import provenance_path
from .observation import ObservationStore
from .offline_boundary import (
    BoundaryObserver,
    OfflineBoundary,
    primitives_available,
)
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
from .seccomp_notify import (
    allowed_target,
    notification_id_valid,
    receive_notification,
    send_response,
)
from .seccomp_notify import primitive_available as seccomp_primitive_available
from .watchdog import HEARTBEAT, HEARTBEAT_MAGIC, HEARTBEAT_SOCKET

MAX_FRAME = 32 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
POLICY_SCHEMA = "lumi-eggcracker.policy.v5"
QUERY_SOCKET = Path("/run/lumi-eggcracker/query.sock")
OPERATOR_SOCKET = Path("/run/lumi-eggcracker/operator.sock")
ADMIN_SOCKET = Path("/run/lumi-eggcracker/admin.sock")
LEGACY_SOCKET = Path("/run/lumi-eggcracker/control.sock")
SOCKET_ACTIONS = {
    QUERY_SOCKET: frozenset({"approvals", "detections", "doctor", "exec_policies", "incidents", "list", "status"}),
    OPERATOR_SOCKET: frozenset({"kill", "start"}),
    ADMIN_SOCKET: frozenset({
        "approve",
        "exec_policy_create",
        "exec_policy_revoke",
        "incident_acknowledge",
        "incident_clear",
        "incident_show",
        "revoke",
    }),
}
STATE_DIR = Path("/var/lib/lumi-eggcracker")
UNIT_PREFIX = "lumi-eggcracker-workload-"
GATES_DIR = Path("/run/lumi-eggcracker/gates")
STAGED_DIR = Path("/run/lumi-eggcracker/staged")
EXEC_DIR = Path("/run/lumi-eggcracker/exec")
DISCOVERY_PROGRESS_SCHEMA = "lumi-eggcracker.discovery-progress.v1"
DISCOVERY_PROGRESS = STATE_DIR / "discovery-progress.json"
MAX_TERMINAL_RECORDS = 128
DETECTION_LIMIT = 1000
RECENT_DISCOVERY_NS = 5_000_000_000
CONTENT_SCAN_INTERVAL = 2
MAX_CORRELATED_PROCESSES = 64
SCAN_HEALTH_TIMEOUT_NS = 1_000_000_000
MAX_DISCOVERY_FAILURES = 3
MAX_ENFORCEMENT_TASKS = 16


def policy_network_mode(policy: dict[str, Any]) -> str:
    value = policy.get("network_mode")
    return value if value == "offline" else "unsupported"


@dataclass(frozen=True)
class _EvidenceCandidate:
    snapshot: ProcessSnapshot
    content: tuple[ArtifactEvidence, ...]
    runtimes: tuple[RuntimeEvidence, ...]
    first_seen_ns: int
    fast_match: DetectionMatch | None = None


@dataclass(frozen=True)
class _DetectionGroup:
    """A minimal detection witness plus its full related containment scope."""

    witness: tuple[_EvidenceCandidate, ...]
    scope: tuple[_EvidenceCandidate, ...]
    boundary: str


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise JsonInputError("duplicate JSON key")
        value[key] = item
    return value


def _bounded_int(value: str) -> int:
    if len(value.removeprefix("-")) > 128:
        raise JsonInputError("request integer is too large")
    return int(value)


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
        value = json.loads(
            exact(length).decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_int=_bounded_int,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, JsonInputError) as error:
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
            "network_mode",
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
        if policy["version"] != __version__ or policy["network_mode"] != "offline" or not isinstance(policy["source_commit"], str):
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
        self.launches = STATE_DIR / "launches"
        self.detections = STATE_DIR / "detections"
        self.incidents = STATE_DIR / "incidents"
        self.exec_policies = EXEC_POLICY_DIR
        self.quarantine_root: Path | None = None
        self.stop_event = threading.Event()
        self.locks: dict[str, threading.Lock] = {}
        self.lock_guard = threading.Lock()
        self.start_lock = threading.Lock()
        self.approval_lock = threading.Lock()
        self.completed: dict[str, dict[str, Any]] = {}
        self.operations: list[str] = []  # Test-visible ordering only.
        self.discovery_lock = threading.Lock()
        self.discovery_active: set[ProcessIdentity] = set()
        self.discovery_done: dict[ProcessIdentity, int] = {}
        self.discovery_thread: threading.Thread | None = None
        self.active_cgroups: set[str] = set()
        self.digest_cache: dict[tuple[int, int, int, int, int], str] = {}
        self.executable_metadata: dict[ProcessIdentity, tuple[int, int]] = {}
        # Deep content/runtime inspection is keyed by stable inode metadata so
        # shared libraries and model files are parsed once per scan window,
        # rather than once for every process that maps them.  Entries are
        # bounded and naturally invalidated when a file is replaced or
        # modified.
        self.artifact_cache: dict[tuple[int, int, int, int, int], ArtifactEvidence | None] = {}
        self.runtime_cache: dict[
            tuple[int, int, int, int, int], tuple[RuntimeEvidence, ...]
        ] = {}
        self.enforcement_slots = threading.BoundedSemaphore(MAX_ENFORCEMENT_TASKS)
        self.observations = ObservationStore()
        self.artifact_fd_offsets: dict[ProcessIdentity, int] = {}
        self.artifact_map_offsets: dict[ProcessIdentity, int] = {}
        self.runtime_map_offsets: dict[ProcessIdentity, int] = {}
        self.observed_content: dict[ProcessIdentity, dict[str, ArtifactEvidence]] = {}
        self.observed_runtimes: dict[ProcessIdentity, dict[str, RuntimeEvidence]] = {}
        self.content_scan_tick = 0
        self.discovery_window_generation = 0
        self.last_scan_completed_ns = 0
        self.last_scan_duration_ns = 0
        self.discovery_failures = 0
        self.receipt_persistence_healthy = True
        self.boundary_cleanup_healthy = True
        self.incident_health_healthy = True
        self.incident_response_lock = threading.RLock()
        self.incident_sweep_lock = threading.Lock()
        self.incident_sweep_active = False
        self.boundaries: dict[str, OfflineBoundary] = {}
        self.enforcement_saturation_until_ns = 0
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
        if not hasattr(self, "active_cgroups"):
            self.active_cgroups = set()
        if record["state"] in ACTIVE_STATES:
            self.active_cgroups.add(record["cgroup"])
        else:
            self.active_cgroups.discard(record["cgroup"])
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
        if record["state"] not in ACTIVE_STATES and hasattr(self, "launches"):
            provenance_path(self.launches, record["run_id"]).unlink(missing_ok=True)
            self._clear_stage(record["run_id"])
        self._prune_terminal_records()

    @staticmethod
    def _clear_stage(run_id: str) -> None:
        if not RUN_ID.fullmatch(run_id):
            raise JsonInputError("staged launch identity is invalid")
        root = STAGED_DIR / run_id
        if not root.exists():
            return
        if root.is_symlink() or not root.is_dir():
            raise JsonInputError("staged launch root is invalid")
        children = list(root.iterdir())
        if any(
            child.name != "script.py" or child.is_symlink() or not child.is_file()
            for child in children
        ):
            raise JsonInputError("staged launch contents are invalid")
        for child in children:
            child.unlink()
        root.rmdir()

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

    def _boundary_for_record(self, record: dict[str, Any]) -> OfflineBoundary | None:
        """Resolve one exact boundary without broadening a run's ownership."""
        value = record.get("boundary")
        if value is None:
            return None
        run_id = record.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise JsonInputError("offline boundary run identity is invalid")
        boundaries = getattr(self, "boundaries", None)
        if boundaries is None:
            boundaries = self.boundaries = {}
        current = boundaries.get(run_id)
        if current is not None:
            return current
        boundary = OfflineBoundary.from_record(value)
        self.boundaries[run_id] = boundary
        return boundary

    def _teardown_boundary(self, record: dict[str, Any]) -> dict[str, Any] | None:
        boundaries = getattr(self, "boundaries", None)
        if boundaries is None:
            boundaries = self.boundaries = {}
        boundary = boundaries.get(record.get("run_id"))
        if boundary is None and record.get("boundary") is not None:
            boundary = self._boundary_for_record(record)
        if boundary is None:
            return None
        try:
            self.operations.append("boundary-teardown")
            return boundary.teardown()
        except (JsonInputError, OSError):
            self.boundary_cleanup_healthy = False
            raise
        finally:
            boundaries.pop(record.get("run_id"), None)

    def _prepare(self) -> None:
        # Workloads need traversal only to their group-readable gate.  The
        # control socket remains a root/operator 0660 inode, so traversal does
        # not grant control-socket access or directory listing.
        for path, mode, gid in (
            (QUERY_SOCKET.parent, 0o711, self.policy["operator_gid"]),
            (GATES_DIR, 0o710, self.policy["workload_gid"]),
            (STAGED_DIR, 0o711, 0),
            (EXEC_DIR, 0o710, self.policy["workload_gid"]),
            (STATE_DIR, 0o700, 0),
            (self.runs, 0o700, 0),
            (self.names, 0o700, 0),
            (self.receipts, 0o700, 0),
            (self.approvals, 0o700, 0),
            (self.launches, 0o700, 0),
            (self.detections, 0o700, 0),
            (self.incidents, 0o700, 0),
            (self.exec_policies, 0o700, 0),
        ):
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            os.chown(path, 0, gid)
            os.chmod(path, mode)
        for path in (*SOCKET_ACTIONS, LEGACY_SOCKET):
            if path.exists() or path.is_symlink():
                raise JsonInputError("Eggcracker socket already exists")
        self._reserve_discovery_window()
        # A malformed or replayed incident must not be adopted.  Keep the
        # service available for root diagnosis, but fail health and all new
        # starts closed until the store is repaired or cleared by root.
        try:
            incident_store.compact(self.incidents)
        except (JsonInputError, OSError):
            self.incident_health_healthy = False
        self._recover()
        self.quarantine_root = self._prepare_quarantine()
        self._scan_synchronously()

    def _scan_synchronously(self) -> None:
        """Complete and health-account the required startup discovery scan."""
        started = time.monotonic_ns()
        self._scan_once(synchronous=True)
        completed = time.monotonic_ns()
        self.last_scan_completed_ns = completed
        self.last_scan_duration_ns = completed - started
        self.discovery_failures = 0

    def _reserve_discovery_window(self) -> None:
        """Reserve a fair scan generation that survives supervisor recovery."""
        path = getattr(self, "discovery_progress_path", DISCOVERY_PROGRESS)
        generation = 0
        if path.exists() or path.is_symlink():
            value = load_regular_json(path)
            if (
                set(value) != {"generation", "schema_version"}
                or value.get("schema_version") != DISCOVERY_PROGRESS_SCHEMA
                or isinstance(value.get("generation"), bool)
                or not isinstance(value.get("generation"), int)
                or value["generation"] < 0
            ):
                raise JsonInputError("discovery progress state is invalid")
            generation = value["generation"]
        write_atomic(
            path,
            {
                "generation": generation + 1,
                "schema_version": DISCOVERY_PROGRESS_SCHEMA,
            },
        )
        self.discovery_window_generation = generation

    def _window_start(self, probes: int) -> int:
        # A process first observed after an expensive scan must join the
        # current fair window, not the supervisor-startup window.  The durable
        # base advances on recovery; the scan tick advances while this process
        # remains alive.
        scan_generation = getattr(self, "content_scan_tick", 0) // CONTENT_SCAN_INTERVAL
        return (
            getattr(self, "discovery_window_generation", 0) + scan_generation
        ) * probes

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
        active_cgroups = getattr(self, "active_cgroups", None)
        if active_cgroups is None:
            return False
        return any(
            line.startswith("0::") and line[3:] in active_cgroups for line in snapshot.cgroups
        )

    def _owned_cgroup(self, snapshot: ProcessSnapshot) -> str | None:
        """Return one exact Eggcracker-owned cgroup, never an ancestor."""
        prefix = "/system.slice/lumi-eggcracker.service/"
        active_selected = getattr(self, "active_cgroups", set())
        for line in snapshot.cgroups:
            if not line.startswith("0::"):
                continue
            value = line[3:]
            if value.startswith(prefix):
                relative = value.removeprefix(prefix)
                if not relative or relative.startswith("quarantine/"):
                    continue
            else:
                unit = Path(value).name
                if (
                    value not in active_selected
                    or value != f"/system.slice/{unit}"
                    or not unit.startswith(UNIT_PREFIX)
                    or not unit.endswith(".service")
                    or not RUN_ID.fullmatch(
                        unit.removeprefix(UNIT_PREFIX).removesuffix(".service")
                    )
                ):
                    continue
            path = Path("/sys/fs/cgroup").joinpath(*value.lstrip("/").split("/"))
            if (
                path.is_symlink()
                or not path.is_dir()
                or not all(
                    (path / item).is_file()
                    for item in ("cgroup.events", "cgroup.procs", "cgroup.kill")
                )
            ):
                continue
            return value
        return None

    def _related(
        self,
        left: _EvidenceCandidate,
        right: _EvidenceCandidate,
        snapshots: dict[ProcessIdentity, ProcessSnapshot],
    ) -> tuple[bool, str]:
        """Establish a live bounded relation between two evidence roles."""
        if left.snapshot.uid != self.policy["workload_uid"] or right.snapshot.uid != self.policy["workload_uid"]:
            return False, ""
        left_cgroup = self._owned_cgroup(left.snapshot)
        right_cgroup = self._owned_cgroup(right.snapshot)
        if left_cgroup is not None and left_cgroup == right_cgroup:
            return True, "owned-cgroup"
        left_parent = left.snapshot.parent
        right_parent = right.snapshot.parent
        if left_parent == right.snapshot.identity or right_parent == left.snapshot.identity:
            return True, "parent-child"
        if left_parent is not None and left_parent == right_parent:
            parent = snapshots.get(left_parent)
            if parent is not None and parent.uid == self.policy["workload_uid"]:
                return True, "sibling"
        return False, ""

    def _correlate(
        self,
        candidates: list[_EvidenceCandidate],
        snapshots: dict[ProcessIdentity, ProcessSnapshot],
    ) -> list[tuple[tuple[_EvidenceCandidate, ...], str]]:
        """Union evidence sets joined by an exact live relation.

        Component size is never interpreted as absence.  Callers reduce a
        component to a minimal complete evidence set before enforcement.
        """
        if not candidates:
            return []
        parent = list(range(len(candidates)))
        boundaries: dict[tuple[int, int], str] = {}

        def find(value: int) -> int:
            while parent[value] != value:
                parent[value] = parent[parent[value]]
                value = parent[value]
            return value

        def union(left: int, right: int, boundary: str) -> None:
            one, two = find(left), find(right)
            if one == two:
                return
            parent[two] = one
            boundaries[(min(one, two), max(one, two))] = boundary

        for left in range(len(candidates)):
            for right in range(left + 1, len(candidates)):
                related, boundary = self._related(candidates[left], candidates[right], snapshots)
                if related:
                    union(left, right, boundary)
        groups: dict[int, list[int]] = {}
        for index in range(len(candidates)):
            groups.setdefault(find(index), []).append(index)
        result: list[tuple[tuple[_EvidenceCandidate, ...], str]] = []
        for indexes in groups.values():
            values = tuple(candidates[index] for index in indexes)
            boundary_types = {
                value
                for (left, right), value in boundaries.items()
                if left in indexes or right in indexes
            }
            boundary = next(iter(boundary_types), "same-process") if len(values) > 1 else "same-process"
            result.append((values, boundary))
        return result

    def _candidate_evidence(
        self, candidates: tuple[_EvidenceCandidate, ...] | list[_EvidenceCandidate]
    ) -> dict[str, set[str]]:
        paired = with_vllm_pair(with_pytorch_pair(
            item for candidate in candidates for item in candidate.runtimes
        ))
        value = {
            "MODEL_CONTENT": {
                item.evidence_id for candidate in candidates for item in candidate.content
            },
            "MODEL_RUNTIME": {item.evidence_id for item in paired},
        }
        topology = {
            item.evidence_id
            for item in paired
            if item.evidence_id in {OLLAMA_LAUNCHER_EVIDENCE_ID, VLLM_PAIR_EVIDENCE_ID}
        }
        if topology:
            value["MODEL_TOPOLOGY"] = topology
        return value

    def _authorizes_protected_scope(
        self,
        snapshot: ProcessSnapshot,
        provenance: dict[str, Any] | None,
        *,
        profile: str | None = None,
    ) -> bool:
        """Authorize a qualified topology worker in one approved cgroup.

        A topology launcher commonly execs or forks a worker whose PID/start
        time was not present at the pre-exec gate.  The root-owned provenance
        record and exact delegated cgroup are the approval closure for that
        worker.  Direct profiles deliberately do not receive this cgroup-wide
        closure: an approved launcher must not shelter a separate direct AI
        process.  UID and cgroup identity remain mandatory, so the topology
        exception does not broaden approval to a user, directory, process name
        or wildcard.
        """
        if profile not in {"content.gguf-ollama", "content.safetensors-vllm"}:
            return False
        if provenance is None or snapshot.uid != self.policy["workload_uid"]:
            return False
        selected = f"0::{provenance['cgroup']}"
        if provenance["cgroup"] not in getattr(self, "active_cgroups", set()):
            return False
        return any(line == selected for line in snapshot.cgroups)

    def _profile_match(
        self,
        candidates: tuple[_EvidenceCandidate, ...] | list[_EvidenceCandidate],
        profile: Any,
    ) -> DetectionMatch | None:
        return match(
            Catalogue(self.catalogue.digest, (profile,)),
            candidates[0].snapshot,
            evidence=self._candidate_evidence(candidates),
        )

    def _minimal_content_groups(
        self,
        candidates: list[_EvidenceCandidate],
        scope: tuple[_EvidenceCandidate, ...],
        boundary: str,
    ) -> list[_DetectionGroup]:
        """Find bounded partial-role witnesses without broadening approval.

        Each evidence-bearing identity is used as an anchor.  A witness is
        retained only when that anchor materially contributes to one exact
        content profile.  Approval is later evaluated on the witness alone;
        containment uses the complete related component.
        """
        result: list[_DetectionGroup] = []
        seen_witnesses: set[tuple[ProcessIdentity, ...]] = set()
        ordered = sorted(candidates, key=lambda item: item.snapshot.identity)
        profiles = tuple(item for item in self.catalogue.profiles if item.path == "CONTENT")
        for anchor in ordered:
            for profile in profiles:
                selected = [anchor]
                seen_content = {item.evidence_id for item in anchor.content}
                seen_runtime = {item.evidence_id for item in anchor.runtimes}
                detected = self._profile_match(selected, profile)
                while detected is None and len(selected) < MAX_CORRELATED_PROCESSES:
                    best: _EvidenceCandidate | None = None
                    best_score: tuple[int, int] = (0, 0)
                    for candidate in ordered:
                        if candidate in selected:
                            continue
                        content_ids = {item.evidence_id for item in candidate.content}
                        runtime_ids = {item.evidence_id for item in candidate.runtimes}
                        added = len(content_ids - seen_content) + len(
                            runtime_ids - seen_runtime
                        )
                        if not added:
                            continue
                        completes = int(
                            self._profile_match([*selected, candidate], profile) is not None
                        )
                        score = (completes, added)
                        if score > best_score:
                            best = candidate
                            best_score = score
                    if best is None:
                        break
                    selected.append(best)
                    seen_content.update(item.evidence_id for item in best.content)
                    seen_runtime.update(item.evidence_id for item in best.runtimes)
                    detected = self._profile_match(selected, profile)
                if detected is None:
                    continue
                without_anchor = [item for item in selected if item is not anchor]
                if without_anchor and self._profile_match(without_anchor, profile) is not None:
                    continue
                key = tuple(sorted(item.snapshot.identity for item in selected))
                if key in seen_witnesses:
                    continue
                seen_witnesses.add(key)
                result.append(_DetectionGroup(tuple(selected), scope, boundary))
        return result

    def _content_groups(
        self,
        candidates: list[_EvidenceCandidate],
        snapshots: dict[ProcessIdentity, ProcessSnapshot],
    ) -> list[_DetectionGroup]:
        """Separate match witnesses from full related containment components."""
        result: list[_DetectionGroup] = []
        for component, boundary in self._correlate(candidates, snapshots):
            normalized: list[_EvidenceCandidate] = []
            complete: list[_EvidenceCandidate] = []
            partial: list[_EvidenceCandidate] = []
            for item in component:
                own_runtime = with_vllm_pair(with_pytorch_pair(item.runtimes))
                own_match = match(
                    self.catalogue,
                    item.snapshot,
                    evidence=self._candidate_evidence(
                        (
                            _EvidenceCandidate(
                                item.snapshot,
                                item.content,
                                tuple(own_runtime),
                                item.first_seen_ns,
                            ),
                        )
                    ),
                )
                current = _EvidenceCandidate(
                    item.snapshot,
                    item.content,
                    tuple(own_runtime),
                    item.first_seen_ns,
                    own_match,
                )
                normalized.append(current)
                (complete if own_match is not None else partial).append(current)
            scope = tuple(normalized)
            if complete:
                # All independently complete identities in one related
                # component share one enforcement task and one full scope.
                result.append(_DetectionGroup(tuple(complete), scope, boundary))
            result.extend(self._minimal_content_groups(partial, scope, boundary))
        return result

    @staticmethod
    def _discovery_excluded(snapshot: ProcessSnapshot) -> bool:
        """Exclude only the supervisor itself; a run record is not approval."""
        return snapshot.identity.pid == os.getpid()

    @staticmethod
    def _refresh_group(
        group: tuple[_EvidenceCandidate, ...],
    ) -> tuple[_EvidenceCandidate, ...]:
        """Refresh live identity facts after evidence inspection.

        A protected gate can exec between the initial process snapshot and
        descriptor-based evidence inspection without changing PID/start-time.
        Approval must use the post-exec executable and cgroup facts, never the
        stale gate snapshot.  Evidence is retained only for identities that
        still exist with the exact captured start time.
        """
        refreshed: list[_EvidenceCandidate] = []
        for candidate in group:
            current = process_snapshot(
                candidate.snapshot.identity,
                include_evidence=False,
            )
            if current is None:
                continue
            refreshed.append(
                _EvidenceCandidate(
                    current,
                    candidate.content,
                    candidate.runtimes,
                    candidate.first_seen_ns,
                    candidate.fast_match,
                )
            )
        return tuple(refreshed)

    def _cached_executable_digest(self, snapshot: ProcessSnapshot) -> str:
        metadata = executable_metadata_for_identity(snapshot.identity)
        key = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        value = self.digest_cache.get(key)
        if value is None:
            value, hashed_metadata = executable_digest_for_identity(snapshot.identity)
            if (
                hashed_metadata.st_dev,
                hashed_metadata.st_ino,
                hashed_metadata.st_size,
                hashed_metadata.st_mtime_ns,
                hashed_metadata.st_ctime_ns,
            ) != key:
                raise JsonInputError("executable changed during cached hashing")
            self.digest_cache[key] = value
            while len(self.digest_cache) > 256:
                self.digest_cache.pop(next(iter(self.digest_cache)))
        self.executable_metadata[snapshot.identity] = (metadata.st_dev, metadata.st_ino)
        return value

    def _trim_evidence_caches(self) -> None:
        for cache in (self.artifact_cache, self.runtime_cache):
            while len(cache) > 2048:
                cache.pop(next(iter(cache)))

    def _detection_path(self, event_id: str) -> Path:
        if not RUN_ID.fullmatch(event_id):
            raise JsonInputError("detection event identity is invalid")
        return self.detections / f"{event_id}.json"

    def _discovered_run_cgroups(
        self,
        snapshot: ProcessSnapshot,
        correlated: tuple[_EvidenceCandidate, ...],
    ) -> set[str]:
        values: set[str] = set()
        candidates = correlated or (
            _EvidenceCandidate(snapshot, (), (), time.monotonic_ns()),
        )
        for candidate in candidates:
            for line in candidate.snapshot.cgroups:
                if not line.startswith("0::/system.slice/"):
                    continue
                cgroup = line[3:]
                unit = Path(cgroup).name
                if (
                    cgroup == f"/system.slice/{unit}"
                    and unit.startswith(UNIT_PREFIX)
                    and unit.endswith(".service")
                    and RUN_ID.fullmatch(
                        unit.removeprefix(UNIT_PREFIX).removesuffix(".service")
                    )
                ):
                    values.add(cgroup)
        return values

    def _mark_discovered_runs_terminated(self, cgroups: set[str]) -> None:
        """Prevent the cgroup watcher from relabelling a detector kill benign."""
        if not cgroups:
            return
        for path in self.runs.glob("*.json"):
            try:
                current = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            if current["cgroup"] not in cgroups:
                continue
            lock = self._new_lock(current["run_id"])
            with lock:
                try:
                    latest = load_run(self.runs, current["run_id"])
                except JsonInputError:
                    latest = current
                if latest["state"] != "TERMINATED":
                    latest["state"] = "TERMINATED"
                    self._store(latest)

    def _discovery_containment_targets(
        self,
        group: tuple[_EvidenceCandidate, ...],
        snapshots: dict[ProcessIdentity, ProcessSnapshot],
    ) -> set[ProcessIdentity]:
        """Select evidence roots or the complete exact selected workload.

        A detector match inside an Eggcracker-launched systemd cgroup is a
        violation by that selected workload.  Include every observed process
        in that one exact owned unit so a broker, sibling, or replacement
        cannot survive while the run is recorded as terminated.  Unmanaged
        related-process matches remain limited to the evidence roots and
        their descendants.
        """
        targets = {candidate.snapshot.identity for candidate in group}
        selected_cgroups = self._discovered_run_cgroups(group[0].snapshot, group)
        if not selected_cgroups:
            # A live same-UID parent is the connector that makes direct
            # siblings one claimed workload.  Stop it before capture so it
            # cannot replenish a sibling while the component is moved.
            parents = {
                candidate.snapshot.parent
                for candidate in group
                if candidate.snapshot.parent is not None
            }
            for parent in parents:
                connector = snapshots.get(parent)
                if connector is not None and connector.uid == self.policy["workload_uid"]:
                    related_children = sum(
                        candidate.snapshot.parent == parent for candidate in group
                    )
                    if related_children >= 2:
                        targets.add(parent)
            return targets
        for snapshot in snapshots.values():
            if any(
                line.startswith("0::") and line[3:] in selected_cgroups
                for line in snapshot.cgroups
            ):
                targets.add(snapshot.identity)
        return targets

    def _store_detection(self, value: dict[str, Any]) -> None:
        try:
            write_atomic(self._detection_path(value["event_id"]), value)
            records = sorted(
                self.detections.glob("*.json"),
                key=lambda item: item.stat().st_mtime_ns,
                reverse=True,
            )
            for path in records[DETECTION_LIMIT:]:
                path.unlink(missing_ok=True)
        except (JsonInputError, OSError):
            # Containment has already happened when this is called from the
            # autonomous enforcement path.  A missing durable empty-state
            # receipt must therefore make health fail closed until a root
            # operator repairs storage and restarts the supervisor.
            self.receipt_persistence_healthy = False
            raise

    def _incident_values(self) -> list[dict[str, Any]]:
        root = getattr(self, "incidents", None)
        if root is None:
            return []
        if not getattr(self, "incident_health_healthy", True):
            raise JsonInputError("incident store is unavailable; root recovery is required")
        lock = getattr(self, "incident_response_lock", None)
        try:
            if lock is None:
                return incident_store.compact(root)
            with lock:
                return incident_store.compact(root)
        except (JsonInputError, OSError):
            self.incident_health_healthy = False
            raise

    def _incident_status(self) -> dict[str, Any]:
        root = getattr(self, "incidents", None)
        if root is None:
            return {"healthy": True, "count": 0, "active": 0, "lockdown": False}
        try:
            values = self._incident_values()
        except (JsonInputError, OSError):
            return {"healthy": False, "count": 0, "active": 0, "lockdown": True}
        active = incident_store.active(values)
        return {
            "healthy": True,
            "count": len(values),
            "active": len(active),
            "lockdown": bool(active),
        }

    def _incident_block_for_start(self, argv_sha256: str) -> dict[str, Any] | None:
        values = self._incident_values()
        return incident_store.find_match(
            values,
            argv_sha256=argv_sha256,
            uid=self.policy["workload_uid"],
        )

    def _incident_match_for_candidate(
        self,
        snapshot: ProcessSnapshot,
        detected: DetectionMatch,
        executable_sha256: str | None,
    ) -> dict[str, Any] | None:
        if not getattr(self, "incident_health_healthy", True):
            return None
        try:
            values = self._incident_values()
        except (JsonInputError, OSError):
            return None
        return incident_store.find_match(
            values,
            argv_sha256=argv_digest(snapshot.argv),
            uid=snapshot.uid,
            executable_sha256=executable_sha256,
            profile=detected.profile,
        )

    def _approval_identity(self, run_id: str) -> dict[str, Any] | None:
        try:
            values = load_launch_provenance(self.launches)
        except (JsonInputError, OSError):
            return None
        value = next((item for item in values if item["run_id"] == run_id), None)
        if value is None:
            return None
        return {
            "argv_sha256": value["argv_sha256"],
            "bound_input_sha256": list(value["bound_input_sha256"]),
            "created_monotonic_ns": value["approval_created_monotonic_ns"],
            "executable_sha256": value["executable_sha256"],
            "name": value["approval_name"],
            "uid": value["uid"],
        }

    def _revoke_exact_approval(self, approval: dict[str, Any] | None) -> bool:
        if approval is None:
            return True
        values = load_approvals(self.approvals)
        matches = [
            item
            for item in values
            if item["name"] == approval["name"]
            and item["created_monotonic_ns"] == approval["created_monotonic_ns"]
            and item["argv_sha256"] == approval["argv_sha256"]
            and item["executable_sha256"] == approval["executable_sha256"]
            and item["uid"] == approval["uid"]
        ]
        if not matches:
            # The exact record may already have been revoked by root.  Never
            # delete a same-named but different approval.
            if any(item["name"] == approval["name"] for item in values):
                raise JsonInputError("affected approval identity no longer matches")
            return True
        revoke(self.approvals, approval["name"])
        return True

    @staticmethod
    def _incident_match(
        receipt: dict[str, Any],
        record: dict[str, Any] | None,
        approval: dict[str, Any] | None,
    ) -> dict[str, Any]:
        observed = receipt.get("observed") if isinstance(receipt.get("observed"), dict) else {}
        executable = receipt.get("executable") if isinstance(receipt.get("executable"), dict) else {}
        argv_sha256 = (
            record.get("argv_sha256")
            if record is not None
            else observed.get("argv_sha256")
        )
        executable_sha256 = (
            approval.get("executable_sha256")
            if approval is not None
            else executable.get("sha256")
        )
        uid = record.get("workload_uid") if record is not None else observed.get("uid")
        if not isinstance(argv_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", argv_sha256):
            raise JsonInputError("incident launch identity is unavailable")
        if not isinstance(executable_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", executable_sha256):
            executable_sha256 = "0" * 64
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            raise JsonInputError("incident workload identity is unavailable")
        detector = receipt.get("detector") if isinstance(receipt.get("detector"), dict) else {}
        profile = detector.get("profile")
        return {
            "argv_sha256": argv_sha256,
            "executable_sha256": executable_sha256,
            "profile": profile if isinstance(profile, str) else None,
            "uid": uid,
        }

    @staticmethod
    def _incident_workload(record: dict[str, Any] | None, receipt: dict[str, Any]) -> dict[str, Any]:
        if record is not None:
            return {
                "boot_id": record["boot_id"],
                "cgroup": record["cgroup"],
                "cgroup_device": record["cgroup_device"],
                "cgroup_inode": record["cgroup_inode"],
                "run_id": record["run_id"],
                "unit": record["unit"],
                "uid": record["workload_uid"],
            }
        workload = receipt.get("workload")
        if not isinstance(workload, dict):
            raise JsonInputError("incident workload receipt identity is unavailable")
        return {
            "boot_id": workload["boot_id"],
            "cgroup": workload["cgroup"],
            "cgroup_device": workload["cgroup_device"],
            "cgroup_inode": workload["cgroup_inode"],
            "run_id": workload["run_id"],
            "unit": workload["unit"],
            "uid": workload["workload_uid"],
        }

    def _incident_sweep(self, incident_id: str) -> None:
        lock = getattr(self, "incident_sweep_lock", None)
        if lock is None:
            return
        # A synchronous sweep can discover another exact match.  Its
        # containment response re-enters this method on the same worker while
        # the outer sweep owns the non-reentrant lock; return before attempting
        # to acquire it rather than self-deadlocking the enforcement worker.
        if getattr(self, "incident_sweep_active", False):
            return
        with lock:
            if getattr(self, "incident_sweep_active", False):
                return
            self.incident_sweep_active = True
            try:
                with self.incident_response_lock:
                    values = self._incident_values()
                    current = next(item for item in values if item["incident_id"] == incident_id)
                    recurrence = dict(current["recurrence"])
                    recurrence["sweep_count"] += 1
                    incident_store.update(self.incidents, current, recurrence=recurrence)
                self.operations.append("incident-sweep")
                # Reuse the existing bounded discovery and containment path.
                # Nested response calls link receipts to this incident but do
                # not recurse into another sweep while this flag is set.
                self._scan_once(synchronous=True)
            except (JsonInputError, OSError, RuntimeError):
                self.incident_health_healthy = False
            finally:
                self.incident_sweep_active = False

    def _post_containment_response(
        self,
        receipt: dict[str, Any],
        *,
        record: dict[str, Any] | None = None,
        approval: dict[str, Any] | None = None,
    ) -> None:
        trigger_value = receipt.get("trigger")
        trigger = trigger_value.get("kind") if isinstance(trigger_value, dict) else None
        if not isinstance(trigger, str) or not (
            trigger in {"NETWORK_BOUNDARY", "EXECUTION_BOUNDARY"}
            or trigger.startswith("UNAPPROVED_")
        ):
            return
        root = getattr(self, "incidents", None)
        if root is None:
            return
        if receipt.get("result") != "TERMINATED":
            return
        try:
            sweep_id: str | None = None
            with self.incident_response_lock:
                match = self._incident_match(receipt, record, approval)
                values = self._incident_values()
                existing = incident_store.find_match(
                    values,
                    argv_sha256=match["argv_sha256"],
                    uid=match["uid"],
                    executable_sha256=match["executable_sha256"],
                    profile=match["profile"],
                )
                if existing is not None:
                    incident_store.link(root, existing, receipt)
                    self.operations.append("incident-state")
                    return
                detector = receipt.get("detector") if isinstance(receipt.get("detector"), dict) else {}
                evidence = detector.get("matched_evidence")
                if not isinstance(evidence, list):
                    evidence = []
                incident = incident_store.create(
                    root,
                    receipt=receipt,
                    policy=self.policy,
                    catalogue_sha256=self.catalogue.digest,
                    source_commit=self.policy["source_commit"],
                    version=__version__,
                    trigger=trigger,
                    profile=match["profile"],
                    evidence=[item for item in evidence if isinstance(item, str)],
                    match=match,
                    workload=self._incident_workload(record, receipt),
                    approval=approval,
                )
                self.operations.append("incident-state")
                revoked = self._revoke_exact_approval(approval)
                response = dict(incident["response"])
                response["approval_revoked"] = revoked
                response["completed"] = revoked
                response["response_completed_monotonic_ns"] = time.monotonic_ns()
                incident = incident_store.update(root, incident, response=response)
                # The sweep performs a synchronous discovery pass.  Run it
                # after releasing incident_response_lock: a nested match can
                # itself complete containment and call this method, and a
                # non-reentrant lock here would deadlock the enforcement
                # worker while other detections wait for their receipts.
                sweep_id = incident["incident_id"]
            if sweep_id is not None:
                self._incident_sweep(sweep_id)
        except (JsonInputError, OSError, RuntimeError):
            # The kill and original receipt already succeeded.  A response
            # persistence fault fails health closed and stops future starts;
            # it never turns a successful containment into a false failure.
            self.incident_health_healthy = False

    def _detection_sort_key(self, path: Path) -> tuple[int, str]:
        try:
            value = load_regular_json(path)
            observed = value.get("trigger", {}).get("observed_monotonic_ns", 0)
            if isinstance(observed, int) and observed >= 0:
                return observed, path.name
        except (JsonInputError, OSError):
            pass
        return 0, path.name

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
        executable_sha256: str | None,
        result: AdoptionResult | None,
        error: str | None,
        correlated: tuple[_EvidenceCandidate, ...] = (),
        boundary_type: str = "same-process",
    ) -> dict[str, Any]:
        trigger_kind = {
            "content.safetensors-pytorch": "UNAPPROVED_SAFETENSORS_PYTORCH",
            "content.safetensors-vllm": "UNAPPROVED_VLLM_SAFETENSORS",
            "content.gguf-ollama": "UNAPPROVED_OLLAMA_GGUF",
        }.get(detected.profile, "UNAPPROVED_AI_MATCH")
        detector: dict[str, Any] = {
            "catalogue_schema": "lumi-eggcracker.detectors.v3",
            "detection_path": detected.path,
            "matched_evidence": list(detected.evidence),
            "matched_predicates": list(detected.evidence),
            "profile": detected.profile,
        }
        if detected.path == "CONTENT":
            model = next((item for item in content if item.evidence_id == "safetensors-v1"), None)
            runtime = next(
                (item for item in runtimes if item.evidence_id == "pytorch-bridge-aten-pair-pinned-cpu"),
                None,
            )
            detector["model"] = (model or (content[0] if content else None)).public() if (model or content) else {}
            detector["runtime"] = (runtime or (runtimes[0] if runtimes else None)).public() if (runtime or runtimes) else {}
            detector["observation"] = {
                "first_seen_monotonic_ns": first_seen_ns,
                "qualified_monotonic_ns": qualified_ns,
            }
        executable_record: dict[str, Any] = {
            "basename": snapshot.exe_basename,
            "sha256": executable_sha256,
        }
        if executable_sha256 is None:
            executable_record["digest_status"] = "UNAVAILABLE"
        value: dict[str, Any] = {
            "catalogue_sha256": self.catalogue.digest,
            "detector": detector,
            "event_id": event_id,
            "executable": executable_record,
            "observed": {
                "argv_count": len(snapshot.argv),
                "argv_sha256": argv_digest(snapshot.argv),
                "argv_complete": snapshot.argv_complete,
                "pid": snapshot.identity.pid,
                "start_time": snapshot.identity.start_time,
                "uid": snapshot.uid,
            },
            "receipt_written_utc": None,
            "schema_version": "lumi-eggcracker.detection-receipt.v2",
            "source_commit": self.policy["source_commit"],
            "trigger": {"kind": trigger_kind},
            "version": __version__,
        }
        if result is not None:
            quarantine = str(result.identity.path)
            value["workload"] = {
                "boot_id": f"detection-{event_id}",
                "cgroup": quarantine,
                "cgroup_device": result.identity.device,
                "cgroup_inode": result.identity.inode,
                "run_id": event_id,
                "unit": Path(quarantine).name,
                "workload_uid": snapshot.uid,
            }
        evidence_roles: list[dict[str, Any]] = []
        for candidate in correlated or (
            _EvidenceCandidate(snapshot, content, runtimes, first_seen_ns, detected),
        ):
            roles: list[str] = []
            if candidate.content:
                roles.append("MODEL_CONTENT")
            if candidate.runtimes:
                roles.append("MODEL_RUNTIME")
            if self._candidate_evidence((candidate,)).get("MODEL_TOPOLOGY"):
                roles.append("MODEL_TOPOLOGY")
            evidence_roles.append(
                {
                    "pid": candidate.snapshot.identity.pid,
                    "start_time": candidate.snapshot.identity.start_time,
                    "uid": candidate.snapshot.uid,
                    "parent": (
                        {
                            "pid": candidate.snapshot.parent.pid,
                            "start_time": candidate.snapshot.parent.start_time,
                        }
                        if candidate.snapshot.parent is not None
                        else None
                    ),
                    "roles": roles,
                }
            )
        value["correlation"] = {
            "boundary": boundary_type,
            "evidence_bearing": evidence_roles,
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
                    "kind": trigger_kind,
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
        executable_sha256: str | None,
        event_id: str,
        pidfd: int | None = None,
        targets: set[ProcessIdentity] | None = None,
        correlated: tuple[_EvidenceCandidate, ...] = (),
        boundary_type: str = "same-process",
    ) -> None:
        containment_started = False
        managed_targets = targets or {snapshot.identity}
        discovered_run_cgroups = self._discovered_run_cgroups(snapshot, correlated)
        try:
            if self.quarantine_root is None:
                raise JsonInputError("quarantine root is unavailable")
            self.operations.append("pidfd.stop")
            containment_started = True
            target_set = targets or {snapshot.identity}
            result = contain_many(
                target_set,
                self.quarantine_root,
                event_id,
                pidfds={snapshot.identity: pidfd} if pidfd is not None else None,
            )
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
                correlated=correlated,
                boundary_type=boundary_type,
            )
            receipt["receipt_written_utc"] = (
                dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
            )
            self._store_detection(receipt)
            self._post_containment_response(receipt)
            self._mark_discovered_runs_terminated(discovered_run_cgroups)
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
                correlated=correlated,
                boundary_type=boundary_type,
            )
            receipt["receipt_written_utc"] = (
                dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")
            )
            try:
                self._store_detection(receipt)
            except (JsonInputError, OSError):
                pass
        finally:
            # ``contain`` owns and closes a handed-off pidfd.  If the
            # precondition above prevents the hand-off, close it here.
            if pidfd is not None and not containment_started:
                os.close(pidfd)
            with self.discovery_lock:
                self.discovery_active.difference_update(managed_targets)
                now = time.monotonic_ns()
                for identity in managed_targets:
                    self.discovery_done[identity] = now
                self.discovery_done = {
                    identity: completed
                    for identity, completed in self.discovery_done.items()
                    if now - completed <= RECENT_DISCOVERY_NS
                }

    def _scan_once(self, *, synchronous: bool = False) -> None:
        self.content_scan_tick += 1
        content_due = synchronous or self.content_scan_tick % CONTENT_SCAN_INTERVAL == 0
        snapshots = scan(
            exclude=self._discovery_excluded,
            include_evidence=content_due,
        )
        snapshot_map = {item.identity: item for item in snapshots}
        live_identities = set(snapshot_map)
        for cache in (
            getattr(self, "artifact_fd_offsets", {}),
            getattr(self, "artifact_map_offsets", {}),
            getattr(self, "runtime_map_offsets", {}),
            getattr(self, "observed_content", {}),
            getattr(self, "observed_runtimes", {}),
        ):
            for identity in tuple(cache):
                if identity not in live_identities:
                    cache.pop(identity, None)
        candidates: list[_EvidenceCandidate] = []
        for snapshot in snapshots:
            fast_match = match(self.catalogue, snapshot)
            content: tuple[ArtifactEvidence, ...] = ()
            runtimes: tuple[RuntimeEvidence, ...] = ()
            first_seen_ns = time.monotonic_ns()
            if content_due:
                artifact_offsets = getattr(self, "artifact_fd_offsets", None)
                if artifact_offsets is None:
                    self.artifact_fd_offsets = {}
                    artifact_offsets = self.artifact_fd_offsets
                runtime_offsets = getattr(self, "runtime_map_offsets", None)
                if runtime_offsets is None:
                    self.runtime_map_offsets = {}
                    runtime_offsets = self.runtime_map_offsets
                artifact_map_offsets = getattr(self, "artifact_map_offsets", None)
                if artifact_map_offsets is None:
                    self.artifact_map_offsets = {}
                    artifact_map_offsets = self.artifact_map_offsets
                artifact_fd_start = artifact_offsets.get(
                    snapshot.identity,
                    self._window_start(MAX_FD_PROBES_PER_SCAN),
                )
                artifact_map_start = artifact_map_offsets.get(
                    snapshot.identity,
                    self._window_start(MAX_MAP_PROBES_PER_SCAN),
                )
                content_now = artifacts_from_snapshot(
                    snapshot,
                    cache=self.artifact_cache,
                    fd_start_index=artifact_fd_start,
                    map_start_index=artifact_map_start,
                )
                artifact_offsets[snapshot.identity] = (
                    artifact_fd_start + MAX_FD_PROBES_PER_SCAN
                )
                artifact_map_offsets[snapshot.identity] = (
                    artifact_map_start + MAX_MAP_PROBES_PER_SCAN
                )
                # Runtime evidence is intentionally collected independently so
                # it can be correlated with content held by a bounded peer.
                runtime_start = runtime_offsets.get(
                    snapshot.identity,
                    self._window_start(MAX_RUNTIME_CANDIDATES),
                )
                runtimes_now = runtime_from_snapshot(
                    snapshot,
                    cache=self.runtime_cache,
                    start_index=runtime_start,
                )
                runtime_offsets[snapshot.identity] = runtime_start + MAX_RUNTIME_CANDIDATES
                observed_content = getattr(self, "observed_content", None)
                if observed_content is None:
                    self.observed_content = {}
                    observed_content = self.observed_content
                observed_runtimes = getattr(self, "observed_runtimes", None)
                if observed_runtimes is None:
                    self.observed_runtimes = {}
                    observed_runtimes = self.observed_runtimes
                content_values = observed_content.setdefault(snapshot.identity, {})
                runtime_values = observed_runtimes.setdefault(snapshot.identity, {})
                content_values.update({item.evidence_id: item for item in content_now})
                runtime_values.update({item.evidence_id: item for item in runtimes_now})
                current_ids = {
                    *(item.evidence_id for item in content_now),
                    *(item.evidence_id for item in runtimes_now),
                }
                if current_ids:
                    observation = self.observations.observe(
                        snapshot.identity, current_ids
                    )
                    first_seen_ns = observation.first_seen_ns
                else:
                    observation = self.observations.get(snapshot.identity)
                if observation is not None:
                    active = observation.evidence
                    content = tuple(
                        item for key, item in content_values.items() if key in active
                    )
                    runtimes = with_pytorch_pair(
                        item for key, item in runtime_values.items() if key in active
                    )
            if fast_match is None and not content and not runtimes:
                continue
            candidates.append(
                _EvidenceCandidate(snapshot, content, runtimes, first_seen_ns, fast_match)
            )

        content_groups = self._content_groups(
            [
                item
                for item in candidates
                if (item.content or item.runtimes) and item.fast_match is None
            ],
            snapshot_map,
        )
        groups = [
            _DetectionGroup((item,), (item,), "same-process")
            for item in candidates
            if item.fast_match is not None
        ] + content_groups
        for detection_group in groups:
            scope = self._refresh_group(detection_group.scope)
            if not scope:
                continue
            refreshed_by_identity = {
                candidate.snapshot.identity: candidate for candidate in scope
            }
            witness = tuple(
                refreshed_by_identity[item.snapshot.identity]
                for item in detection_group.witness
                if item.snapshot.identity in refreshed_by_identity
            )
            if not witness:
                continue
            for candidate in scope:
                snapshot_map[candidate.snapshot.identity] = candidate.snapshot
            # Launch provenance is written before the protected gate releases.
            # Load it only after refreshing the post-exec process identity;
            # loading it at scan start can race a concurrent protected start
            # and falsely kill an invocation admitted during that same scan.
            try:
                provenances = load_launch_provenance(self.launches)
            except JsonInputError:
                # Corrupt or incomplete provenance never authorizes a matching
                # workload.  Post-exec procfs argv is intentionally not used.
                provenances = []
            provenance_by_identity = {
                ProcessIdentity(item["pid"], item["start_time"]): item
                for item in provenances
            }
            provenance_by_cgroup = {item["cgroup"]: item for item in provenances}
            trigger_candidate = witness[0]
            aggregate_content: list[ArtifactEvidence] = []
            aggregate_runtimes: list[RuntimeEvidence] = []
            for candidate in witness:
                for evidence in candidate.content:
                    if evidence not in aggregate_content:
                        aggregate_content.append(evidence)
                for evidence in candidate.runtimes:
                    if evidence not in aggregate_runtimes:
                        aggregate_runtimes.append(evidence)
            aggregate_runtimes = list(with_vllm_pair(with_pytorch_pair(aggregate_runtimes)))
            supplied = self._candidate_evidence(
                tuple(
                    _EvidenceCandidate(
                        candidate.snapshot,
                        tuple(aggregate_content),
                        tuple(aggregate_runtimes),
                        candidate.first_seen_ns,
                    )
                    for candidate in witness[:1]
                )
            )
            detected = trigger_candidate.fast_match or match(
                self.catalogue, trigger_candidate.snapshot, evidence=supplied
            )
            if detected is None:
                continue
            qualified_ns = time.monotonic_ns()
            unapproved: list[_EvidenceCandidate] = []
            executable_digests: dict[ProcessIdentity, str | None] = {}
            for candidate in witness:
                try:
                    executable_sha256 = self._cached_executable_digest(candidate.snapshot)
                except (JsonInputError, OSError):
                    executable_digests[candidate.snapshot.identity] = None
                    unapproved.append(candidate)
                    continue
                executable_digests[candidate.snapshot.identity] = executable_sha256
                provenance = provenance_by_identity.get(candidate.snapshot.identity)
                candidate_cgroup = next(
                    (
                        line[3:]
                        for line in candidate.snapshot.cgroups
                        if line.startswith("0::/system.slice/")
                    ),
                    "",
                )
                scope_provenance = provenance_by_cgroup.get(candidate_cgroup)
                # A root-approved launch identity authorizes only that exact
                # process.  Cgroup-wide approval is reserved for detector
                # profiles whose contract explicitly includes a qualified
                # launcher/worker topology.  A direct profile (for example
                # GGUF+llama) must not let an approved Python launcher hide a
                # separate AI process in the same owned cgroup.
                authorized = (
                    provenance is not None
                    and launch_authorizes(
                        candidate.snapshot,
                        executable_sha256,
                        getattr(self, "executable_metadata", {}).get(
                            candidate.snapshot.identity
                        ),
                        provenance,
                    )
                ) or self._authorizes_protected_scope(
                    candidate.snapshot,
                    scope_provenance,
                    profile=detected.profile,
                )
                # An active local lockdown turns an exact protected
                # recurrence into an enforcement candidate even when a stale
                # provenance record still makes it look authorised.  The
                # comparison is conjunctive and bounded by the same argv,
                # executable, uid and detector identities as the incident.
                incident_match = self._incident_match_for_candidate(
                    candidate.snapshot,
                    detected,
                    executable_sha256,
                )
                if not authorized or incident_match is not None:
                    unapproved.append(candidate)
            if not unapproved:
                continue
            trigger_candidate = unapproved[0]
            if trigger_candidate.fast_match is not None:
                detected = trigger_candidate.fast_match
            target_set = self._discovery_containment_targets(scope, snapshot_map)
            with self.discovery_lock:
                now = time.monotonic_ns()
                self.discovery_done = {
                    identity: completed
                    for identity, completed in self.discovery_done.items()
                    if now - completed <= RECENT_DISCOVERY_NS
                }
                if target_set & (self.discovery_active | set(self.discovery_done)):
                    continue
                self.discovery_active.update(target_set)
            event_id = os.urandom(12).hex()
            snapshot = unapproved[0].snapshot
            try:
                # Bind one evidence identity before handing enforcement to a
                # worker; contain_many binds all remaining roots immediately.
                pidfd = open_pidfd(snapshot.identity)
            except (JsonInputError, OSError, ProcessLookupError):
                with self.discovery_lock:
                    self.discovery_active.difference_update(target_set)
                continue
            executable_sha256 = executable_digests.get(snapshot.identity)
            first_seen_ns = min(candidate.first_seen_ns for candidate in witness)
            kwargs = {
                "targets": target_set,
                "correlated": tuple(scope),
                "boundary_type": detection_group.boundary,
            }
            if synchronous:
                self._enforce_discovery(
                    snapshot,
                    detected,
                    tuple(aggregate_content),
                    tuple(aggregate_runtimes),
                    first_seen_ns,
                    qualified_ns,
                    executable_sha256,
                    event_id,
                    pidfd,
                    **kwargs,
                )
            else:
                task_args = (
                    snapshot,
                    detected,
                    tuple(aggregate_content),
                    tuple(aggregate_runtimes),
                    first_seen_ns,
                    qualified_ns,
                    executable_sha256,
                    event_id,
                    pidfd,
                )
                if not self.enforcement_slots.acquire(blocking=False):
                    # Admission is bounded.  Defer overflow to the next
                    # bounded scan instead of running containment inline in
                    # the detector thread.  Inline work can hold the scan
                    # long enough to starve the watchdog heartbeat when many
                    # independent workloads arrive together.  The target is
                    # deliberately removed from ``discovery_active`` without
                    # entering ``discovery_done`` so it is retried promptly.
                    self.enforcement_saturation_until_ns = (
                        time.monotonic_ns() + 250_000_000
                    )
                    os.close(pidfd)
                    with self.discovery_lock:
                        self.discovery_active.difference_update(target_set)
                    continue

                def enforce_bounded(
                    task_args: tuple[Any, ...] = task_args,
                    task_kwargs: dict[str, Any] = kwargs,
                ) -> None:
                    try:
                        self._enforce_discovery(*task_args, **task_kwargs)
                    finally:
                        self.enforcement_slots.release()

                try:
                    threading.Thread(target=enforce_bounded, daemon=True).start()
                except RuntimeError:
                    self.enforcement_slots.release()
                    self._enforce_discovery(*task_args, **kwargs)
        self._trim_evidence_caches()

    def _discovery_loop(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic_ns()
            try:
                self._scan_once()
                completed = time.monotonic_ns()
                self.last_scan_completed_ns = completed
                self.last_scan_duration_ns = completed - started
                self.discovery_failures = 0
            except (JsonInputError, OSError, RuntimeError) as error:
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
            or self.last_scan_completed_ns <= 0
            or time.monotonic_ns() - self.last_scan_completed_ns > SCAN_HEALTH_TIMEOUT_NS
            or self.discovery_failures >= MAX_DISCOVERY_FAILURES
            or not self.receipt_persistence_healthy
            or not getattr(self, "incident_health_healthy", True)
            or time.monotonic_ns() < self.enforcement_saturation_until_ns
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
        self,
        record: dict[str, Any],
        trigger: str,
        trigger_ns: int | None = None,
        *,
        boundary: OfflineBoundary | None = None,
        execution_boundary: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Direct cgroup.kill is the first trigger-side effect; cleanup is post-proof only."""
        lock = self._new_lock(record["run_id"])
        with lock:
            if record["run_id"] in self.completed:
                return self.completed[record["run_id"]]
            identity = identity_from_run(record)
            observed = trigger_ns if trigger_ns is not None else time.monotonic_ns()
            boundary_error: str | None = None
            if boundary is None and trigger != "EXECUTION_BOUNDARY":
                try:
                    boundary = self._boundary_for_record(record)
                except (JsonInputError, OSError) as error:
                    boundary_error = str(error)[:160]
            if trigger == "NETWORK_BOUNDARY" and boundary is None:
                # A malformed or missing boundary must still be contained, but
                # must not produce a false network-boundary receipt.
                trigger = "SUPERVISOR_FAILURE"
            # Terminal storage removes launch provenance.  Capture the exact
            # approval identity before containment so a post-containment local
            # lockdown can revoke only the affected approval.
            approval = (
                self._approval_identity(record["run_id"])
                if trigger in {"NETWORK_BOUNDARY", "EXECUTION_BOUNDARY"}
                else None
            )
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
                boundary=(boundary.receipt_metadata() if trigger == "NETWORK_BOUNDARY" and boundary is not None else None),
                execution_boundary=execution_boundary,
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
            if boundary is None and record.get("boundary") is not None:
                try:
                    boundary = self._boundary_for_record(record)
                except (JsonInputError, OSError) as error:
                    boundary_error = str(error)[:160]
            cleanup = self._cleanup(record["unit"])
            if boundary is not None:
                try:
                    cleanup["offline_boundary"] = self._teardown_boundary(record)
                except (JsonInputError, OSError) as error:
                    self.boundary_cleanup_healthy = False
                    cleanup["offline_boundary"] = {"error": str(error)[:160]}
            if boundary_error is not None:
                cleanup["offline_boundary_error"] = boundary_error
            receipt["cleanup"] = cleanup
            try:
                write_atomic(self._receipt_path(event_id), receipt)
            except (OSError, JsonInputError):
                receipt["cleanup_update_error"] = True
            receipt["receipt_path"] = str(self._receipt_path(event_id))
            self._post_containment_response(receipt, record=record, approval=approval)
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
            try:
                current = load_run(self.runs, record["run_id"])
            except JsonInputError:
                current = record
            if current["state"] not in ACTIVE_STATES:
                return False
            current["state"] = "COMPLETED_ALLOWED"
            record.update(current)
            self._store(current)
            try:
                self._teardown_boundary(current)
            except (JsonInputError, OSError):
                # The workload is already empty and the terminal state is
                # durable.  Keep the boundary failure visible to doctor and
                # restart recovery rather than claiming a clean teardown.
                self.boundary_cleanup_healthy = False
            return True

    def _watch_once(
        self,
        record: dict[str, Any],
        ready: threading.Event | None = None,
        *,
        prime_boundary: bool = False,
    ) -> None:
        identity = identity_from_run(record)
        path = validate_identity(identity)
        boundary = self._boundary_for_record(record)
        observer = BoundaryObserver(boundary) if boundary is not None else None
        pids_fd = os.open(path / "pids.events", os.O_RDONLY | os.O_CLOEXEC)
        cgroup_fd = os.open(path / "cgroup.events", os.O_RDONLY | os.O_CLOEXEC)
        try:
            baseline = events_from_fd(pids_fd).get("max")
            if baseline is None:
                raise JsonInputError("pids.events lacks max counter")
            poller = select.poll()
            poller.register(pids_fd, select.POLLPRI)
            poller.register(cgroup_fd, select.POLLPRI)
            if observer is not None:
                if prime_boundary:
                    # The launch FIFO is still closed. Prime immediately
                    # before arming so delayed kernel setup traffic cannot
                    # fall into the gap between warmup and readiness.
                    boundary.warmup()
                # systemd may emit one namespace setup packet before the
                # gated target is released. It is denied by nftables and is
                # not workload traffic; reset it before readiness is exposed.
                boundary.reset_counter()
                observer.arm()
            if ready is not None:
                ready.set()
            while not self.stop_event.is_set():
                poller.poll(50 if observer is not None else 250)
                current = events_from_fd(pids_fd).get("max")
                if current is None:
                    raise JsonInputError("pids.events lacks max counter")
                if current > baseline:
                    self._contain(record, "PID_LIMIT", time.monotonic_ns())
                    return
                if self._complete_allowed(record, cgroup_fd):
                    return
                if observer is not None and observer.poll():
                    self._contain(
                        record,
                        "NETWORK_BOUNDARY",
                        time.monotonic_ns(),
                        boundary=boundary,
                    )
                    return
        finally:
            os.close(pids_fd)
            os.close(cgroup_fd)

    def _watch(
        self,
        record: dict[str, Any],
        ready: threading.Event | None = None,
        *,
        prime_boundary: bool = False,
    ) -> None:
        failure: BaseException | None = None
        for attempt in range(2):
            try:
                self._watch_once(record, ready, prime_boundary=prime_boundary)
                return
            except (JsonInputError, OSError, RuntimeError) as error:
                # A collected transient unit is accepted only through the same
                # exact-empty proof used after a direct cgroup kill.  It is
                # not inferred from systemd's inactive state.
                if "unavailable" in str(error) or "No such file" in str(error):
                    try:
                        _empty_ns, proof = verify_empty(identity_from_run(record))
                    except (JsonInputError, OSError):
                        proof = None
                    if proof is not None and proof.complete:
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

    def _make_exec_channel(self, run_id: str) -> tuple[Path, socket.socket]:
        """Create one root-owned fd-passing channel for the gated process."""
        if not RUN_ID.fullmatch(run_id):
            raise JsonInputError("execution channel identity is invalid")
        path = EXEC_DIR / f"{run_id}.sock"
        if path.exists() or path.is_symlink():
            raise JsonInputError("execution channel already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(path))
            os.chown(path, 0, self.policy["workload_gid"])
            os.chmod(path, 0o660)
            listener.listen(4)
            listener.settimeout(8.0)
            return path, listener
        except Exception:
            listener.close()
            path.unlink(missing_ok=True)
            raise

    @staticmethod
    def _process_in_run(pid: int, record: dict[str, Any]) -> bool:
        """Bind a notification task to the exact cgroup and workload UID."""
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
            return False
        try:
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            uid = int(uid_line.split()[1])
            cgroups = Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
        except (OSError, StopIteration, ValueError):
            return False
        return uid == record["workload_uid"] and f"0::{record['cgroup']}" in cgroups

    @staticmethod
    def _cgroup_is_exactly_empty(record: dict[str, Any]) -> bool:
        try:
            root = validate_identity(identity_from_run(record))
            events = dict(
                line.split(" ", 1)
                for line in (root / "cgroup.events").read_text(encoding="ascii").splitlines()
                if " " in line
            )
            if events.get("populated") != "0":
                return False
            directories = [root, *(item for item in root.rglob("*") if item.is_dir() and not item.is_symlink())]
            return all(not (directory / "cgroup.procs").read_text(encoding="ascii").strip() for directory in directories)
        except (JsonInputError, OSError, ValueError):
            return False

    @staticmethod
    def _cgroup_was_collected_empty(record: dict[str, Any]) -> bool:
        """Accept a listener HUP only when the owned cgroup was collected empty."""
        try:
            validate_identity(identity_from_run(record))
        except JsonInputError as error:
            if "unavailable" not in str(error):
                return False
            try:
                _empty_ns, proof = verify_empty(identity_from_run(record))
            except (JsonInputError, OSError):
                return False
            return proof.complete
        except OSError:
            return False
        return False

    @classmethod
    def _wait_for_cgroup_empty(cls, record: dict[str, Any], *, timeout_seconds: float = 2.0) -> bool:
        """Bridge the short race between process exit, listener HUP and unit collection."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if cls._cgroup_is_exactly_empty(record) or cls._cgroup_was_collected_empty(record):
                return True
            time.sleep(0.005)
        return cls._cgroup_is_exactly_empty(record) or cls._cgroup_was_collected_empty(record)

    def _accept_exec_listener(
        self,
        channel: socket.socket,
        record: dict[str, Any],
        expected_pid: int,
    ) -> int:
        """Accept exactly the listener sent by the pre-exec gate process."""
        connection, _ = channel.accept()
        with connection:
            try:
                _pid, uid, _gid = struct.unpack(
                    "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if uid != record["workload_uid"] or _pid != expected_pid or not self._process_in_run(_pid, record):
                    raise JsonInputError("execution listener peer is not the gated workload")
                payload, ancillary, _flags, _address = connection.recvmsg(32, socket.CMSG_SPACE(struct.calcsize("i")))
                if payload != b"LUMI-EXEC\n":
                    raise JsonInputError("execution listener handshake is invalid")
                descriptors: list[int] = []
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array("i")
                        values.frombytes(data[: values.itemsize * (len(data) // values.itemsize)])
                        descriptors.extend(values.tolist())
                if len(descriptors) != 1 or descriptors[0] < 0:
                    raise JsonInputError("execution listener descriptor is invalid")
                descriptor = descriptors[0]
                connection.sendall(b"OK\n")
                return descriptor
            except Exception:
                try:
                    connection.sendall(b"NO\n")
                except OSError:
                    pass
                raise

    def _exec_listener_loop(
        self,
        record: dict[str, Any],
        policy: dict[str, Any],
        descriptor: int,
    ) -> None:
        """Mediate native exec requests; enforcement precedes any receipt."""
        try:
            poller = select.poll()
            poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
            while not self.stop_event.is_set():
                events = poller.poll(250)
                if not events:
                    if record.get("state") not in ACTIVE_STATES:
                        return
                    continue
                if events[0][1] & (select.POLLHUP | select.POLLERR):
                    if self._wait_for_cgroup_empty(record):
                        self._mark_completed(record)
                        return
                    if record.get("state") in ACTIVE_STATES:
                        self._contain(record, "SUPERVISOR_FAILURE", time.monotonic_ns())
                    return
                try:
                    notification = receive_notification(descriptor)
                except OSError as error:
                    if error.errno in {errno.EAGAIN, errno.EINTR, errno.ENOENT}:
                        continue
                    if record.get("state") in ACTIVE_STATES:
                        self._contain(record, "SUPERVISOR_FAILURE", time.monotonic_ns())
                    return
                if not notification_id_valid(descriptor, notification.id):
                    continue
                if not self._process_in_run(notification.pid, record):
                    # A notification that cannot be bound to this run is a
                    # fail-closed event, not a reason to grant the exec.
                    if record.get("state") in ACTIVE_STATES:
                        self._contain(record, "EXECUTION_BOUNDARY", time.monotonic_ns(), execution_boundary={"policy_id": policy["policy_id"], "policy_sha256": policy["digest"]})
                    try:
                        send_response(descriptor, notification.id, allow=False)
                    except OSError:
                        pass
                    return
                if allowed_target(policy, notification):
                    try:
                        send_response(descriptor, notification.id, allow=True)
                    except OSError:
                        if record.get("state") in ACTIVE_STATES:
                            self._contain(record, "SUPERVISOR_FAILURE", time.monotonic_ns())
                        return
                    continue
                # Keep the syscall held while the authoritative direct kill
                # and exact-empty proof complete.  Only then release it with
                # EPERM, ensuring no prohibited image can enter.
                if record.get("state") in ACTIVE_STATES:
                    self._contain(
                        record,
                        "EXECUTION_BOUNDARY",
                        time.monotonic_ns(),
                        execution_boundary={"policy_id": policy["policy_id"], "policy_sha256": policy["digest"]},
                    )
                try:
                    send_response(descriptor, notification.id, allow=False)
                except OSError:
                    pass
                return
        except (JsonInputError, OSError, RuntimeError):
            if record.get("state") in ACTIVE_STATES:
                try:
                    self._contain(record, "SUPERVISOR_FAILURE", time.monotonic_ns())
                except JsonInputError:
                    pass
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _release_gate(self, gate: Path) -> None:
        # systemd may take a little longer to schedule a freshly created
        # transient unit under sustained fork-race qualification.  The gate
        # remains closed throughout this bounded wait, so this changes launch
        # availability only; it never releases an unobserved workload.
        deadline = time.monotonic() + 5.0
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

    @staticmethod
    def _gated_process(identity: Any) -> ProcessIdentity:
        """Capture the one pre-exec gate identity in an exact owned cgroup."""
        path = validate_identity(identity)
        try:
            raw = (path / "cgroup.procs").read_text(encoding="ascii").splitlines()
        except OSError as error:
            raise JsonInputError("cannot inspect gated workload process") from error
        if len(raw) != 1 or not raw[0].isdigit():
            raise JsonInputError("gated workload must contain exactly one process before exec")
        value = process_identity(int(raw[0]))
        if value is None:
            raise JsonInputError("gated workload process identity vanished")
        return value

    def _active_exists(self) -> bool:
        return bool(getattr(self, "active_cgroups", set()))

    def _start(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) == {"argv", "cpu_quota_percent", "max_memory_mib", "max_pids", "name"}:
            args = {**args, "exec_policy": None}
        if set(args) != {"argv", "cpu_quota_percent", "exec_policy", "max_memory_mib", "max_pids", "name"}:
            raise JsonInputError("start arguments are invalid")
        name, argv, maximum = args["name"], args["argv"], args["max_pids"]
        exec_policy_id = args["exec_policy"]
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
        if not self._incident_status()["healthy"]:
            raise JsonInputError("local lockdown state is unavailable; root recovery is required")
        with self.start_lock, self.approval_lock:
            if name_path(self.names, name).exists() or self._active_exists():
                raise JsonInputError(
                    "one protected workload is already active or name is unavailable"
                )
            blocked = self._incident_block_for_start(summary["argv_sha256"])
            if blocked is not None:
                raise JsonInputError(
                    f"INCIDENT_LOCKDOWN: exact protected relaunch is blocked ({blocked['incident_id']})"
                )
            try:
                approval = match_launch(
                    uid=self.policy["workload_uid"],
                    argv=argv,
                    approvals=load_approvals(self.approvals),
                )
            except JsonInputError:
                approval = None
            run_id = os.urandom(12).hex()
            if exec_policy_id is None:
                execution_policy = ephemeral_execution_policy(argv[0], run_id)
            elif isinstance(exec_policy_id, str):
                execution_policy = load_execution_policy(self.exec_policies, exec_policy_id)
            else:
                raise JsonInputError("execution policy identity is invalid")
            unit = f"{UNIT_PREFIX}{run_id}.service"
            boundary: OfflineBoundary | None = None
            gate: Path | None = None
            exec_channel_path: Path | None = None
            exec_channel: socket.socket | None = None
            exec_listener_fd = -1
            props: dict[str, str] = {}
            try:
                boundary = OfflineBoundary.create(run_id)
                self.boundaries[run_id] = boundary
                effective_argv = (
                    stage_launch(approval, argv, STAGED_DIR / run_id)
                    if approval is not None
                    else list(argv)
                )
                gate = self._make_gate(run_id)
                exec_channel_path, exec_channel = self._make_exec_channel(run_id)
            except Exception:
                if gate is not None:
                    gate.unlink(missing_ok=True)
                if exec_channel is not None:
                    exec_channel.close()
                if exec_channel_path is not None:
                    exec_channel_path.unlink(missing_ok=True)
                self._clear_stage(run_id)
                if boundary is not None:
                    try:
                        self._teardown_boundary(
                            {"run_id": run_id, "boundary": boundary.identity.as_record()}
                        )
                    except (JsonInputError, OSError):
                        self.boundary_cleanup_healthy = False
                raise
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
                    f"--property=NetworkNamespacePath={boundary.workload_namespace_path}",
                    "--property=PrivateTmp=yes",
                    "--property=RestrictNamespaces=yes",
                    "--property=CapabilityBoundingSet=",
                    "--property=AmbientCapabilities=",
                    "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
                    f"--property=TasksMax={maximum}",
                    f"--property=MemoryMax={memory_mib}M",
                    f"--property=CPUQuota={cpu_quota}%",
                    "--property=IOWeight=10",
                    "--property=LimitNOFILE=1024",
                    "--working-directory=/",
                    "--setenv=HOME=/nonexistent",
                    "--setenv=BASH_ENV=/nonexistent",
                    "--setenv=ENV=/nonexistent",
                    "--setenv=GCONV_PATH=/nonexistent",
                    "--setenv=LD_AUDIT=",
                    "--setenv=LD_LIBRARY_PATH=",
                    "--setenv=LD_PRELOAD=",
                    "--setenv=LOCPATH=/nonexistent",
                    "--setenv=NLSPATH=/nonexistent",
                    "--setenv=PYTHONBREAKPOINT=0",
                    "--setenv=PYTHONINSPECT=",
                    "--setenv=PYTHONNOUSERSITE=1",
                    "--setenv=PYTHONSAFEPATH=1",
                    "--setenv=PYTHONPATH=/nonexistent",
                    "--setenv=PYTHONSTARTUP=/nonexistent",
                    "--setenv=PYTHONUSERBASE=/nonexistent",
                    "--",
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz",
                    "_gate",
                    "--fifo",
                    str(gate),
                    "--exec-socket",
                    str(exec_channel_path),
                    "--",
                    *effective_argv,
                ]
            )
            if result.returncode:
                gate.unlink(missing_ok=True)
                if exec_channel is not None:
                    exec_channel.close()
                if exec_channel_path is not None:
                    exec_channel_path.unlink(missing_ok=True)
                self._clear_stage(run_id)
                try:
                    self._teardown_boundary(
                        {"run_id": run_id, "boundary": boundary.identity.as_record()}
                    )
                except (JsonInputError, OSError):
                    self.boundary_cleanup_healthy = False
                raise JsonInputError(result.stderr.strip() or "system workload launch failed")
            try:
                deadline = time.monotonic() + 2.0
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
                    "boundary": boundary.identity.as_record(),
                    "cgroup": identity.cgroup,
                    "cgroup_device": identity.device,
                    "cgroup_inode": identity.inode,
                    "created_monotonic_ns": time.monotonic_ns(),
                    "cpu_quota_percent": cpu_quota,
                    "exec_policy_digest": execution_policy["digest"],
                    "exec_policy_id": execution_policy["policy_id"],
                    "max_memory_mib": memory_mib,
                    "max_pids": maximum,
                    "name": name,
                    "network_mode": "offline",
                    "operator_uid": self.operator_uid,
                    "run_id": run_id,
                    "schema_version": RUN_SCHEMA,
                    "state": "STARTING",
                    "unit": unit,
                    "workload_gid": self.policy["workload_gid"],
                    "workload_uid": self.policy["workload_uid"],
                }
                self._store(record)
                gated_process = self._gated_process(identity)
                if approval is not None:
                    create_launch_provenance(
                        self.launches,
                        run=record,
                        process=gated_process,
                        approval=approval,
                    )
                if exec_channel is None:
                    raise JsonInputError("execution channel is unavailable")
                exec_listener_fd = self._accept_exec_listener(exec_channel, record, gated_process.pid)
                exec_channel.close()
                exec_channel = None
                if exec_channel_path is not None:
                    exec_channel_path.unlink(missing_ok=True)
                    exec_channel_path = None
                exec_listener = threading.Thread(
                    target=self._exec_listener_loop,
                    args=(record, execution_policy, exec_listener_fd),
                    daemon=True,
                )
                exec_listener.start()
                exec_listener_fd = -1
                ready = threading.Event()
                watcher = threading.Thread(
                    target=self._watch,
                    args=(record, ready),
                    kwargs={"prime_boundary": True},
                    daemon=True,
                )
                watcher.start()
                # Boundary priming may wait through delayed kernel IPv6
                # control traffic before exposing the launch gate.
                if not ready.wait(8.0):
                    raise JsonInputError("watcher did not become ready before target release")
                # The gated target has not executed yet.  The watcher has opened
                # both event descriptors and captured the PID baseline.
                self._release_gate(gate)
                if record["state"] in ACTIVE_STATES:
                    record["state"] = "RUNNING"
                    self._store(record)
                return {
                    "name": name,
                    "exec_policy_id": record["exec_policy_id"],
                    "network_mode": "offline",
                    "run_id": run_id,
                    "state": record["state"],
                    "unit": unit,
                    "cpu_quota_percent": cpu_quota,
                    "max_memory_mib": memory_mib,
                    "workload_uid": record["workload_uid"],
                }
            except Exception:
                if exec_listener_fd >= 0:
                    try:
                        os.close(exec_listener_fd)
                    except OSError:
                        pass
                if exec_channel is not None:
                    exec_channel.close()
                if exec_channel_path is not None:
                    exec_channel_path.unlink(missing_ok=True)
                gate.unlink(missing_ok=True)
                provenance_path(self.launches, run_id).unlink(missing_ok=True)
                self._clear_stage(run_id)
                try:
                    # Best effort rollback after a launch failure; direct kill is still authoritative.
                    identity = capture_identity(props["ControlGroup"], run_id, unit)
                    kill_path(validate_identity(identity))
                    verify_empty(identity)
                except (JsonInputError, OSError, RuntimeError):
                    self._run(["/usr/bin/systemctl", "stop", unit])
                if boundary is not None:
                    try:
                        self._teardown_boundary({"run_id": run_id, "boundary": boundary.identity.as_record()})
                    except (JsonInputError, OSError):
                        self.boundary_cleanup_healthy = False
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
            "boundary": None,
            "cgroup": identity.cgroup,
            "cgroup_device": identity.device,
            "cgroup_inode": identity.inode,
            "created_monotonic_ns": time.monotonic_ns(),
            "cpu_quota_percent": 0,
            "exec_policy_digest": "0" * 64,
            "exec_policy_id": "orphaned",
            "executable": "<orphaned-owned-cgroup>",
            "max_pids": 0,
            "max_memory_mib": 0,
            "name": f"orphan-{run_id}",
            "network_mode": "none",
            "operator_uid": self.policy.get("operator_uid", 0),
            "run_id": run_id,
            "schema_version": RUN_SCHEMA,
            "state": "RUNNING",
            "unit": unit,
            "workload_gid": self.policy["workload_gid"],
            "workload_uid": self.policy["workload_uid"],
        }

    def _recover(self) -> None:
        recorded_ids: set[str] = set()
        if not hasattr(self, "active_cgroups"):
            self.active_cgroups = set()
        self.active_cgroups.clear()
        for path in self.runs.glob("*.json"):
            try:
                record = load_run(self.runs, path.stem)
            except JsonInputError:
                continue
            recorded_ids.add(record["run_id"])
            if record["state"] in ACTIVE_STATES:
                self.active_cgroups.add(record["cgroup"])
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
                    # `_contain` records a failure before raising when the
                    # systemd unit has already been collected.  The exact
                    # empty proof is authoritative for this recovery case;
                    # restore the active state so normal completion can be
                    # committed instead of leaving a false failure record.
                    record["state"] = "RUNNING"
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

    def _installation_health(self) -> dict[str, Any]:
        """Verify the installed-file inventory without trusting arbitrary paths."""
        manifest_path = STATE_DIR / "install-manifest.json"
        journal_path = STATE_DIR / "upgrade-journal.json"
        try:
            journal_present = journal_path.exists() or journal_path.is_symlink()
        except OSError:
            return {"state": "DRIFT", "journal": False, "files_match": False}
        if journal_present:
            return {"state": "RECOVERY_REQUIRED", "journal": True, "files_match": False}
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return {"state": "NOT_INSTALLED", "journal": False, "files_match": False}
        try:
            manifest = load_regular_json(manifest_path)
            files = manifest.get("files")
            expected_paths = {
                "/usr/local/bin/eggcracker",
                "/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz",
                "/etc/lumi-eggcracker/detector_catalogue.json",
                "/etc/lumi-eggcracker/policy.json",
                "/etc/systemd/system/lumi-eggcracker.service",
                "/etc/systemd/system/lumi-eggcracker-watchdog.service",
            }
            if not isinstance(files, dict) or set(files) != expected_paths:
                return {"state": "DRIFT", "journal": False, "files_match": False}
            matches = True
            for raw_path, expected in files.items():
                path = Path(raw_path)
                if path.is_symlink() or not path.is_file() or not isinstance(expected, str):
                    matches = False
                    break
                value = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(64 * 1024), b""):
                        value.update(block)
                if value.hexdigest() != expected:
                    matches = False
                    break
            version = manifest.get("version", self.policy["version"])
            if not isinstance(version, str):
                version = "unknown"
            if version != self.policy["version"]:
                matches = False
            return {"state": "HEALTHY" if matches else "DRIFT", "journal": False, "files_match": matches, "manifest_version": version}
        except (JsonInputError, OSError, TypeError, ValueError):
            return {"state": "DRIFT", "journal": False, "files_match": False}

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
            now_ns = time.monotonic_ns()
            scan_healthy = (
                self.last_scan_completed_ns > 0
                and now_ns - self.last_scan_completed_ns <= SCAN_HEALTH_TIMEOUT_NS
                and self.discovery_failures < MAX_DISCOVERY_FAILURES
                and self.receipt_persistence_healthy
                and getattr(self, "boundary_cleanup_healthy", True)
                and self.discovery_thread is not None
                and self.discovery_thread.is_alive()
            )
            boundary_primitives = primitives_available()
            execution_primitives = seccomp_primitive_available()
            incident_status = self._incident_status()
            ready = (
                available
                and pidfd_available()
                and self.quarantine_root is not None
                and policy_network_mode(self.policy) == "offline"
                and boundary_primitives["supported"]
                and execution_primitives["supported"]
                and scan_healthy
                and incident_status["healthy"]
            )
            return {
                "autonomous_discovery": ready,
                "backend": "root-supervisor",
                "network": {
                    "mode": policy_network_mode(self.policy),
                    "primitives": boundary_primitives,
                    "cleanup_healthy": getattr(self, "boundary_cleanup_healthy", True),
                },
                "catalogue": public_catalogue(self.catalogue),
                "cgroup_v2": available,
                "execution_boundary": execution_primitives,
                "incidents": incident_status,
                "discovery": {
                    "consecutive_failures": self.discovery_failures,
                    "last_scan_duration_ms": self.last_scan_duration_ns / 1_000_000,
                    "last_scan_completed": self.last_scan_completed_ns > 0,
                    "receipt_persistence_healthy": self.receipt_persistence_healthy,
                    "healthy": scan_healthy,
                    "scan_health_timeout_ms": SCAN_HEALTH_TIMEOUT_NS / 1_000_000,
                },
                "pidfd": pidfd_available(),
                "installation": self._installation_health(),
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
                "network_mode": (
                    record["boundary"].get("mode", "offline")
                    if isinstance(record.get("boundary"), dict)
                    else "none"
                ),
                "exec_policy_id": record.get("exec_policy_id", "legacy"),
                "exec_policy_digest": record.get("exec_policy_digest", "0" * 64),
                "incident_lockdown": self._incident_status()["lockdown"],
                "workload_uid": record["workload_uid"],
            }
        if action == "list" and not args:
            runs = [
                self.handle({"action": "status", "args": {"name": path.stem}})
                for path in sorted(self.names.glob("*.json"))
            ]
            return {"runs": runs}
        if action in {"approve", "revoke", "exec_policy_create", "exec_policy_revoke"} and not self._incident_status()["healthy"]:
            raise JsonInputError("local lockdown state is unavailable; root recovery is required")
        if action == "approve" and set(args) == {"argv", "name", "uid"}:
            with self.approval_lock:
                value = create_approval(
                    self.approvals,
                    name=args["name"],
                    uid=args["uid"],
                    argv=args["argv"],
                    administrator_uid=0,
                )
            return {"approval": public_approval(value), "result": "APPROVED"}
        if action == "revoke" and set(args) == {"name"}:
            with self.approval_lock:
                return revoke(self.approvals, args["name"])
        if action == "approvals" and not args:
            with self.approval_lock:
                return {
                    "approvals": [
                        public_approval(value) for value in load_approvals(self.approvals)
                    ]
                }
        if action == "exec_policies" and not args:
            with self.approval_lock:
                return {"exec_policies": [public_execution_policy(value) for value in load_execution_policies(self.exec_policies)]}
        if action == "exec_policy_create" and set(args) == {"name", "paths"}:
            with self.approval_lock:
                value = create_execution_policy(
                    self.exec_policies,
                    name=args["name"],
                    paths=args["paths"],
                    creator_uid=0,
                )
            return {"exec_policy": public_execution_policy(value), "result": "CREATED"}
        if action == "exec_policy_revoke" and set(args) == {"policy_id"}:
            with self.approval_lock:
                return revoke_execution_policy(self.exec_policies, args["policy_id"])
        if action == "incidents" and not args:
            with self.incident_response_lock:
                return {"incidents": [incident_store.summary(item) for item in self._incident_values()]}
        if action == "incident_show" and set(args) == {"incident_id"}:
            with self.incident_response_lock:
                values = self._incident_values()
                value = next(
                    (item for item in values if item["incident_id"] == args["incident_id"]),
                    None,
                )
                if value is None:
                    raise JsonInputError("incident is unavailable")
                return incident_store.public_detail(value)
        if action in {"incident_acknowledge", "incident_clear"} and set(args) == {"incident_id"}:
            with self.incident_response_lock:
                values = self._incident_values()
                value = next(
                    (item for item in values if item["incident_id"] == args["incident_id"]),
                    None,
                )
                if value is None:
                    raise JsonInputError("incident is unavailable")
                if action == "incident_acknowledge":
                    if value["state"] == "CLEARED":
                        raise JsonInputError("cleared incident cannot be acknowledged")
                    updated = incident_store.update(
                        self.incidents,
                        value,
                        acknowledgement={"monotonic_ns": time.monotonic_ns(), "uid": 0},
                        state="ACKNOWLEDGED",
                    )
                else:
                    if value["state"] == "CLEARED":
                        return incident_store.public_detail(value)
                    response = dict(value["response"])
                    response["relaunch_suppressed"] = False
                    updated = incident_store.update(
                        self.incidents,
                        value,
                        clearance={"monotonic_ns": time.monotonic_ns(), "uid": 0},
                        response=response,
                        state="CLEARED",
                    )
                self.operations.append("incident-state")
                return incident_store.public_detail(updated)
        if action == "detections" and not args:
            values: list[dict[str, Any]] = []
            paths = [*self.detections.glob("*.json"), *self.receipts.glob("*.json")]
            for path in sorted(paths, key=self._detection_sort_key, reverse=True):
                try:
                    value = load_regular_json(path)
                    trigger = value.get("trigger")
                    trigger_kind = trigger.get("kind") if isinstance(trigger, dict) else None
                    if path.parent == self.receipts and trigger_kind not in {"NETWORK_BOUNDARY", "EXECUTION_BOUNDARY"}:
                        continue
                    if path.parent == self.receipts:
                        boundary = value.get("boundary")
                        execution_boundary = value.get("execution_boundary")
                        if trigger_kind == "NETWORK_BOUNDARY":
                            if not isinstance(boundary, dict) or set(boundary) != {
                                "address_family", "mode", "policy_sha256", "violation"
                            }:
                                continue
                            extra = {"boundary": boundary}
                        else:
                            if not isinstance(execution_boundary, dict) or set(execution_boundary) != {"policy_id", "policy_sha256"}:
                                continue
                            extra = {"execution_boundary": execution_boundary}
                        values.append({"event_id": value["event_id"], "result": value["result"], "trigger": trigger, "version": value["version"], **extra})
                        continue
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
            except (
                JsonInputError,
                OSError,
                OverflowError,
                RecursionError,
                TypeError,
                ValueError,
                struct.error,
            ) as error:
                try:
                    _send(connection, {"ok": False, "value": str(error)})
                except (OSError, OverflowError, RecursionError, TypeError, ValueError):
                    pass

    def serve(self) -> int:
        self._prepare()
        self.discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self.discovery_thread.start()
        # The required synchronous startup scan is already complete and the
        # discovery worker is live. Emit its health proof immediately so a
        # sequence of deliberate restarts cannot starve the watchdog merely
        # because each detected workload is contained before the next scan.
        self._heartbeat()
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
