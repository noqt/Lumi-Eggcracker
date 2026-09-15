"""Off-by-default harmless Linux stop/re-entry demonstration.

The module is a deliberately small experiment adapter.  Importing it and the
default command only print the contract.  The opt-in path is intended for the
disposable, no-network VM prepared by :mod:`vm_runner`; it requires a fresh
run directory, a root-owned accepted envelope, and a root-owned source
manifest.  The selected workload is an inert fake-data writer.  It cannot
read the controller state, observer output, accepted record, or canary tree.

The native stop primitive is a private cgroup-v2 allocation.  A cgroup kill
covers the selected process and descendants which escape their process group,
while a separate trusted-root observer process reads ``cgroup.procs``/
``cgroup.events`` and ``/proc`` without issuing a kill.  That observer is
process/logically independent from the workload, not a privilege-separated
assurance.  Process-group membership is retained as a secondary identity and
audit signal, not as the descendant containment claim.  The root-owned
admission file is committed before every stop and before every launch
transaction.  A fresh controller process therefore cannot reopen admission
after a stop.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows only imports
    fcntl = None  # type: ignore[assignment]

try:
    import pwd
except ImportError:  # pragma: no cover - native execution is Linux-only
    pwd = None  # type: ignore[assignment]

try:
    import termios
except ImportError:  # pragma: no cover - native execution is Linux-only
    termios = None  # type: ignore[assignment]

SCHEMA = "counter-ai-v2.native-demo.v2"
ADMISSION_SCHEMA = "counter-ai-v2.admission.v2"
HAZARD_SCHEMA = "counter-ai-v2.hazard-acceptance.v2"
SOURCE_MANIFEST_SCHEMA = "counter-ai-v2.source-manifest.v1"
OBSERVER_SCHEMA = "counter-ai-v2.observer.v1"
ARTIFACT_MANIFEST_SCHEMA = "counter-ai-v2.artifact-manifest.v2"
HAZARD_ENVELOPE_ID = "PT-EC-COUNTER-AI-V2-20260915-NATIVE-LINUX-V1"
RUN_ID_RE = re.compile(r"v2-[a-z0-9][a-z0-9-]{7,63}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
REASONS = {"FORCED_STOP", "TEARDOWN", "RECOVERY"}
MAX_STATE_BYTES = 16 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_SEED_FILE_BYTES = 256 * 1024
MAX_REASON_CHARS = 64
DEFAULT_STOP_TIMEOUT = 2.0
DEFAULT_OBSERVER_POLL = 0.02
SERIAL_RESULT_PREFIX = "COUNTER_AI_V2_RESULT_V1"
_FALLBACK_LOCK_GUARD = threading.Lock()
_FALLBACK_LOCKS: dict[str, threading.Lock] = {}


class NativeDemoError(RuntimeError):
    """A refusal or an unverifiable native experiment condition."""


class AdmissionRefused(NativeDemoError):
    """A durable latch or incomplete launch transaction refused admission."""


class ObservationUnknown(NativeDemoError):
    """An observer could not establish a bounded result."""


def _now_ns() -> int:
    return time.monotonic_ns()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise NativeDemoError("source file cannot be hashed") from error
    return digest.hexdigest()


def _read_json(path: Path, maximum: int = MAX_STATE_BYTES) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file():
            raise AdmissionRefused("state is absent or not a regular file")
        raw = path.read_bytes()
    except OSError as error:
        raise AdmissionRefused("state is unavailable") from error
    if len(raw) > maximum:
        raise AdmissionRefused("state exceeds the bounded size")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise AdmissionRefused("state is corrupt") from error
    if not isinstance(value, dict):
        raise AdmissionRefused("state envelope is invalid")
    return value


def _regular_private_directory(path: Path, *, root_required: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise NativeDemoError("control directory is unavailable") from error
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise NativeDemoError("control directory must be a real directory")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise NativeDemoError("control directory must be private")
    if root_required and (os.name != "posix" or os.geteuid() != 0 or metadata.st_uid != 0):
        raise NativeDemoError("native control directory must be root-owned")


def _state_owner_ok(path: Path, *, root_required: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AdmissionRefused("state is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise AdmissionRefused("state must be a regular file")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AdmissionRefused("state permissions are too broad")
    if root_required and (os.name != "posix" or os.geteuid() != 0 or metadata.st_uid != 0):
        raise AdmissionRefused("state is not root-owned")


def _write_inhibit_marker(path: Path, reason: str) -> None:
    marker = path.with_name(f".{path.name}.failed")
    payload = _json_bytes({"schema": "counter-ai-v2.admission-inhibit.v1", "reason": reason[:MAX_REASON_CHARS]})
    try:
        with marker.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(marker, 0o600)
        if os.name == "posix" and os.geteuid() == 0:
            os.chown(marker, 0, 0)
    except (FileExistsError, OSError):
        # The pending file remains fail-closed even if the marker could not be
        # written.  Never hide the original transition failure.
        return


def _sync_directory(path: Path, *, required: bool = False) -> None:
    """Durably sync a control directory when the native POSIX path requires it."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as error:
        if required and os.name == "posix":
            raise NativeDemoError("admission control directory could not be synced") from error
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_transition_marker(path: Path, value: dict[str, Any], reason: str) -> None:
    """Pre-arm a durable fail-closed stop intent before replacing state.

    The marker is deliberately written by a path separate from ``_atomic_write``.
    Thus a fault injected at the first state replacement still leaves an
    observable durable inhibit record which a new controller refuses to cross.
    """
    marker = path.with_name(f".{path.name}.transition")
    payload = _json_bytes(
        {
            "schema": "counter-ai-v2.admission-transition.v1",
            "reason": reason[:MAX_REASON_CHARS],
            "run_id": value.get("run_id"),
            "generation": value.get("generation"),
            "sequence": value.get("sequence"),
        }
    )
    if len(payload) > MAX_STATE_BYTES:
        raise NativeDemoError("admission transition marker exceeds the bounded size")
    if marker.exists() or marker.is_symlink():
        raise AdmissionRefused("an incomplete admission transition permanently inhibits admission")
    try:
        with marker.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(marker, 0o600)
        if os.name == "posix" and os.geteuid() == 0:
            os.chown(marker, 0, 0)
        _sync_directory(path.parent, required=True)
    except (NativeDemoError, OSError, ValueError) as error:
        # Do not report a successful stop commit when the intent could not be
        # durably armed.  There is no safe way to claim restart inhibition.
        try:
            marker.unlink()
        except OSError:
            pass
        raise NativeDemoError("stop intent could not be durably pre-armed") from error


def _clear_transition_marker(path: Path) -> None:
    marker = path.with_name(f".{path.name}.transition")
    try:
        marker.unlink()
        _sync_directory(path.parent, required=True)
    except FileNotFoundError:
        return
    except (NativeDemoError, OSError) as error:
        # Keep the marker when cleanup is not durable: a fresh controller must
        # remain inhibited even though the STOP_LATCHED replacement succeeded.
        raise NativeDemoError("completed stop transition marker could not be cleared") from error


def _atomic_write(path: Path, value: dict[str, Any], *, root_required: bool) -> None:
    payload = _json_bytes(value)
    if len(payload) > MAX_STATE_BYTES:
        raise NativeDemoError("admission state exceeds the bounded size")
    temporary = path.with_name(f".{path.name}.pending")
    if temporary.exists() or temporary.is_symlink():
        raise NativeDemoError("interrupted admission write is present")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        if root_required and os.name == "posix":
            os.chown(temporary, 0, 0)
        os.replace(temporary, path)
        try:
            descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            descriptor = None
        if descriptor is not None:
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except (OSError, ValueError) as error:
        _write_inhibit_marker(path, "durable admission write failed")
        raise NativeDemoError("durable admission state write failed") from error
    _state_owner_ok(path, root_required=root_required)


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None:
        raise NativeDemoError("run identity is invalid")
    return run_id


def _validate_nonce(nonce: str) -> str:
    if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
        raise NativeDemoError("run nonce is invalid")
    return nonce


def _validate_state(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "active_pgid",
        "active_pid",
        "generation",
        "mode",
        "reason",
        "run_id",
        "schema",
        "sequence",
        "updated_monotonic_ns",
    }
    if set(value) != required or value.get("schema") != ADMISSION_SCHEMA:
        raise AdmissionRefused("admission state schema is invalid")
    _validate_run_id(value["run_id"])
    if value["mode"] not in {"OPEN", "STOP_LATCHED"}:
        raise AdmissionRefused("admission mode is invalid")
    if value["reason"] is not None and (
        not isinstance(value["reason"], str)
        or len(value["reason"]) > MAX_REASON_CHARS
        or value["reason"] not in REASONS
    ):
        raise AdmissionRefused("admission stop reason is invalid")
    if value["mode"] == "OPEN" and value["reason"] is not None:
        raise AdmissionRefused("open admission cannot carry a stop reason")
    if value["mode"] == "STOP_LATCHED" and value["reason"] is None:
        raise AdmissionRefused("latched admission requires a stop reason")
    for key in ("generation", "sequence", "updated_monotonic_ns"):
        if type(value[key]) is not int or value[key] < 0:
            raise AdmissionRefused("admission integer is invalid")
    if value["generation"] < 1:
        raise AdmissionRefused("admission generation is invalid")
    for key in ("active_pid", "active_pgid"):
        item = value[key]
        if item is not None and (type(item) is not int or item < 0):
            raise AdmissionRefused("active process identity is invalid")
    if (value["active_pid"] is None) != (value["active_pgid"] is None):
        raise AdmissionRefused("active process identity is incomplete")
    if (value["active_pid"] == 0) != (value["active_pgid"] == 0):
        raise AdmissionRefused("pending process identity is incomplete")
    return value


class AdmissionStore:
    """Root-owned durable stop latch with a single-writer launch lock.

    Callers hold :meth:`writer_lock` across reserve/spawn/bind.  The lock is
    advisory only for other root controllers, but the lock file is root-owned
    and the state itself remains the durable authority after a crash.
    """

    def __init__(self, path: Path, *, require_root: bool = False):
        self.path = Path(path)
        self.require_root = require_root
        self._lock_depth = 0
        self._load()

    @property
    def _pending_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.pending")

    @property
    def _failure_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.failed")

    @property
    def _transition_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.transition")

    @property
    def _lock_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.lock")

    @classmethod
    def create(cls, path: Path, run_id: str, *, require_root: bool = False) -> AdmissionStore:
        path = Path(path)
        _validate_run_id(run_id)
        if path.exists() or path.is_symlink():
            raise NativeDemoError("refusing to replace an existing admission state")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if require_root:
            if os.name != "posix" or os.geteuid() != 0:
                raise NativeDemoError("native admission state requires root")
            os.chown(path.parent, 0, 0)
            os.chmod(path.parent, 0o700)
        else:
            os.chmod(path.parent, 0o700)
        _regular_private_directory(path.parent, root_required=require_root)
        value = {
            "active_pgid": None,
            "active_pid": None,
            "generation": 1,
            "mode": "OPEN",
            "reason": None,
            "run_id": run_id,
            "schema": ADMISSION_SCHEMA,
            "sequence": 0,
            "updated_monotonic_ns": _now_ns(),
        }
        _validate_state(value)
        _atomic_write(path, value, root_required=require_root)
        lock = path.with_name(f".{path.name}.lock")
        with lock.open("ab"):
            pass
        os.chmod(lock, 0o600)
        if require_root:
            os.chown(lock, 0, 0)
        return cls(path, require_root=require_root)

    def _load(self) -> None:
        try:
            _regular_private_directory(self.path.parent, root_required=self.require_root)
        except NativeDemoError as error:
            raise AdmissionRefused(str(error)) from error
        if self._pending_path.exists() or self._pending_path.is_symlink():
            raise AdmissionRefused("interrupted admission write is present")
        if self._transition_path.exists() or self._transition_path.is_symlink():
            raise AdmissionRefused("an incomplete admission transition permanently inhibits admission")
        if self._failure_path.exists() or self._failure_path.is_symlink():
            raise AdmissionRefused("a failed admission transition permanently inhibits admission")
        try:
            lock_metadata = self._lock_path.lstat()
        except OSError as error:
            raise AdmissionRefused("admission writer lock is unavailable") from error
        if self._lock_path.is_symlink() or not stat.S_ISREG(lock_metadata.st_mode) or (os.name == "posix" and stat.S_IMODE(lock_metadata.st_mode) & 0o077):
            raise AdmissionRefused("admission writer lock is not private")
        if self.require_root and lock_metadata.st_uid != 0:
            raise AdmissionRefused("admission writer lock is not root-owned")
        _state_owner_ok(self.path, root_required=self.require_root)
        self.state = _validate_state(_read_json(self.path))

    @contextlib.contextmanager
    def writer_lock(self) -> Iterator[None]:
        """Hold the root-controller single-writer lock across a transaction."""
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        if fcntl is None or os.name != "posix":
            # Native enforcement is Linux-only.  The in-process fallback keeps
            # two controller objects serialized for offline Windows invariant
            # tests; production Linux uses the kernel advisory file lock below.
            key = os.path.normcase(str(self.path.resolve()))
            with _FALLBACK_LOCK_GUARD:
                fallback_lock = _FALLBACK_LOCKS.setdefault(key, threading.Lock())
            fallback_lock.acquire()
            self._lock_depth = 1
            try:
                yield
            finally:
                self._lock_depth = 0
                fallback_lock.release()
            return
        try:
            descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CLOEXEC)
        except OSError as error:
            raise AdmissionRefused("admission writer lock is unavailable") from error
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self._lock_depth = 1
            yield
        except OSError as error:
            raise AdmissionRefused("admission writer lock failed") from error
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                self._lock_depth = 0
                os.close(descriptor)

    def _commit(self, value: dict[str, Any]) -> None:
        value = dict(value)
        value["updated_monotonic_ns"] = _now_ns()
        _validate_state(value)
        _atomic_write(self.path, value, root_required=self.require_root)
        self.state = value

    @property
    def latched(self) -> bool:
        self._load()
        return self.state["mode"] == "STOP_LATCHED"

    def reload(self) -> AdmissionStore:
        return type(self)(self.path, require_root=self.require_root)

    def reserve_start(self) -> dict[str, int | str]:
        with self.writer_lock():
            return self._reserve_start_unlocked()

    def _reserve_start_unlocked(self) -> dict[str, int | str]:
        self._load()
        if self.state["mode"] != "OPEN" or self.state["active_pid"] is not None:
            raise AdmissionRefused("launch admission is inhibited")
        value = dict(self.state)
        value["active_pid"], value["active_pgid"] = 0, 0
        value["sequence"] += 1
        self._commit(value)
        return {"generation": value["generation"], "run_id": value["run_id"]}

    def mark_active(self, pid: int, pgid: int) -> None:
        with self.writer_lock():
            self._mark_active_unlocked(pid, pgid)

    def _mark_active_unlocked(self, pid: int, pgid: int) -> None:
        if type(pid) is not int or pid <= 0 or type(pgid) is not int or pgid <= 0:
            raise NativeDemoError("active process identity is invalid")
        self._load()
        if (self.state["active_pid"], self.state["active_pgid"]) != (0, 0):
            raise NativeDemoError("launch is not pending")
        value = dict(self.state)
        value["active_pid"], value["active_pgid"] = pid, pgid
        self._commit(value)

    def request_stop(self, reason: str = "FORCED_STOP") -> dict[str, Any]:
        with self.writer_lock():
            return self._request_stop_unlocked(reason)

    def _request_stop_unlocked(self, reason: str = "FORCED_STOP") -> dict[str, Any]:
        if reason not in REASONS:
            raise NativeDemoError("stop reason is not predeclared")
        self._load()
        value = dict(self.state)
        if value["mode"] == "OPEN":
            next_value = dict(value)
            next_value["mode"], next_value["reason"] = "STOP_LATCHED", reason
            next_value["sequence"] += 1
            # Arm a separate durable intent before the state replacement.  If
            # the replacement fails, this marker makes every fresh controller
            # fail closed rather than reopening OPEN admission.
            _write_transition_marker(self.path, next_value, reason)
            self._commit(next_value)
            # Clearing is deliberately after the durable STOP_LATCHED commit;
            # a cleanup failure leaves the marker and therefore remains closed.
            _clear_transition_marker(self.path)
        return dict(self.state)

    def mark_stopped(self) -> None:
        with self.writer_lock():
            self._mark_stopped_unlocked()

    def _mark_stopped_unlocked(self) -> None:
        self._load()
        if self.state["mode"] != "STOP_LATCHED":
            raise NativeDemoError("cannot clear active identity before the stop latch")
        value = dict(self.state)
        value["active_pid"], value["active_pgid"] = None, None
        value["sequence"] += 1
        self._commit(value)

    def reset(self, *, observed_stopped: bool, observation: dict[str, Any] | None = None) -> dict[str, Any]:
        with self.writer_lock():
            return self._reset_unlocked(observed_stopped=observed_stopped, observation=observation)

    def _reset_unlocked(self, *, observed_stopped: bool, observation: dict[str, Any] | None = None) -> dict[str, Any]:
        self._load()
        if not observed_stopped:
            raise AdmissionRefused("explicit reset requires an external stopped observation")
        if self.state["mode"] != "STOP_LATCHED" or self.state["active_pid"] is not None:
            raise AdmissionRefused("reset requires a durable latch with no active identity")
        if self.require_root:
            if not isinstance(observation, dict):
                raise AdmissionRefused("root reset requires a bound stopped observation")
            if (
                observation.get("run_id") != self.state["run_id"]
                or observation.get("generation") != self.state["generation"]
                or type(observation.get("pid")) is not int
                or observation["pid"] <= 0
                or type(observation.get("pgid")) is not int
                or observation["pgid"] <= 0
                or type(observation.get("starttime")) is not int
                or observation["starttime"] <= 0
                or type(observation.get("session")) is not int
                or observation["session"] <= 0
                or type(observation.get("uid")) is not int
                or observation["uid"] <= 0
                or observation.get("exact_empty") is not True
                or type(observation.get("observed_monotonic_ns")) is not int
                or observation["observed_monotonic_ns"] <= 0
            ):
                raise AdmissionRefused("stopped observation is not bound to the latched launch")
        value = dict(self.state)
        value["generation"] += 1
        value["mode"], value["reason"] = "OPEN", None
        value["sequence"] += 1
        self._commit(value)
        return dict(self.state)


def validate_hazard_acceptance(value: dict[str, Any], *, run_nonce: str | None = None) -> dict[str, Any]:
    """Validate the exact, nonce-scoped technical and Risk acceptance."""
    if not isinstance(value, dict) or value.get("schema") != HAZARD_SCHEMA:
        raise NativeDemoError("hazard acceptance schema is invalid")
    required = {
        "acceptance_id",
        "artifact_manifest_sha256",
        "envelope_id",
        "risk_review",
        "run_nonce",
        "schema",
        "source_sha256",
        "status",
        "technical_review",
    }
    if set(value) != required or value["status"] != "ACCEPTED":
        raise NativeDemoError("native action requires an accepted hazard envelope")
    if value["envelope_id"] != HAZARD_ENVELOPE_ID:
        raise NativeDemoError("hazard acceptance targets a different envelope")
    for key in ("acceptance_id", "envelope_id", "risk_review", "technical_review"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise NativeDemoError("hazard acceptance identity is incomplete")
    if (
        not isinstance(value["source_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"])
        or set(value["source_sha256"]) == {"0"}
    ):
        raise NativeDemoError("hazard acceptance source identity is invalid")
    if (
        not isinstance(value["artifact_manifest_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", value["artifact_manifest_sha256"]) is None
        or set(value["artifact_manifest_sha256"]) == {"0"}
    ):
        raise NativeDemoError("hazard acceptance artifact-manifest identity is invalid")
    _validate_nonce(value["run_nonce"])
    if run_nonce is not None and value["run_nonce"] != _validate_nonce(run_nonce):
        raise NativeDemoError("hazard acceptance nonce does not bind this run")
    if value["technical_review"] == "PENDING" or value["risk_review"] == "PENDING":
        raise NativeDemoError("pending technical or Risk review cannot authorize execution")
    return value


@dataclass(frozen=True)
class ProcIdentity:
    pid: int
    pgid: int
    session: int
    starttime: int
    uid: int


@dataclass(frozen=True)
class GroupObservation:
    pgid: int
    pids: tuple[int, ...]
    live_pids: tuple[int, ...]
    zombie_pids: tuple[int, ...]
    stopped: bool
    exact_empty: bool
    observed_monotonic_ns: int
    error: str | None = None


class ProcObserver:
    """Read-only /proc observer; it never sends a signal."""

    @staticmethod
    def _stat_fields(raw: str) -> tuple[str, int, int, int]:
        close = raw.rfind(")")
        if close < 0:
            raise ObservationUnknown("/proc stat command field is malformed")
        fields = raw[close + 2 :].split()
        if len(fields) < 20 or not fields[0] or not fields[2].isdigit() or not fields[3].isdigit():
            raise ObservationUnknown("/proc stat process fields are malformed")
        if not fields[19].isdigit():
            raise ObservationUnknown("/proc stat starttime is malformed")
        return fields[0], int(fields[2]), int(fields[3]), int(fields[19])

    @staticmethod
    def _stat_pgid(raw: str) -> int:
        close = raw.rfind(")")
        if close < 0:
            raise ObservationUnknown("/proc stat command field is malformed")
        fields = raw[close + 2 :].split()
        if len(fields) < 3 or not fields[2].isdigit():
            raise ObservationUnknown("/proc stat process-group field is malformed")
        return int(fields[2])

    def identity(self, pid: int) -> ProcIdentity:
        if platform.system() != "Linux":
            raise ObservationUnknown("the native observer requires Linux /proc")
        try:
            raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
            state, pgid, session, starttime = self._stat_fields(raw)
            status = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
        except (OSError, UnicodeDecodeError, StopIteration, ValueError) as error:
            raise ObservationUnknown("process identity is unavailable") from error
        if state == "Z":
            raise ObservationUnknown("process identity is already a zombie")
        return ProcIdentity(pid, pgid, session, starttime, real_uid)

    def _group(self, pgid: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
        if platform.system() != "Linux" or type(pgid) is not int or pgid <= 0:
            raise ObservationUnknown("process-group identity is invalid")
        live: list[int] = []
        zombie: list[int] = []
        try:
            entries = list(Path("/proc").iterdir())
        except OSError as error:
            raise ObservationUnknown("/proc cannot be enumerated") from error
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                raw = (entry / "stat").read_text(encoding="ascii")
                state, item_pgid, _session, _start = self._stat_fields(raw)
                if item_pgid == pgid:
                    (zombie if state == "Z" else live).append(int(entry.name))
            except (OSError, UnicodeDecodeError):
                if entry.exists():
                    raise ObservationUnknown("process identity changed during observation")
            except ObservationUnknown:
                if entry.exists():
                    raise
        return tuple(sorted(live)), tuple(sorted(zombie))

    def group_pids(self, pgid: int) -> tuple[int, ...]:
        live, zombie = self._group(pgid)
        return tuple(sorted((*live, *zombie)))

    def observe(self, pgid: int) -> GroupObservation:
        observed = _now_ns()
        live, zombie = self._group(pgid)
        pids = tuple(sorted((*live, *zombie)))
        return GroupObservation(pgid, pids, live, zombie, not live, not pids, observed)

    def wait_empty(
        self,
        pgid: int,
        *,
        timeout_seconds: float = DEFAULT_STOP_TIMEOUT,
        poll_seconds: float = DEFAULT_OBSERVER_POLL,
        leader: subprocess.Popen[Any] | None = None,
    ) -> GroupObservation:
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ObservationUnknown("observer timing is invalid")
        deadline = time.monotonic() + timeout_seconds
        last = self.observe(pgid)
        while time.monotonic() < deadline:
            if leader is not None and leader.poll() is not None:
                try:
                    leader.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
            last = self.observe(pgid)
            if last.exact_empty:
                return last
            time.sleep(poll_seconds)
        raise ObservationUnknown(f"owned process group was not exactly empty: {last.pids}")


def _terminate_group(
    observer: ProcObserver,
    pgid: int,
    *,
    timeout_seconds: float,
    leader: subprocess.Popen[Any] | None = None,
) -> GroupObservation:
    # A leader which has already exited must be reaped/observed, not signalled
    # by a potentially recycled PGID.  The authoritative cgroup kill has
    # already covered its descendants in the native path.
    if leader is not None and leader.poll() is not None:
        return observer.wait_empty(pgid, timeout_seconds=timeout_seconds, leader=leader)
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise NativeDemoError("owned process group could not receive SIGTERM") from error
    try:
        return observer.wait_empty(pgid, timeout_seconds=timeout_seconds, leader=leader)
    except ObservationUnknown:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise NativeDemoError("owned process group could not receive SIGKILL") from error
        return observer.wait_empty(pgid, timeout_seconds=timeout_seconds, leader=leader)


@dataclass(frozen=True)
class CgroupObservation:
    path: str
    pids: tuple[int, ...]
    populated: int
    empty: bool
    observed_monotonic_ns: int


class NativeCgroup:
    """One private cgroup-v2 allocation owned by this disposable run."""

    def __init__(self, path: Path):
        path = Path(path)
        if path.is_symlink() or not path.is_absolute() or path.parent != Path("/sys/fs/cgroup") or re.fullmatch(r"counter-ai-v2-[0-9a-f]{24}", path.name) is None:
            raise NativeDemoError("cgroup path is outside the fresh v2 allocation namespace")
        self.path = path
        self._procs = path / "cgroup.procs"
        self._events = path / "cgroup.events"
        self._kill = path / "cgroup.kill"

    @classmethod
    def create(cls, run_id: str, generation: int, role: str) -> NativeCgroup:
        if platform.system() != "Linux" or os.name != "posix" or os.geteuid() != 0:
            raise NativeDemoError("native execution requires a Linux cgroup-v2 root")
        root = Path("/sys/fs/cgroup")
        if root.is_symlink() or not root.is_dir():
            raise NativeDemoError("cgroup-v2 root is unavailable")
        suffix = hashlib.sha256(f"{run_id}:{generation}:{role}".encode()).hexdigest()[:24]
        path = root / f"counter-ai-v2-{suffix}"
        try:
            path.mkdir(mode=0o700)
        except OSError as error:
            raise NativeDemoError("private cgroup allocation failed") from error
        try:
            for item in (path / "cgroup.procs", path / "cgroup.events", path / "cgroup.kill"):
                if item.is_symlink() or not item.exists():
                    raise NativeDemoError("private cgroup lacks required v2 controls")
            os.chown(path, 0, 0)
            os.chmod(path, 0o700)
        except (NativeDemoError, OSError) as error:
            try:
                path.rmdir()
            except OSError:
                pass
            if isinstance(error, NativeDemoError):
                raise
            raise NativeDemoError("private cgroup ownership could not be established") from error
        return cls(path)

    def attach(self, pid: int) -> None:
        try:
            with self._procs.open("w", encoding="ascii") as stream:
                stream.write(f"{pid}\n")
                stream.flush()
        except OSError as error:
            raise NativeDemoError("selected process could not be attached to its private cgroup") from error

    def observe(self) -> CgroupObservation:
        try:
            raw_pids = self._procs.read_text(encoding="ascii")
            raw_events = self._events.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise ObservationUnknown("cgroup observer controls are unavailable") from error
        pids: list[int] = []
        for item in raw_pids.split():
            if not item.isdigit() or int(item) <= 0:
                raise ObservationUnknown("cgroup process identity is malformed")
            pids.append(int(item))
        event_values: dict[str, int] = {}
        for line in raw_events.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1] in {"0", "1"}:
                event_values[fields[0]] = int(fields[1])
        if event_values.get("populated") not in {0, 1}:
            raise ObservationUnknown("cgroup populated event is unavailable")
        return CgroupObservation(
            str(self.path),
            tuple(sorted(set(pids))),
            event_values["populated"],
            event_values["populated"] == 0 and not pids,
            _now_ns(),
        )

    def wait_empty(self, *, timeout_seconds: float = DEFAULT_STOP_TIMEOUT) -> CgroupObservation:
        deadline = time.monotonic() + timeout_seconds
        last = self.observe()
        while time.monotonic() < deadline:
            if last.empty:
                return last
            time.sleep(DEFAULT_OBSERVER_POLL)
            last = self.observe()
        raise ObservationUnknown(f"private cgroup remained populated: {last.pids}")

    def kill(self) -> tuple[int, int]:
        # This is the same direct cgroup.kill primitive used by the retained
        # Eggcracker containment implementation.  The experiment creates a
        # fresh local identity instead of installing the production unit
        # namespace, so the guest source remains bounded and offline.
        started = _now_ns()
        try:
            with self._kill.open("w", encoding="ascii") as stream:
                stream.write("1\n")
                stream.flush()
        except OSError as error:
            raise NativeDemoError("private cgroup kill failed") from error
        return started, _now_ns()

    def close(self) -> None:
        observation = self.observe()
        if not observation.empty:
            raise NativeDemoError("private cgroup cannot be removed while populated")
        try:
            self.path.rmdir()
        except OSError as error:
            raise NativeDemoError("private cgroup cleanup failed") from error


def _load_self_report(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _controlled_workload_script(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise NativeDemoError("workload script must be an absolute regular file")
    if os.name == "posix":
        for item in (path, *path.parents):
            try:
                metadata = item.lstat()
            except OSError as error:
                raise NativeDemoError("workload script ownership cannot be checked") from error
            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise NativeDemoError("workload script and parents must be root-controlled")
    return path


def _controlled_root_file(path: Path, description: str, *, maximum: int = MAX_STATE_BYTES) -> Path:
    path = Path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise NativeDemoError(f"{description} is unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        raise NativeDemoError(f"{description} must be a root-owned regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise NativeDemoError(f"{description} must not be writable by the workload")
    if metadata.st_size > maximum:
        raise NativeDemoError(f"{description} exceeds the bounded size")
    return path


def validate_source_manifest(
    manifest_path: Path,
    *,
    native_script: Path,
    workload_script: Path,
    acceptance_path: Path,
    artifact_manifest_path: Path,
    run_id: str,
    run_nonce: str,
) -> dict[str, Any]:
    """Verify the frozen source manifest and post-acceptance bindings."""
    manifest_path = _controlled_root_file(manifest_path, "source manifest")
    try:
        manifest = _read_json(manifest_path, maximum=MAX_STATE_BYTES)
    except AdmissionRefused as error:
        raise NativeDemoError("source manifest is invalid") from error
    required = {"artifact_manifest_sha256", "native_demo_sha256", "run_id", "run_nonce", "schema", "workload_sha256"}
    if set(manifest) != required or manifest["schema"] != SOURCE_MANIFEST_SCHEMA:
        raise NativeDemoError("source manifest schema is invalid")
    _validate_run_id(manifest["run_id"])
    _validate_nonce(manifest["run_nonce"])
    if manifest["run_id"] != run_id or manifest["run_nonce"] != run_nonce:
        raise NativeDemoError("source manifest does not bind this run")
    for key in ("native_demo_sha256", "workload_sha256"):
        if not isinstance(manifest[key], str) or re.fullmatch(r"[0-9a-f]{64}", manifest[key]) is None:
            raise NativeDemoError("source manifest hash is invalid")
    if not isinstance(manifest["artifact_manifest_sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", manifest["artifact_manifest_sha256"]) is None:
        raise NativeDemoError("source manifest artifact identity is invalid")
    if sha256_file(native_script) != manifest["native_demo_sha256"]:
        raise NativeDemoError("native source hash changed after preparation")
    if sha256_file(workload_script) != manifest["workload_sha256"]:
        raise NativeDemoError("workload source hash changed after preparation")
    artifact_manifest = validate_artifact_manifest(
        artifact_manifest_path,
        expected_sha256=manifest["artifact_manifest_sha256"],
        native_script=native_script,
        workload_script=workload_script,
    )
    if manifest["artifact_manifest_sha256"] != artifact_manifest["_sha256"]:
        raise NativeDemoError("source manifest artifact identity changed after preparation")
    _controlled_root_file(acceptance_path, "accepted hazard record")
    try:
        acceptance = _read_json(acceptance_path, maximum=MAX_RESULT_BYTES)
        validate_hazard_acceptance(acceptance, run_nonce=run_nonce)
    except (AdmissionRefused, NativeDemoError) as error:
        raise NativeDemoError("accepted hazard record is invalid or not nonce-bound") from error
    return manifest


def validate_artifact_manifest(
    manifest_path: Path,
    *,
    expected_sha256: str,
    native_script: Path,
    workload_script: Path,
) -> dict[str, Any]:
    """Verify the frozen, non-circular source/tool manifest in the guest.

    The acceptance record carries the digest; the manifest does not carry its
    own digest and therefore cannot self-authorize by changing the acceptance
    hash.  Host-only input pins are rechecked by ``vm_runner``; the guest uses
    the same frozen manifest to bind the transported source bundle.
    """
    manifest_path = _controlled_root_file(manifest_path, "artifact manifest", maximum=MAX_RESULT_BYTES)
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise NativeDemoError("artifact manifest digest is invalid")
    actual_sha256 = sha256_file(manifest_path)
    if actual_sha256 != expected_sha256:
        raise NativeDemoError("artifact manifest digest changed after acceptance")
    try:
        manifest = _read_json(manifest_path, maximum=MAX_RESULT_BYTES)
    except AdmissionRefused as error:
        raise NativeDemoError("artifact manifest is invalid") from error
    if manifest.get("schema") != ARTIFACT_MANIFEST_SCHEMA or not isinstance(manifest.get("source"), dict):
        raise NativeDemoError("artifact manifest schema is invalid")
    source = manifest["source"]
    native_key = "experiments/counter_ai_v2/native_demo.py"
    workload_key = "experiments/counter_ai_v2/workload.py"
    if (
        not isinstance(source.get(native_key), str)
        or not isinstance(source.get(workload_key), str)
        or re.fullmatch(r"[0-9a-f]{64}", source[native_key]) is None
        or re.fullmatch(r"[0-9a-f]{64}", source[workload_key]) is None
    ):
        raise NativeDemoError("artifact manifest source pins are invalid")
    if source[native_key] != sha256_file(native_script) or source[workload_key] != sha256_file(workload_script):
        raise NativeDemoError("transported source does not match the frozen artifact manifest")
    # Keep the digest internal to the validation result; it is not written back
    # into the manifest and cannot introduce a circular acceptance binding.
    manifest = dict(manifest)
    manifest["_sha256"] = actual_sha256
    return manifest


def _owned_identity(observer: ProcObserver, process: subprocess.Popen[Any], uid: int) -> ProcIdentity:
    identity = observer.identity(process.pid)
    if identity.pgid != process.pid or identity.session != process.pid or identity.uid != uid:
        raise NativeDemoError("selected workload did not receive a private bound identity")
    return identity


def _workload_identity(name: str) -> tuple[int, int]:
    if platform.system() != "Linux" or os.name != "posix" or pwd is None:
        raise NativeDemoError("native demonstration requires Linux")
    if os.geteuid() != 0:
        uid, gid = os.getuid(), os.getgid()
        if uid == 0:
            raise NativeDemoError("root must select a dedicated unprivileged workload")
        return uid, gid
    try:
        account = pwd.getpwnam(name)
    except KeyError as error:
        raise NativeDemoError(f"dedicated workload account is missing: {name}") from error
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise NativeDemoError("workload account must be unprivileged")
    return account.pw_uid, account.pw_gid


def _assert_guest_layout(
    run_dir: Path,
    control: Path,
    work: Path,
    gates: Path,
    target_dir: Path,
    canary_dir: Path,
    *,
    target_uid: int,
    target_gid: int,
    canary_uid: int,
    canary_gid: int,
) -> None:
    """Verify the exact root/search-only/owned directory boundary before launch."""
    if target_uid == canary_uid:
        raise NativeDemoError("target and canary must use distinct unprivileged identities")
    expected = (
        (run_dir, 0o711, 0, 0, "run root"),
        (control, 0o700, 0, 0, "control"),
        (work, 0o711, 0, 0, "work ancestor"),
        (gates, 0o711, 0, 0, "launch gates"),
        (target_dir, 0o700, target_uid, target_gid, "target tree"),
        (canary_dir, 0o700, canary_uid, canary_gid, "canary tree"),
    )
    for path, mode, owner_uid, owner_gid, label in expected:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise NativeDemoError(f"{label} is unavailable") from error
        if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise NativeDemoError(f"{label} must be a real directory")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != mode:
            raise NativeDemoError(f"{label} permissions are not the frozen boundary")
        if os.name == "posix" and os.geteuid() == 0 and (
            metadata.st_uid != owner_uid or metadata.st_gid != owner_gid
        ):
            raise NativeDemoError(f"{label} ownership is not the frozen boundary")


def _assert_workload_identity_ready(path: Path, *, uid: int, gid: int, label: str) -> None:
    """Perform a harmless operation as the actual selected UID/GID.

    Root-side stat/chown checks do not prove that the guest account can traverse
    the shared search-only ancestors.  This short probe creates and removes one
    run-local marker as the exact UID/GID with no inherited supplementary
    groups.  It is a readiness check, not the selected workload demonstration.
    """
    if os.name != "posix" or os.geteuid() != 0:
        raise NativeDemoError("actual-UID readiness requires the root Linux guest path")
    probe = """
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
uid = int(sys.argv[2])
gid = int(sys.argv[3])
if os.geteuid() != uid or os.getegid() != gid:
    raise SystemExit(2)
marker = path / '.counter-ai-v2-uid-ready'
if marker.exists():
    raise SystemExit(3)
marker.write_bytes(b'ready')
marker.unlink()
"""
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", probe, str(path), str(uid), str(gid)],
            cwd=str(path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
            close_fds=True,
            user=uid,
            group=gid,
            extra_groups=(),
            check=False,
            timeout=2.0,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise NativeDemoError(f"{label} actual-UID readiness could not run") from error
    if result.returncode != 0:
        raise NativeDemoError(f"{label} actual-UID readiness failed")


def _spawn_workload(
    workload_script: Path,
    arguments: list[str],
    *,
    uid: int,
    gid: int,
) -> subprocess.Popen[str]:
    if workload_script.is_symlink() or not workload_script.is_file():
        raise NativeDemoError("workload script must be a regular file")
    if os.geteuid() == 0 and uid == 0:
        raise NativeDemoError("refusing to launch the selected workload as root")
    try:
        return subprocess.Popen(
            [sys.executable, "-I", "-B", str(workload_script), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
            close_fds=True,
            start_new_session=True,
            text=True,
            user=uid if os.geteuid() == 0 else None,
            group=gid if os.geteuid() == 0 else None,
            extra_groups=() if os.geteuid() == 0 else None,
        )
    except (OSError, ValueError) as error:
        raise NativeDemoError("selected workload could not be launched") from error


def _wait_report(path: Path, process: subprocess.Popen[Any], *, generation: int, role: str, timeout: float = 2.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        report = _load_self_report(path)
        if report is not None and report.get("role") == role and report.get("generation") == generation:
            return report
        if process.poll() is not None:
            break
        time.sleep(DEFAULT_OBSERVER_POLL)
    raise NativeDemoError("selected workload self-report did not arrive for this generation")


def _write_result(path: Path, value: dict[str, Any]) -> None:
    payload = _json_bytes(value)
    if len(payload) > MAX_RESULT_BYTES:
        raise NativeDemoError("result exceeds the bounded size")
    if path.exists() or path.is_symlink():
        raise NativeDemoError("refusing to replace an existing result")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.pending")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    if os.name == "posix" and os.geteuid() == 0:
        os.chown(temporary, 0, 0)
    os.replace(temporary, path)


def _release_gate(path: Path) -> None:
    """Release a root-created read-only gate after cgroup attachment."""
    if path.exists() or path.is_symlink():
        raise NativeDemoError("launch gate is not fresh")
    try:
        with path.open("xb") as stream:
            stream.write(b"READY\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o444)
        if os.name == "posix" and os.geteuid() == 0:
            os.chown(path, 0, 0)
    except OSError as error:
        raise NativeDemoError("launch gate could not be released") from error


def _emit_serial_result(serial_path: Path, run_nonce: str, result: dict[str, Any]) -> None:
    """Write one bounded, nonce-bound line to the guest's QEMU serial port."""
    _validate_nonce(run_nonce)
    if Path(serial_path) != Path("/dev/ttyS0"):
        raise NativeDemoError("serial result path is not the dedicated guest serial port")
    encoded = base64.b64encode(_json_bytes(result)).decode("ascii")
    line = f"{SERIAL_RESULT_PREFIX} {run_nonce} {encoded}\n".encode("ascii")
    if len(line) > MAX_RESULT_BYTES:
        raise NativeDemoError("serial result exceeds the bounded size")
    try:
        descriptor = os.open("/dev/ttyS0", os.O_WRONLY | os.O_NOCTTY | os.O_CLOEXEC)
        try:
            written = os.write(descriptor, line)
            if written != len(line):
                raise NativeDemoError("serial result was truncated")
            if termios is None:
                raise NativeDemoError("guest serial terminal drain is unavailable")
            termios.tcdrain(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise NativeDemoError("guest serial result export failed") from error


def _poweroff_guest() -> None:
    if platform.system() != "Linux" or os.name != "posix" or os.geteuid() != 0:
        raise NativeDemoError("guest poweroff requires Linux root")
    try:
        completed = subprocess.run(["/sbin/poweroff", "-f"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5)
        if completed.returncode != 0:
            raise NativeDemoError("guest poweroff returned failure")
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NativeDemoError("guest poweroff could not be requested") from error


def _fresh_controller_relaunch_check(state_path: Path, *, run_id: str, generation: int) -> bool:
    """Run the refusal check in a fresh controller process."""
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--controller-relaunch-check", "--state", str(state_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NativeDemoError("fresh controller restart check failed") from error
    expected = f"RELAUNCH_REFUSED {run_id} {generation}"
    if result.returncode != 0 or result.stdout.strip() != expected:
        raise NativeDemoError("controller restart did not return the exact durable refusal")
    return True


def _run_external_observer(
    *,
    cgroup: NativeCgroup,
    pgid: int,
    run_id: str,
    generation: int,
    run_nonce: str,
    output: Path,
) -> dict[str, Any]:
    """Ask a separate trusted-root, logically read-only observer for a snapshot.

    This is process/logical independence from the workload, not a
    privilege-separated assurance: the observer runs as the same trusted
    guest root as the controller and has no cgroup-kill or latch code path.
    """
    _validate_run_id(run_id)
    if type(generation) is not int or generation < 1:
        raise ObservationUnknown("observer generation is invalid")
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--observer-once",
                "--cgroup",
                str(cgroup.path),
                "--pgid",
                str(pgid),
                "--run-id",
                run_id,
                "--generation",
                str(generation),
                "--nonce",
                run_nonce,
                "--output",
                str(output),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ObservationUnknown("trusted-root observer process failed") from error
    if completed.returncode != 0:
        raise ObservationUnknown("trusted-root observer process returned failure")
    try:
        value = _read_json(output, maximum=MAX_STATE_BYTES)
    except AdmissionRefused as error:
        raise ObservationUnknown("trusted-root observer record is unreadable") from error
    required = {"cgroup", "generation", "observed_monotonic_ns", "process_group", "run_id", "run_nonce", "schema"}
    if set(value) != required or value.get("schema") != OBSERVER_SCHEMA or value.get("run_nonce") != run_nonce or value.get("run_id") != run_id or value.get("generation") != generation:
        raise ObservationUnknown("trusted-root observer record is not exactly run-bound")
    cgroup_record = value.get("cgroup")
    group_record = value.get("process_group")
    if not isinstance(cgroup_record, dict) or not isinstance(group_record, dict):
        raise ObservationUnknown("trusted-root observer record shape is invalid")
    if set(cgroup_record) != {"empty", "path", "pids", "populated"} or set(group_record) != {"exact_empty", "live_pids", "pgid", "pids", "zombie_pids"}:
        raise ObservationUnknown("trusted-root observer record fields are incomplete")
    if cgroup_record.get("path") != str(cgroup.path) or group_record.get("pgid") != pgid:
        raise ObservationUnknown("trusted-root observer identity changed")
    if (
        type(cgroup_record.get("empty")) is not bool
        or cgroup_record.get("populated") not in {0, 1}
        or not isinstance(cgroup_record.get("pids"), list)
        or any(type(pid) is not int or pid <= 0 for pid in cgroup_record["pids"])
        or type(group_record.get("exact_empty")) is not bool
        or not isinstance(group_record.get("pids"), list)
        or not isinstance(group_record.get("live_pids"), list)
        or not isinstance(group_record.get("zombie_pids"), list)
        or any(type(pid) is not int or pid <= 0 for pid in (*group_record["pids"], *group_record["live_pids"], *group_record["zombie_pids"]))
    ):
        raise ObservationUnknown("trusted-root observer record values are invalid")
    if cgroup_record["empty"] != (cgroup_record["populated"] == 0 and not cgroup_record["pids"]):
        raise ObservationUnknown("trusted-root observer cgroup fields contradict")
    if group_record["exact_empty"] != (not group_record["pids"]):
        raise ObservationUnknown("trusted-root observer process fields contradict")
    if type(value.get("observed_monotonic_ns")) is not int or value["observed_monotonic_ns"] <= 0:
        raise ObservationUnknown("trusted-root observer timestamp is invalid")
    return value


def _observer_once(cgroup_path: Path, pgid: int, run_id: str, generation: int, run_nonce: str, output: Path) -> int:
    _validate_run_id(run_id)
    if type(generation) is not int or generation < 1:
        raise NativeDemoError("observer generation is invalid")
    _validate_nonce(run_nonce)
    cgroup = NativeCgroup(cgroup_path)
    observation = cgroup.observe()
    proc = ProcObserver().observe(pgid)
    value = {
        "schema": OBSERVER_SCHEMA,
        "run_id": run_id,
        "generation": generation,
        "run_nonce": run_nonce,
        "cgroup": {"path": str(cgroup.path), "pids": list(observation.pids), "populated": observation.populated, "empty": observation.empty},
        "process_group": {"pgid": pgid, "pids": list(proc.pids), "live_pids": list(proc.live_pids), "zombie_pids": list(proc.zombie_pids), "exact_empty": proc.exact_empty},
        "observed_monotonic_ns": max(observation.observed_monotonic_ns, proc.observed_monotonic_ns),
    }
    _write_result(output, value)
    return 0


def _cleanup_cgroup(cgroup: NativeCgroup | None, *, force: bool = True) -> str | None:
    if cgroup is None:
        return None
    first_error: str | None = None
    try:
        observation = cgroup.observe()
    except (NativeDemoError, ObservationUnknown) as error:
        observation = None
        first_error = type(error).__name__
    if force:
        try:
            # Even when the initial census is unavailable, issue the
            # authoritative cgroup kill before reporting cleanup ambiguity.
            if observation is None or not observation.empty:
                cgroup.kill()
            cgroup.wait_empty()
        except (NativeDemoError, ObservationUnknown) as error:
            first_error = first_error or type(error).__name__
    try:
        cgroup.close()
    except (NativeDemoError, ObservationUnknown) as error:
        first_error = first_error or type(error).__name__
    return first_error


def _failure_result(*, run_id: str, run_nonce: str, acceptance: dict[str, Any], error: BaseException, phases: dict[str, Any], cleanup_errors: list[str]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "UNKNOWN",
        "evidence_label": "IMPLEMENTED_INTERNAL_FAILURE",
        "evidence_class": "NATIVE_HARMLESS_DEMONSTRATION",
        "hazard_acceptance_id": acceptance.get("acceptance_id"),
        "hazard_status": "ACCEPTED_FOR_THIS_RUN",
        "artifact_manifest_sha256": acceptance.get("artifact_manifest_sha256"),
        "run_id": run_id,
        "run_nonce": run_nonce,
        "error_class": type(error).__name__,
        "request": None,
        "phases": phases,
        "cleanup": {"complete": not cleanup_errors, "errors": cleanup_errors},
        "limitations": [
            "Failure is retained as UNKNOWN until all owned guest resources are accounted for.",
            "Controller restart is a fresh process over the durable file, not power-loss qualification.",
        ],
    }


def run_demo(
    run_dir: Path,
    *,
    workload_script: Path,
    workload_user: str,
    canary_user: str,
    hazard_acceptance: dict[str, Any],
    run_id: str,
    run_nonce: str,
    native_script: Path | None = None,
    acceptance_path: Path | None = None,
    source_manifest: Path | None = None,
    artifact_manifest: Path | None = None,
    stop_timeout_seconds: float = DEFAULT_STOP_TIMEOUT,
    serial_result: Path | None = None,
    result_path: Path | None = None,
    poweroff_after_result: bool = False,
    _spawn: Callable[..., subprocess.Popen[str]] = _spawn_workload,
) -> dict[str, Any]:
    """Run one accepted native case and persist success or UNKNOWN evidence."""
    run_nonce = _validate_nonce(run_nonce)
    validate_hazard_acceptance(hazard_acceptance, run_nonce=run_nonce)
    if platform.system() != "Linux" or os.name != "posix" or os.geteuid() != 0:
        raise NativeDemoError("native execution requires a disposable Linux root context")
    run_id = _validate_run_id(run_id)
    workload_script = _controlled_workload_script(Path(workload_script).resolve(strict=True))
    native_script = _controlled_root_file(Path(native_script or Path(__file__).resolve()), "native source", maximum=MAX_SEED_FILE_BYTES)
    if acceptance_path is None or source_manifest is None or artifact_manifest is None:
        raise NativeDemoError("accepted record, source manifest, and artifact manifest are required")
    acceptance_path = _controlled_root_file(Path(acceptance_path), "accepted hazard record")
    artifact_manifest_value = validate_artifact_manifest(
        Path(artifact_manifest),
        expected_sha256=hazard_acceptance["artifact_manifest_sha256"],
        native_script=native_script,
        workload_script=workload_script,
    )
    validate_source_manifest(
        Path(source_manifest),
        native_script=native_script,
        workload_script=workload_script,
        acceptance_path=acceptance_path,
        artifact_manifest_path=Path(artifact_manifest),
        run_id=run_id,
        run_nonce=run_nonce,
    )
    try:
        accepted_on_disk = _read_json(acceptance_path, maximum=MAX_RESULT_BYTES)
    except AdmissionRefused as error:
        raise NativeDemoError("accepted hazard record is unreadable") from error
    if accepted_on_disk != hazard_acceptance:
        raise NativeDemoError("in-memory acceptance differs from the root-owned accepted record")
    if hazard_acceptance["source_sha256"] != sha256_file(native_script):
        raise NativeDemoError("accepted source hash does not bind the native source")
    if artifact_manifest_value["_sha256"] != hazard_acceptance["artifact_manifest_sha256"]:
        raise NativeDemoError("accepted artifact manifest does not bind this run")
    if run_dir.exists() or run_dir.is_symlink():
        raise NativeDemoError("native run directory must be fresh")
    # The run root and work ancestor are search-only shared ancestors: the
    # unprivileged target/canary must traverse to their separately owned 0700
    # trees, while admission and all evidence remain private to root.
    run_dir.mkdir(mode=0o711, parents=False)
    os.chmod(run_dir, 0o711)
    control = run_dir / "control"
    work = run_dir / "work"
    control.mkdir(mode=0o700)
    os.chmod(control, 0o700)
    gates = run_dir / "gates"
    gates.mkdir(mode=0o711)
    os.chmod(gates, 0o711)
    work.mkdir(mode=0o711)
    os.chmod(work, 0o711)
    target_dir = work / "target"
    canary_dir = work / "canary"
    target_dir.mkdir(mode=0o700)
    canary_dir.mkdir(mode=0o700)
    target_uid, target_gid = _workload_identity(workload_user)
    canary_uid, canary_gid = _workload_identity(canary_user)
    if target_uid == canary_uid:
        raise NativeDemoError("target and canary must use distinct unprivileged identities")
    os.chown(target_dir, target_uid, target_gid)
    os.chown(canary_dir, canary_uid, canary_gid)
    os.chmod(target_dir, 0o700)
    os.chmod(canary_dir, 0o700)
    _assert_guest_layout(
        run_dir,
        control,
        work,
        gates,
        target_dir,
        canary_dir,
        target_uid=target_uid,
        target_gid=target_gid,
        canary_uid=canary_uid,
        canary_gid=canary_gid,
    )
    state_path = control / "admission.json"
    store = AdmissionStore.create(state_path, run_id, require_root=True)
    observer = ProcObserver()
    target: subprocess.Popen[str] | None = None
    canary: subprocess.Popen[str] | None = None
    target_identity: ProcIdentity | None = None
    canary_identity: ProcIdentity | None = None
    target_pgid: int | None = None
    canary_pgid: int | None = None
    target_cgroup: NativeCgroup | None = None
    canary_cgroup: NativeCgroup | None = None
    phases: dict[str, Any] = {}
    cleanup_errors: list[str] = []
    success_result: dict[str, Any] | None = None
    failure: BaseException | None = None
    target_stop_observation: GroupObservation | None = None
    canary_stop_observation: GroupObservation | None = None
    try:
        _assert_workload_identity_ready(target_dir, uid=target_uid, gid=target_gid, label="target tree")
        _assert_workload_identity_ready(canary_dir, uid=canary_uid, gid=canary_gid, label="canary tree")
        phases["guest_layout_and_uid_ready"] = True
        canary_report = canary_dir / "self-report-g1.json"
        canary_sink = canary_dir / "heartbeat-g1.log"
        canary_gate = gates / "canary-g1.ready"
        canary = _spawn(workload_script, ["--role", "canary", "--sink", str(canary_sink), "--self-report", str(canary_report), "--generation", "1", "--start-gate", str(canary_gate)], uid=canary_uid, gid=canary_gid)
        canary_identity = _owned_identity(observer, canary, canary_uid)
        canary_pgid = canary_identity.pgid
        canary_cgroup = NativeCgroup.create(run_id, 1, "canary")
        canary_cgroup.attach(canary.pid)
        _release_gate(canary_gate)
        canary_before = _wait_report(canary_report, canary, generation=1, role="canary")
        phases["canary_started"] = True

        with store.writer_lock():
            token = store.reserve_start()
            generation = int(token["generation"])
            target_report = target_dir / f"self-report-g{generation}.json"
            target_sink = target_dir / f"fake-sink-g{generation}.log"
            target_gate = gates / f"target-g{generation}.ready"
            target = _spawn(workload_script, ["--role", "target", "--sink", str(target_sink), "--self-report", str(target_report), "--generation", str(generation), "--start-gate", str(target_gate)], uid=target_uid, gid=target_gid)
            target_identity = _owned_identity(observer, target, target_uid)
            target_pgid = target_identity.pgid
            target_cgroup = NativeCgroup.create(run_id, generation, "target")
            target_cgroup.attach(target.pid)
            store.mark_active(target.pid, target_pgid)
            _release_gate(target_gate)
        target_self_report = _wait_report(target_report, target, generation=generation, role="target")
        target_before = observer.observe(target_pgid)
        external_before = _run_external_observer(cgroup=target_cgroup, pgid=target_pgid, run_id=run_id, generation=generation, run_nonce=run_nonce, output=control / "observer-before.json")
        phases["target_started"] = True
        time.sleep(0.25)
        canary_heartbeat_before = _file_size(canary_sink)
        target_bytes_before = _file_size(target_sink)

        request_ns = _now_ns()
        with store.writer_lock():
            store.request_stop("FORCED_STOP")
        if target.poll() is None and observer.identity(target_identity.pid) != target_identity:
            raise NativeDemoError("target identity changed before forced stop")
        target_kill_started_ns, target_kill_ended_ns = target_cgroup.kill()
        cgroup_after = target_cgroup.wait_empty(timeout_seconds=stop_timeout_seconds)
        # cgroup.kill is authoritative for the selected tree.  The process
        # census only waits/read-verifies and reaps the known leader; it does
        # not issue a second killpg signal.
        target_stop_observation = observer.wait_empty(target_pgid, timeout_seconds=stop_timeout_seconds, leader=target)
        store.mark_stopped()
        target_after = observer.observe(target_pgid)
        external_after = _run_external_observer(cgroup=target_cgroup, pgid=target_pgid, run_id=run_id, generation=generation, run_nonce=run_nonce, output=control / "observer-after.json")
        target_self_after = _load_self_report(target_report)
        target_bytes_after = _file_size(target_sink)
        stop_observed_ns = max(target_stop_observation.observed_monotonic_ns, cgroup_after.observed_monotonic_ns)
        time.sleep(0.1)
        target_bytes_stable_after = _file_size(target_sink)
        canary_heartbeat_during_stop = _file_size(canary_sink)
        canary_after_target_stop = _load_self_report(canary_report)
        if target_bytes_after != target_bytes_stable_after:
            raise NativeDemoError("target fake sink changed after the stop observation")
        phases["forced_stop"] = True

        relaunch_refused = _fresh_controller_relaunch_check(state_path, run_id=run_id, generation=generation)
        restarted = store.reload()
        phases["controller_restart_relaunch_refused"] = True
        reset_observation = {"run_id": run_id, "generation": generation, "pid": target_identity.pid, "pgid": target_identity.pgid, "starttime": target_identity.starttime, "session": target_identity.session, "uid": target_identity.uid, "exact_empty": target_stop_observation.exact_empty and target_after.exact_empty and external_after["cgroup"]["empty"], "observed_monotonic_ns": stop_observed_ns}
        restarted.reset(observed_stopped=True, observation=reset_observation)
        post_reset = restarted.reload()
        if post_reset.state["active_pid"] is not None:
            raise NativeDemoError("explicit reset unexpectedly launched a workload")
        phases["explicit_reset_no_auto_start"] = True

        second_cgroup: NativeCgroup | None = None
        second_target: subprocess.Popen[str] | None = None
        second_pgid: int | None = None
        try:
            with restarted.writer_lock():
                token2 = restarted.reserve_start()
                generation2 = int(token2["generation"])
                second_report = target_dir / f"self-report-g{generation2}.json"
                second_sink = target_dir / f"fake-sink-g{generation2}.log"
                second_gate = gates / f"target-g{generation2}.ready"
                second_target = _spawn(workload_script, ["--role", "target", "--sink", str(second_sink), "--self-report", str(second_report), "--generation", str(generation2), "--start-gate", str(second_gate)], uid=target_uid, gid=target_gid)
                second_identity = _owned_identity(observer, second_target, target_uid)
                second_pgid = second_identity.pgid
                second_cgroup = NativeCgroup.create(run_id, generation2, "target")
                second_cgroup.attach(second_target.pid)
                restarted.mark_active(second_target.pid, second_pgid)
                _release_gate(second_gate)
            _wait_report(second_report, second_target, generation=generation2, role="target")
            with restarted.writer_lock():
                restarted.request_stop("TEARDOWN")
            if second_target.poll() is None and observer.identity(second_identity.pid) != second_identity:
                raise NativeDemoError("second target identity changed before teardown")
            second_cgroup.kill()
            second_cgroup.wait_empty(timeout_seconds=stop_timeout_seconds)
            second_stop = observer.wait_empty(second_pgid, timeout_seconds=stop_timeout_seconds, leader=second_target)
            restarted.mark_stopped()
            phases["explicit_relaunch_and_teardown"] = True
        finally:
            cleanup_error = _cleanup_cgroup(second_cgroup)
            if cleanup_error:
                cleanup_errors.append(f"second_target_cgroup:{cleanup_error}")
            if second_target is not None and second_cgroup is not None:
                try:
                    second_target.wait(timeout=stop_timeout_seconds)
                except (OSError, subprocess.TimeoutExpired) as error:
                    cleanup_errors.append(f"second_target_reap:{type(error).__name__}")
                if second_target.poll() is None and second_pgid is not None:
                    try:
                        _terminate_group(observer, second_pgid, timeout_seconds=stop_timeout_seconds, leader=second_target)
                    except NativeDemoError as error:
                        cleanup_errors.append(f"second_target_escape:{type(error).__name__}")
            elif second_target is not None and second_pgid is not None and second_target.poll() is None:
                try:
                    _terminate_group(observer, second_pgid, timeout_seconds=stop_timeout_seconds, leader=second_target)
                except NativeDemoError as error:
                    cleanup_errors.append(f"second_target_group:{type(error).__name__}")

        with store.writer_lock():
            store.request_stop("TEARDOWN")
        if canary.poll() is None and observer.identity(canary_identity.pid) != canary_identity:
            raise NativeDemoError("canary identity changed before teardown")
        canary_cgroup.kill()
        canary_cgroup.wait_empty(timeout_seconds=stop_timeout_seconds)
        canary_stop_observation = observer.wait_empty(canary_pgid, timeout_seconds=stop_timeout_seconds, leader=canary)
        canary.wait(timeout=stop_timeout_seconds)
        canary_after = _load_self_report(canary_report)
        canary_heartbeat_after = _file_size(canary_sink)
        final_state = restarted.reload().state
        success_result = {
            "schema": SCHEMA,
            "status": "PASS",
            "evidence_label": "IMPLEMENTED_INTERNAL",
            "evidence_class": "NATIVE_HARMLESS_DEMONSTRATION",
            "hazard_acceptance_id": hazard_acceptance["acceptance_id"],
            "hazard_status": "ACCEPTED_FOR_THIS_RUN",
            "artifact_manifest_sha256": hazard_acceptance["artifact_manifest_sha256"],
            "run_id": run_id,
            "run_nonce": run_nonce,
            "request": {"kind": "FORCED_STOP", "monotonic_ns": request_ns},
            "target_self_report": target_self_report,
            "target_self_report_after_stop": target_self_after,
            "owned_identity": {
                "target": {
                    "pid": target_identity.pid,
                    "pgid": target_identity.pgid,
                    "session": target_identity.session,
                    "starttime": target_identity.starttime,
                    "uid": target_identity.uid,
                },
                "canary": {
                    "pid": canary_identity.pid,
                    "pgid": canary_identity.pgid,
                    "session": canary_identity.session,
                    "starttime": canary_identity.starttime,
                    "uid": canary_identity.uid,
                },
            },
            "observer": {
                "before_pids": target_before.pids,
                "after_pids": target_after.pids,
                "stopped": target_stop_observation.exact_empty and target_after.exact_empty,
                "cgroup_empty": cgroup_after.empty and external_after["cgroup"]["empty"],
                "external_before": external_before,
                "external_after": external_after,
                "stop_observed_monotonic_ns": stop_observed_ns,
                "stop_latency_ns": max(0, stop_observed_ns - request_ns),
                "cgroup_kill_started_ns": target_kill_started_ns,
                "cgroup_kill_ended_ns": target_kill_ended_ns,
                "second_stop_stopped": second_stop.exact_empty,
            },
            "controller_restart": {
                "fresh_controller_process": True,
                "durable_latch_reloaded": True,
                "relaunch_refused": relaunch_refused,
                "reset_explicit": True,
                "reset_auto_start": False,
                "final_mode": final_state["mode"],
            },
            "canary": {
                "self_report_before": canary_before,
                "self_report_after": canary_after,
                "self_report_after_target_stop": canary_after_target_stop,
                "continued_during_stop": canary_heartbeat_during_stop > canary_heartbeat_before,
                "heartbeat_bytes_before": canary_heartbeat_before,
                "heartbeat_bytes_during_target_stop": canary_heartbeat_during_stop,
                "heartbeat_bytes_after": canary_heartbeat_after,
                "separate_uid": target_uid != canary_uid,
            },
            "resource_accounting": {
                "target_group_empty": target_after.exact_empty and target_stop_observation.exact_empty,
                "canary_stopped_after_observation": canary_stop_observation.exact_empty,
                "fake_bytes_before_stop": target_bytes_before,
                "fake_bytes_after_stop": target_bytes_after,
                "fake_bytes_stability_sample": target_bytes_stable_after,
                "fake_bytes_stable_after_stop": target_bytes_after == target_bytes_stable_after,
                "network": "none-required",
            },
            "phases": phases,
            "cleanup": {"complete": not cleanup_errors, "errors": cleanup_errors},
            "limitations": [
                "Private cgroup-v2 evidence covers the selected allocation and descendants; compromised kernel/hypervisor is out of scope.",
                "The observer is a separate trusted-root process/logical check, not a privilege-separated assurance.",
                "Controller restart is a fresh process over the durable file, not power-loss qualification.",
                "This harmless workload has no real secret, network, host-share, or third-party effect.",
                "Whole-VM stop is not selective containment and is not measured here.",
            ],
        }
    except (NativeDemoError, OSError, ValueError, subprocess.SubprocessError) as error:
        failure = error
    finally:
        try:
            with store.writer_lock():
                store.request_stop("RECOVERY")
        except (NativeDemoError, OSError) as error:
            cleanup_errors.append(f"latch:{type(error).__name__}")
        for label, cgroup in (("target_cgroup", target_cgroup), ("canary_cgroup", canary_cgroup)):
            cleanup_error = _cleanup_cgroup(cgroup)
            if cleanup_error:
                cleanup_errors.append(f"{label}:{cleanup_error}")
        for label, process, pgid, cgroup in (("target_group", target, target_pgid, target_cgroup), ("canary_group", canary, canary_pgid, canary_cgroup)):
            if process is None:
                continue
            if cgroup is not None:
                # The cgroup is the authoritative ownership boundary.  After
                # its kill/empty attempt, only reap the known Popen leader;
                # never issue a secondary process-group kill.
                try:
                    process.wait(timeout=stop_timeout_seconds)
                except (OSError, subprocess.TimeoutExpired) as error:
                    cleanup_errors.append(f"{label}_reap:{type(error).__name__}")
                if process.poll() is None and pgid is not None:
                    # An attached process that remains live after cgroup.kill
                    # is an ownership anomaly.  Use the exact bound PGID only
                    # as emergency cleanup and retain UNKNOWN evidence.
                    try:
                        _terminate_group(observer, pgid, timeout_seconds=stop_timeout_seconds, leader=process)
                    except NativeDemoError as error:
                        cleanup_errors.append(f"{label}_escape:{type(error).__name__}")
            elif pgid is not None and process.poll() is None:
                # A cgroup may not have been created if setup failed before
                # attachment.  This fallback is not used after an authoritative
                # cgroup kill and is not part of the containment claim.
                try:
                    _terminate_group(observer, pgid, timeout_seconds=stop_timeout_seconds, leader=process)
                except NativeDemoError as error:
                    cleanup_errors.append(f"{label}:{type(error).__name__}")

    final_result_path = Path(result_path) if result_path is not None else run_dir / "result.json"
    if not final_result_path.resolve().is_relative_to(run_dir.resolve()):
        raise NativeDemoError("result path escaped the fresh run directory")
    if failure is not None:
        result = _failure_result(run_id=run_id, run_nonce=run_nonce, acceptance=hazard_acceptance, error=failure, phases=phases, cleanup_errors=cleanup_errors)
        _write_result(final_result_path, result)
        if serial_result is not None:
            _emit_serial_result(Path(serial_result), run_nonce, result)
            if poweroff_after_result:
                _poweroff_guest()
        raise failure
    if success_result is None:
        raise NativeDemoError("native case completed without a result")
    if cleanup_errors:
        success_result["status"] = "UNKNOWN"
        success_result["cleanup"] = {"complete": False, "errors": cleanup_errors}
    _write_result(final_result_path, success_result)
    if serial_result is not None:
        _emit_serial_result(Path(serial_result), run_nonce, success_result)
        if poweroff_after_result:
            _poweroff_guest()
    return success_result


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() and not path.is_symlink() else 0
    except OSError:
        return 0


def default_plan() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "OFF_BY_DEFAULT",
        "native_execution": "requires --execute plus an independently accepted nonce-bound hazard envelope",
        "default_action": "prints this plan; performs no process, cgroup, VM, network, or file mutation",
        "response": "forced cgroup stop is independent of detector output",
        "observer": "separate trusted-root process/logical read-only observation over cgroup-v2 and /proc; this is not privilege-separated assurance and self-report is distinct",
        "admission": "root-owned atomic stop latch with a writer lock; corrupt, missing, pending, or failed state is fail-closed",
    }


def _load_acceptance(path: Path, *, run_nonce: str | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeDemoError("hazard acceptance file is unreadable") from error
    if not isinstance(value, dict):
        raise NativeDemoError("hazard acceptance file is invalid")
    return validate_hazard_acceptance(value, run_nonce=run_nonce)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="requires an accepted envelope")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--workload-script", type=Path)
    parser.add_argument("--native-script", type=Path)
    parser.add_argument("--workload-user", default="counter-v2")
    parser.add_argument("--canary-user", default="counter-v2-canary")
    parser.add_argument("--run-id")
    parser.add_argument("--nonce")
    parser.add_argument("--hazard-acceptance", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--artifact-manifest", type=Path)
    parser.add_argument("--serial-result", type=Path)
    parser.add_argument("--result-path", type=Path)
    parser.add_argument("--poweroff-after-result", action="store_true")
    parser.add_argument("--controller-relaunch-check", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--observer-once", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cgroup", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--pgid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--generation", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--state", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.controller_relaunch_check:
        if args.state is None:
            return 2
        try:
            store = AdmissionStore(args.state, require_root=True)
            try:
                store.reserve_start()
            except AdmissionRefused:
                if store.state["mode"] != "STOP_LATCHED" or store.state["active_pid"] is not None:
                    return 2
                print(f"RELAUNCH_REFUSED {store.state['run_id']} {store.state['generation']}")
                return 0
            return 1
        except (NativeDemoError, OSError, ValueError):
            return 2
    if args.observer_once:
        if args.cgroup is None or args.pgid is None or args.run_id is None or args.generation is None or args.output is None or args.nonce is None:
            return 2
        try:
            return _observer_once(args.cgroup, args.pgid, args.run_id, args.generation, args.nonce, args.output)
        except (NativeDemoError, OSError, ValueError):
            return 2
    if not args.execute:
        print(json.dumps(default_plan(), sort_keys=True))
        return 0
    required = (args.run_dir, args.workload_script, args.run_id, args.nonce, args.hazard_acceptance, args.native_script, args.source_manifest, args.artifact_manifest)
    if any(item is None for item in required):
        print("NATIVE_DEMO_REFUSED: run, source, nonce, source/artifact manifests, and accepted record are required", file=sys.stderr)
        return 2
    try:
        acceptance = _load_acceptance(args.hazard_acceptance, run_nonce=args.nonce)
        result = run_demo(
            args.run_dir,
            workload_script=args.workload_script,
            native_script=args.native_script,
            workload_user=args.workload_user,
            canary_user=args.canary_user,
            hazard_acceptance=acceptance,
            acceptance_path=args.hazard_acceptance,
            source_manifest=args.source_manifest,
            artifact_manifest=args.artifact_manifest,
            run_id=args.run_id,
            run_nonce=args.nonce,
            serial_result=args.serial_result,
            result_path=args.result_path,
            poweroff_after_result=args.poweroff_after_result,
        )
    except (NativeDemoError, OSError, ValueError) as error:
        print(f"NATIVE_DEMO_REFUSED: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
