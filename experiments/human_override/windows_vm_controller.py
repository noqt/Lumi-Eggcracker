"""Mock-only design of a trusted-host VM emergency stop; NO native adapter.

The only accepted backend is the exact MockKernel class below. It neither
imports ctypes nor creates, opens, resumes, or terminates an operating-system
process. Mock handles are Python objects, not Windows handles.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from experiments.human_override.model import bounded_json

CONTRACT = Path(__file__).with_name("windows_vm_contract.v1.json")
MAX_COUNTER = 1_000_000_000


@dataclass
class MockProcess:
    identity: dict
    alive: bool = True
    suspended: bool = True
    termination_pending: bool = False
    exit_code: int | None = None
    closed: bool = False


@dataclass
class MockJob:
    processes: list = field(default_factory=list)
    closed: bool = False
    inherited: bool = False
    breakaway: bool = False
    kill_on_close: bool = True
    active_process_limit: int = 1


@dataclass(frozen=True)
class MockQueryHandle:
    process: MockProcess
    rights: frozenset = frozenset({"query", "synchronize"})


class MockKernel:
    """Deliberate simulator, not evidence of Windows API or job semantics."""

    def __init__(self):
        self.fail_at = set()
        self.events = []
        self.resumes = 0
        self.terminations = 0
        self.serial = 0
        self.query_handles = []

    def _check(self, action):
        self.events.append(action)
        if action in self.fail_at:
            raise OSError("injected mock failure")

    def verify_artifacts(self):
        self._check("verify_artifacts")

    def create_job(self):
        self._check("create_job")
        return MockJob()

    def spawn_suspended(self, job, generation, config_hash, *, atomic_job, inherit, allocation="A"):
        self._check("spawn_suspended")
        if (allocation not in {"A", "B"} or not atomic_job or inherit
                or job.closed or job.inherited or job.breakaway
                or not job.kill_on_close or job.active_process_limit != 1 or job.processes):
            raise OSError("required atomic containment unavailable")
        self.serial += 1
        process = MockProcess({"allocation": allocation, "generation": generation,
                               "instance": f"mock-instance-{self.serial}",
                               "pid": self.serial, "creation_time": self.serial * 100,
                               "image": "MOCK_PINNED_QEMU", "config_sha256": config_hash})
        job.processes.append(process)  # Atomic in the model, never a fallback.
        return process

    def validate(self, process, expected):
        self._check("validate_handle")
        return process is not None and not process.closed and process.identity == expected

    def resume(self, process):
        self._check("resume")
        if process.closed or not process.alive or not process.suspended:
            raise OSError("invalid mock resume")
        process.suspended = False
        self.resumes += 1

    def terminate(self, process):
        self._check("terminate")
        if process.closed or not process.alive:
            raise OSError("target not live")
        self.terminations += 1
        process.termination_pending = True  # Dispatch is NOT exit.

    def duplicate_for_judge(self, process):
        self._check("duplicate_query_handle")
        if process is None or process.closed:
            raise OSError("no retained target")
        handle = MockQueryHandle(process)
        self.query_handles.append(handle)
        return handle

    @staticmethod
    def complete_exit(process):
        process.alive = False
        process.exit_code = 91

    def close_job(self, job):
        self._check("close_job")
        if job is not None:
            if job.inherited or not job.kill_on_close:
                raise OSError("last-handle cleanup unconfirmed")
            job.closed = True
            for process in job.processes:
                self.complete_exit(process)


class Controller:
    """Single-writer mock controller. Principal is trusted driver input.

    Restart never reacquires a PID. A fresh mock judge must still retain the
    original query handle to report exit. Disk writes model process-restart
    persistence, not Windows power-loss durability.
    """

    def __init__(self, path, kernel, *, create=False):
        if type(kernel) is not MockKernel:
            raise TypeError("only exact inert MockKernel is permitted")
        self.path = Path(path)
        self.kernel = kernel
        self.process = None
        self.job = None
        self.lock = threading.RLock()
        self.storage_ok = True
        self.closed = False
        self.config_hash = hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
        self.state = {"schema": "mock-vm-controller.v1", "generation": 0, "epoch": 0,
                      "sequence": 0, "latched": False, "approved": False,
                      "phase": "IDLE", "identity": None, "config_sha256": self.config_hash}
        if create:
            if self.path.exists():
                raise FileExistsError("state already exists")
            if not self._save():
                raise OSError("initial state failed")
        else:
            try:
                loaded = bounded_json(self.path.read_bytes())
                self._validate_state(loaded)
                self.state = loaded
                # Every controller restart inhibits launch, including an old snapshot
                # left by a failed STOP write. It never restores approval or a handle.
                self.state["latched"] = True
                self.state["approved"] = False
                self.state["phase"] = "RECOVERED_INHIBITED"
                if self.state["epoch"] == MAX_COUNTER:
                    raise ValueError("epoch exhausted")
                self.state["epoch"] += 1
                self._save()
            except (OSError, ValueError, KeyError, TypeError):
                self._storage_failure()

    def _validate_state(self, row):
        if not isinstance(row, dict) or set(row) != set(self.state):
            raise ValueError("state shape")
        if row["schema"] != self.state["schema"] or row["config_sha256"] != self.config_hash:
            raise ValueError("state identity")
        for key in ("generation", "epoch", "sequence"):
            if type(row[key]) is not int or not 0 <= row[key] <= MAX_COUNTER:
                raise ValueError("counter")
        for key in ("latched", "approved"):
            if type(row[key]) is not bool:
                raise ValueError("boolean")
        if row["phase"] not in {"IDLE", "START_INTENT", "IDENTIFIED_SUSPENDED", "RUNNING",
                                "STOP_REQUESTED", "RECOVERED_INHIBITED", "UNKNOWN"}:
            raise ValueError("phase")
        identity = row["identity"]
        if identity is not None:
            if (not isinstance(identity, dict) or set(identity) != {
                    "allocation", "generation", "instance", "pid", "creation_time",
                    "image", "config_sha256"} or identity["allocation"] != "A"
                    or identity["generation"] != row["generation"]
                    or identity["config_sha256"] != self.config_hash
                    or identity["image"] != "MOCK_PINNED_QEMU"
                    or not isinstance(identity["instance"], str)
                    or not identity["instance"].startswith("mock-instance-")):
                raise ValueError("process identity")
            for key in ("pid", "creation_time"):
                if type(identity[key]) is not int or not 0 < identity[key] <= MAX_COUNTER:
                    raise ValueError("process counter")

    def _storage_failure(self):
        self.storage_ok = False  # Sticky for this controller lifetime.
        self.state.update(latched=True, approved=False, phase="UNKNOWN")

    def _save(self):
        if not self.storage_ok:
            return False
        try:
            pending = self.path.with_suffix(".pending")
            with pending.open("x", encoding="utf-8") as stream:
                json.dump(self.state, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, self.path)
            self.kernel.events.append("persist:" + self.state["phase"])
            return True
        except (OSError, ValueError, TypeError):
            self._storage_failure()
            return False

    def command(self, principal, operation, *, allocation, generation, epoch, sequence,
                judge=None):
        with self.lock:
            if (self.closed or type(principal) is not str or type(operation) is not str
                    or type(allocation) is not str
                    or not 0 < len(principal) <= 16 or not 0 < len(operation) <= 16
                    or not 0 < len(allocation) <= 16
                    or principal != "human" or allocation != "A"
                    or operation not in {"approve", "start", "stop", "reset"}
                    or any(type(value) is not int or not 0 <= value <= MAX_COUNTER
                           for value in (generation, epoch, sequence))
                    or generation != self.state["generation"] or epoch != self.state["epoch"]
                    or sequence <= self.state["sequence"]):
                return "DENIED"
            if not self.storage_ok and operation != "stop":
                return "DENIED_DURABILITY_UNCONFIRMED"
            self.state["sequence"] = sequence
            if operation == "stop":
                return self._stop()
            if operation == "reset":
                return self._reset(judge)
            if self.state["latched"]:
                self._save()
                return "DENIED"
            if operation == "approve":
                self.state["approved"] = True
                return "OK" if self._save() else "UNKNOWN"
            return self._start()

    def _start(self):
        if (not self.state["approved"] or self.state["phase"] != "IDLE"
                or self.state["generation"] == MAX_COUNTER):
            self._save()
            return "DENIED"
        self.state.update(generation=self.state["generation"] + 1, approved=False,
                          phase="START_INTENT", identity=None)
        if not self._save():
            return "UNKNOWN"
        try:
            self.kernel.verify_artifacts()
            self.job = self.kernel.create_job()
            self.process = self.kernel.spawn_suspended(
                self.job, self.state["generation"], self.config_hash, atomic_job=True, inherit=False)
            self.state["identity"] = dict(self.process.identity)
            self.state["phase"] = "IDENTIFIED_SUSPENDED"
            if not self._save() or self.state["latched"]:
                raise OSError("inhibited before resume")
            if not self.kernel.validate(self.process, self.state["identity"]):
                raise OSError("identity mismatch")
            if self.state["latched"] or not self.storage_ok:
                raise OSError("stop won startup race")
            self.kernel.resume(self.process)
            self.state["phase"] = "RUNNING"
            if not self._save():
                raise OSError("running record failed")
            return "MOCK_RUNNING"
        except (OSError, ValueError):
            self.state.update(latched=True, approved=False, phase="UNKNOWN")
            self._save()
            try:
                self.kernel.close_job(self.job)
            except OSError:
                pass  # Never infer exit from attempted cleanup.
            return "UNKNOWN"

    def _stop(self):
        if not self.state["latched"] and self.state["epoch"] < MAX_COUNTER:
            self.state["epoch"] += 1
        self.state.update(latched=True, approved=False, phase="STOP_REQUESTED")
        durable = self._save()
        try:
            if not self.kernel.validate(self.process, self.state["identity"]):
                return "UNKNOWN"
            self.kernel.terminate(self.process)
        except OSError:
            return "UNKNOWN"
        return "MOCK_STOP_DISPATCHED" if durable else "MOCK_STOP_DISPATCHED_DURABILITY_UNCONFIRMED"

    def observed(self, judge):
        # The registered query capability, not an arbitrary object's success
        # string, authorizes this mock observation. Same-process memory remains trusted.
        from experiments.human_override.windows_vm_lab import MockJudge

        if (type(judge) is not MockJudge or self.state["identity"] is None
                or not any(handle is judge.handle for handle in self.kernel.query_handles)
                or judge.handle.rights != frozenset({"query", "synchronize"})):
            return "UNKNOWN"
        try:
            return MockJudge.observe(judge, dict(self.state["identity"]))
        except (OSError, ValueError, AttributeError):
            return "UNKNOWN"

    def _reset(self, judge):
        if (not self.state["latched"] or self.state["epoch"] == MAX_COUNTER
                or self.observed(judge) != "MOCK_VERIFIED_PRIMARY_EXIT"):
            self._save()
            return "DENIED"
        try:
            self.kernel.close_job(self.job)
        except OSError:
            return "UNKNOWN"
        self.state.update(epoch=self.state["epoch"] + 1, latched=False,
                          approved=False, phase="IDLE")
        if not self._save():
            return "UNKNOWN"
        self.process = None
        self.job = None
        return "OK"

    def crash(self):
        """Model controller loss: last unnamed job handle closes, never reopens."""
        with self.lock:
            self.closed = True
            try:
                self.kernel.close_job(self.job)
            finally:
                self.process = None
                self.job = None
