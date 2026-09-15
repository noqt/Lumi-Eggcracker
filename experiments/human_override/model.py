"""Inert human-stop state machine. Python objects are NOT an isolation boundary."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_INTEGER = 1_000_000_000
MAX_BYTES = 65_536
AUDIT_LIMIT = 64
OBSERVATION_TTL = 5
PRINCIPALS = {"human", "scheduler", "guest"}
OPERATIONS = {"approve", "start", "stop", "reset"}


def bounded_json(raw: bytes):
    """Reject ambiguous/oversized JSON before it can influence model state."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError("JSON byte limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("non-finite JSON number")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=invalid_constant)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("invalid JSON encoding/depth") from exc
    remaining = 4096

    def check(value, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            raise ValueError("JSON structural limit")
        if type(value) is dict:
            for key, child in value.items():
                check(key, depth + 1)
                check(child, depth + 1)
        elif type(value) is list:
            for child in value:
                check(child, depth + 1)
        elif type(value) is str:
            if len(value) > 256:
                raise ValueError("JSON string limit")
        elif type(value) is int:
            if not 0 <= value <= MAX_INTEGER:
                raise ValueError("JSON integer limit")
        elif value is not None and type(value) is not bool:
            raise ValueError("unsupported JSON value")

    check(result)
    return result


@dataclass
class Allocation:
    generation: int = 1
    epoch: int = 0
    latched: bool = False
    approved: bool = False
    control: bool = True
    sequence: dict = field(default_factory=lambda: {p: 0 for p in sorted(PRINCIPALS)})
    audit: list = field(default_factory=list)
    dropped: int = 0


@dataclass
class Execution:
    generation: int = 1
    running: bool = False
    connected: bool = False
    remote_running: bool = False
    launches: int = 0
    revision: int = 0
    effects: list = field(default_factory=list)


class World:
    """Trusted synthetic lifecycle/observer fixture, independent of guest claims."""

    def __init__(self):
        self.allocations = {key: Execution() for key in ("A", "B")}
        self.tick = 0

    def advance(self, ticks=1):
        if type(ticks) is not int or not 0 <= ticks <= MAX_INTEGER - self.tick:
            raise ValueError("invalid simulated time")
        self.tick += ticks

    def effect(self, allocation, kind):
        if kind not in {"read", "export", "child", "restart", "lateral", "tamper"}:
            raise ValueError("unknown synthetic effect")
        execution = self.allocations[allocation]
        reached = execution.running and (kind != "export" or execution.connected)
        if reached:
            execution.effects.append({"kind": kind, "tick": self.tick})
        return reached


class Controller:
    """Single trusted writer. Not thread-safe, authenticated, or power-loss qualified.

    A command principal is supplied by the trusted test driver, never decoded from
    a guest payload. Only a successfully persisted transition may change World.
    """

    def __init__(self, path: Path, world: World, *, create=False):
        self.path = Path(path)
        self.world = world
        self.allocations = {key: Allocation() for key in ("A", "B")}
        self.observations = {}
        self.storage_ok = True
        if create:
            if self.path.exists() or self.path.is_symlink():
                raise FileExistsError("refuse existing controller state")
            self._persist(self.allocations)
        else:
            try:
                if self.path.is_symlink() or self.path.with_suffix(".pending").exists():
                    raise ValueError("state symlink or interrupted write")
                with self.path.open("rb") as stream:
                    data = bounded_json(stream.read(MAX_BYTES + 1))
                if type(data) is not dict or set(data) != {"schema", "allocations"}:
                    raise ValueError("state envelope")
                if data["schema"] != "human-stop-state.v1":
                    raise ValueError("state schema")
                if type(data["allocations"]) is not dict or set(data["allocations"]) != {"A", "B"}:
                    raise ValueError("state allocation scope")
                loaded = {}
                for key, row in data["allocations"].items():
                    self._validate_record(row)
                    loaded[key] = Allocation(**row)
                self.allocations = loaded
            except (OSError, ValueError, TypeError):
                self.storage_ok = False

    @staticmethod
    def _validate_record(row):
        if type(row) is not dict or set(row) != set(asdict(Allocation())):
            raise ValueError("state fields")
        for key in ("generation", "epoch", "dropped"):
            if type(row[key]) is not int or not 0 <= row[key] <= MAX_INTEGER:
                raise ValueError("state integer")
        if row["generation"] < 1:
            raise ValueError("state generation")
        if any(type(row[key]) is not bool for key in ("latched", "approved", "control")):
            raise ValueError("state boolean")
        if row["latched"] and row["approved"]:
            raise ValueError("latched approval")
        seq = row["sequence"]
        if type(seq) is not dict or set(seq) != PRINCIPALS:
            raise ValueError("state principals")
        if any(type(n) is not int or not 0 <= n <= MAX_INTEGER for n in seq.values()):
            raise ValueError("state sequence")
        if type(row["audit"]) is not list or len(row["audit"]) > AUDIT_LIMIT:
            raise ValueError("state audit")
        if any(type(item) is not str or len(item) > 64 for item in row["audit"]):
            raise ValueError("state audit entry")

    def _persist(self, records):
        payload = json.dumps({"schema": "human-stop-state.v1", "allocations": {
            key: asdict(row) for key, row in records.items()
        }}, sort_keys=True).encode("utf-8")
        bounded_json(payload)
        # Parent is a fresh run-owned directory. No guest filesystem access is modelled.
        temporary = self.path.with_suffix(".pending")
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def _commit(self, records):
        try:
            self._persist(records)
        except (OSError, ValueError):
            self.storage_ok = False
            self.observations.clear()
            return False
        self.allocations = records
        return True

    def command(self, principal, event):
        """Flat bounded command; epoch and generation are mandatory fences."""
        if type(principal) is not str or principal not in PRINCIPALS:
            return "INVALID"
        if type(event) is not dict or set(event) != {
            "op", "allocation", "generation", "sequence", "epoch"
        }:
            return "INVALID"
        if any(type(event[k]) is not str for k in ("op", "allocation")):
            return "INVALID"
        if event["op"] not in OPERATIONS or event["allocation"] not in self.allocations:
            return "INVALID"
        if any(type(event[k]) is not int or not 0 <= event[k] <= MAX_INTEGER
               for k in ("generation", "sequence", "epoch")):
            return "INVALID"
        if not self.storage_ok:
            return "STORAGE_UNKNOWN"
        key, op = event["allocation"], event["op"]
        current = self.allocations[key]
        if (event["generation"], event["epoch"]) != (current.generation, current.epoch):
            return "STALE_SCOPE"
        if event["sequence"] <= current.sequence[principal]:
            return "REPLAY"
        if principal == "guest" or (op != "start" and principal != "human"):
            return "DENIED"
        records = copy.deepcopy(self.allocations)
        row = records[key]
        row.sequence[principal] = event["sequence"]
        result = "OK"
        execution = self.world.allocations[key]
        if op == "stop":
            if not row.latched:
                if row.epoch == MAX_INTEGER:
                    return "EXHAUSTED"
                row.epoch += 1
            row.latched, row.approved = True, False
        elif op == "reset":
            if not row.latched or self.status(key)["observed"] != "VERIFIED_STOPPED":
                result = "DENIED"
            else:
                if row.epoch == MAX_INTEGER:
                    return "EXHAUSTED"
                row.epoch += 1
                row.latched, row.approved = False, False
        elif op == "approve":
            if row.latched or not row.control:
                result = "DENIED"
            else:
                row.approved = True
        elif (row.latched or not row.control or not row.approved
              or execution.generation != row.generation or execution.running
              or execution.remote_running):
            result = "DENIED"
        row.audit.append(f"{op}:{result}")
        if len(row.audit) > AUDIT_LIMIT:
            row.audit.pop(0)
            row.dropped = min(MAX_INTEGER, row.dropped + 1)
        if not self._commit(records):
            return "STORAGE_UNKNOWN"
        if op in {"stop", "reset", "start"}:
            self.observations.pop(key, None)
        if op == "start" and result == "OK":
            execution.running = execution.connected = execution.remote_running = True
            execution.launches += 1
            execution.revision += 1
        return result

    def set_control(self, allocation, available):
        """Trusted fixture action, not a guest command or proof of shutdown."""
        if type(available) is not bool or allocation not in self.allocations:
            raise ValueError("control input")
        if not self.storage_ok:
            return False
        records = copy.deepcopy(self.allocations)
        records[allocation].control = available
        records[allocation].approved = False
        self.observations.pop(allocation, None)
        return self._commit(records)

    def adapter(self, allocation, *, cancel_remote=False, fail=False):
        """Fake adapter reads the durable latch. Disconnection is NOT cancellation."""
        row, execution = self.allocations[allocation], self.world.allocations[allocation]
        if (not self.storage_ok or not row.latched or not row.control or fail
                or row.generation != execution.generation):
            return False
        execution.running = execution.connected = False
        if cancel_remote:
            execution.remote_running = False
        execution.revision += 1
        self.observations.pop(allocation, None)
        return True

    def observe(self, allocation, *, fail=False):
        """Only trusted World is sampled; no guest-supplied observation fields."""
        self.observations.pop(allocation, None)
        row, execution = self.allocations[allocation], self.world.allocations[allocation]
        if (fail or not self.storage_ok or not row.control
                or row.generation != execution.generation):
            return "UNKNOWN"
        state = "RUNNING" if execution.running or execution.remote_running else "VERIFIED_STOPPED"
        self.observations[allocation] = (
            row.generation, row.epoch, self.world.tick, execution.revision, state
        )
        return state

    def status(self, allocation):
        row, execution = self.allocations[allocation], self.world.allocations[allocation]
        observation = self.observations.get(allocation)
        observed = "UNKNOWN"
        if observation and self.storage_ok and row.control:
            generation, epoch, tick, revision, state = observation
            if (generation == row.generation == execution.generation and epoch == row.epoch
                    and 0 <= self.world.tick - tick <= OBSERVATION_TTL
                    and revision == execution.revision):
                observed = state
        return {
            "generation": row.generation, "epoch": row.epoch,
            "admission": "ALLOWED" if (self.storage_ok and row.control and row.approved
                                        and not row.latched) else "INHIBITED",
            "stop": "REQUESTED" if self.storage_ok and row.latched else "NONE",
            "observed": observed, "storage_ok": self.storage_ok,
        }

    def replace_allocation(self, allocation):
        """Trusted re-enrolment after reset; never reachable from guest/name churn."""
        row = self.allocations[allocation]
        execution = self.world.allocations[allocation]
        if (not self.storage_ok or row.latched or not row.control or execution.running
                or execution.remote_running or row.generation == MAX_INTEGER):
            return False
        records = copy.deepcopy(self.allocations)
        records[allocation] = Allocation(generation=row.generation + 1)
        if not self._commit(records):
            return False
        self.world.allocations[allocation] = Execution(generation=row.generation + 1)
        self.observations.pop(allocation, None)
        return True
