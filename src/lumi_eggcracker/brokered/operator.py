"""Synthetic, unprivileged brokered-operator demonstration.

This module has no process, shell, network, secret, or filesystem-target action.
Its only protected effect is a journalled increment of one synthetic counter.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ANCHOR_NAME = "operator.anchor.json"
JOURNAL_NAME = "operator.journal"
LOCK_NAME = "operator.lock"
WITNESS_NAME = "operator.witness.json"
ANCHOR_SCHEMA = "lumi-eggcracker.brokered-anchor.v1"
WITNESS_SCHEMA = "lumi-eggcracker.brokered-witness.v1"
CAPABILITY_SCHEMA = "lumi-eggcracker.brokered-capability.v1"
REQUEST_SCHEMA = "lumi-eggcracker.brokered-request.v1"
MAX_REQUEST_BYTES = 4096
MAX_CAPABILITY_BYTES = 1024
MAX_ANCHOR_BYTES = 4096
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_RUNS = 64
MAX_ACTIONS_PER_RUN = 4
MAX_REPLAY_KEYS = MAX_RUNS * MAX_ACTIONS_PER_RUN
MAX_PENDING_BYTES = 64 * 1024
MAX_LIFETIME_MS = 60_000
MAX_RECEIPT_BYTES = 512
MAX_JOURNAL_EVENTS = 1 + MAX_RUNS * (1 + (2 * MAX_ACTIONS_PER_RUN) + 1)
ACTION = "increment"
TARGET = "synthetic.protected-counter"
UNRELATED_CANARY_ALLOCATION = 73

_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_TOKEN_PART = re.compile(r"[A-Za-z0-9_-]+\Z")
_REASONS = {"CAPABILITY_REVOKED", "STOP_REQUESTED"}
_BINARY_FLAG = getattr(os, "O_BINARY", 0)
_DENIALS = {
    "ALREADY_FINAL",
    "BUDGET_EXHAUSTED",
    "CAPABILITY_INVALID",
    "CAPABILITY_REVOKED",
    "EXPIRED",
    "GLOBAL_BUDGET_EXHAUSTED",
    "INVALID_QUEUE_ID",
    "MALFORMED_INPUT",
    "NON_CANONICAL_INPUT",
    "NOT_FOUND",
    "REPLAY",
    "REPLAY_CAPACITY_EXHAUSTED",
    "STALE_GENERATION",
    "UNKNOWN_FIELDS",
}
_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()
_REGISTRAR_SEAL = object()


class BrokeredStoreError(RuntimeError):
    """Durable broker state is unavailable or fails closed validation."""


class _StrictJSONError(ValueError):
    """Input bytes do not follow the broker's strict JSON contract."""


@dataclass(frozen=True)
class Receipt:
    """Small, fixed-field outcome; never contains a request or capability."""

    phase: str
    outcome: str
    code: str
    run_id: str | None = None
    queue_id: str | None = None
    generation: int | None = None
    effect_applied: bool = False
    process_stop: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "effect_applied": self.effect_applied,
            "outcome": self.outcome,
            "phase": self.phase,
        }
        for key in ("generation", "process_stop", "queue_id", "run_id"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        return result

    def canonical_bytes(self) -> bytes:
        raw = _canonical_json(self.as_dict())
        if len(raw) > MAX_RECEIPT_BYTES:
            raise RuntimeError("internal receipt exceeded its fixed size bound")
        return raw


@dataclass(frozen=True)
class CapabilityGrant:
    """Opaque bearer grant issued by the trusted registrar for one run."""

    run_id: str
    generation: int
    expires_at_ms: int
    target: str
    action: str
    capability: str = field(repr=False)


@dataclass(frozen=True)
class WorldSnapshot:
    protected_effects: int
    unrelated_canary_allocation: int


@dataclass
class _Queue:
    queue_id: str
    run_id: str
    operation_id: str
    request_bytes: bytes
    request_sha256: str
    status: str = "QUEUED"


@dataclass
class _Run:
    claims: dict[str, Any]
    generation: int = 0
    revoked: bool = False
    reason: str | None = None
    admitted: int = 0
    applied: int = 0


@dataclass
class _State:
    store_id: str
    last_seq: int
    last_hash: str
    record_count: int
    runs: dict[str, _Run] = field(default_factory=dict)
    queues: dict[str, _Queue] = field(default_factory=dict)
    operation_ids: set[str] = field(default_factory=set)
    applied_operation_ids: set[str] = field(default_factory=set)
    pending_bytes: int = 0
    effect_count: int = 0


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _StrictJSONError("duplicate key")
        value[key] = item
    return value


def _reject_number(_: str) -> None:
    raise _StrictJSONError("non-integer number")


def _parse_canonical_json(raw: bytes, *, maximum: int) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise _StrictJSONError("malformed")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        if not isinstance(value, dict):
            raise _StrictJSONError("malformed")
        if _canonical_json(value) != raw:
            raise _StrictJSONError("non-canonical")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError) as error:
        raise ValueError("malformed") from error
    return value


def _is_int(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _file_identity(path: Path) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BrokeredStoreError("durable state is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BrokeredStoreError("durable state identity is invalid")
    if metadata.st_nlink != 1 or metadata.st_ino <= 0:
        raise BrokeredStoreError("durable state identity is unavailable")
    return metadata.st_dev, metadata.st_ino


def _safe_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise BrokeredStoreError("durable state directory is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise BrokeredStoreError("durable state directory is invalid")
    return resolved


def _lock_for(path: Path) -> threading.RLock:
    key = str(path)
    with _LOCAL_LOCKS_GUARD:
        return _LOCAL_LOCKS.setdefault(key, threading.RLock())


def _write_new(path: Path, data: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY_FLAG,
            0o600,
        )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        raise BrokeredStoreError("durable state could not be created") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise BrokeredStoreError("durable state directory could not be synced") from error


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    if not _TOKEN_PART.fullmatch(value):
        raise ValueError("invalid token encoding")
    try:
        raw = base64.urlsafe_b64decode(value + ("=" * ((4 - len(value) % 4) % 4)))
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid token encoding") from error
    if _b64url(raw) != value:
        raise ValueError("non-canonical token encoding")
    return raw


def _capability_token(claims: dict[str, Any], key: bytes) -> str:
    raw = _canonical_json(claims)
    signature = hmac.new(key, raw, hashlib.sha256).digest()
    return f"{_b64url(raw)}.{_b64url(signature)}"


def _decode_capability(token: object, key: bytes) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > MAX_CAPABILITY_BYTES:
        raise ValueError("invalid capability")
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("invalid capability")
    raw = _unb64url(parts[0])
    signature = _unb64url(parts[1])
    if len(signature) != hashlib.sha256().digest_size:
        raise ValueError("invalid capability")
    expected = hmac.new(key, raw, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid capability")
    claims = _parse_canonical_json(raw, maximum=512)
    if set(claims) != {
        "action",
        "expires_at_ms",
        "generation",
        "max_actions",
        "run_id",
        "schema_version",
        "store_id",
        "target",
    }:
        raise ValueError("invalid capability")
    if (
        claims["schema_version"] != CAPABILITY_SCHEMA
        or not isinstance(claims["store_id"], str)
        or not _HEX32.fullmatch(claims["store_id"])
        or not isinstance(claims["run_id"], str)
        or not _HEX32.fullmatch(claims["run_id"])
        or claims["target"] != TARGET
        or claims["action"] != ACTION
        or not _is_int(claims["generation"])
        or not _is_int(claims["expires_at_ms"], minimum=1)
        or type(claims["max_actions"]) is not int
        or claims["max_actions"] != MAX_ACTIONS_PER_RUN
    ):
        raise ValueError("invalid capability")
    return claims


def _validate_request(raw: bytes) -> tuple[dict[str, Any], str | None]:
    try:
        request = _parse_canonical_json(raw, maximum=MAX_REQUEST_BYTES)
    except ValueError as error:
        code = "NON_CANONICAL_INPUT" if str(error) == "non-canonical" else "MALFORMED_INPUT"
        return {}, code
    expected_fields = {
        "action",
        "capability",
        "generation",
        "operation_id",
        "payload",
        "run_id",
        "schema_version",
        "target",
    }
    if set(request) - expected_fields:
        return {}, "UNKNOWN_FIELDS"
    if set(request) != expected_fields:
        return {}, "MALFORMED_INPUT"
    payload = request.get("payload")
    if (
        request.get("schema_version") != REQUEST_SCHEMA
        or request.get("action") != ACTION
        or request.get("target") != TARGET
        or not isinstance(request.get("run_id"), str)
        or not _HEX32.fullmatch(request["run_id"])
        or not _is_int(request.get("generation"))
        or not isinstance(request.get("operation_id"), str)
        or not _OPERATION_ID.fullmatch(request["operation_id"])
        or not isinstance(request.get("capability"), str)
        or not isinstance(payload, dict)
        or set(payload) != {"delta"}
        or type(payload.get("delta")) is not int
        or payload["delta"] != 1
    ):
        return {}, "MALFORMED_INPUT"
    return request, None


def _validate_claims(claims: dict[str, Any], store_id: str) -> bool:
    return (
        set(claims)
        == {
            "action",
            "expires_at_ms",
            "generation",
            "max_actions",
            "run_id",
            "schema_version",
            "store_id",
            "target",
        }
        and claims.get("schema_version") == CAPABILITY_SCHEMA
        and claims.get("store_id") == store_id
        and isinstance(claims.get("run_id"), str)
        and bool(_HEX32.fullmatch(claims["run_id"]))
        and claims.get("target") == TARGET
        and claims.get("action") == ACTION
        and _is_int(claims.get("generation"))
        and _is_int(claims.get("expires_at_ms"), minimum=1)
        and type(claims.get("max_actions")) is int
        and claims["max_actions"] == MAX_ACTIONS_PER_RUN
    )


class BrokeredOperator:
    """Durable synthetic service that admits, queues, and applies one fixed action."""

    def __init__(self, directory: Path, anchor: dict[str, Any]) -> None:
        self._directory = directory
        self._anchor = anchor
        self._key = bytes.fromhex(anchor["secret"])
        self._local_lock = _lock_for(directory)

    @classmethod
    def bootstrap(cls, state_directory: Path | str) -> tuple[TrustedRegistrar, BrokeredOperator]:
        """Create a new dedicated state directory and its trusted registrar."""
        requested = Path(state_directory).absolute()
        if requested.exists() or requested.is_symlink() or not requested.parent.is_dir():
            raise BrokeredStoreError("bootstrap requires a new directory under an existing parent")
        try:
            requested.mkdir(mode=0o700)
            directory = _safe_directory(requested)
        except OSError as error:
            raise BrokeredStoreError("durable state directory could not be created") from error

        store_id = secrets.token_hex(16)
        secret = secrets.token_hex(32)
        lock_path = directory / LOCK_NAME
        journal_path = directory / JOURNAL_NAME
        witness_path = directory / WITNESS_NAME
        anchor_path = directory / ANCHOR_NAME
        _write_new(lock_path, b"\0")
        _write_new(journal_path, b"")
        _write_new(witness_path, b"\0")
        lock_device, lock_inode = _file_identity(lock_path)
        journal_device, journal_inode = _file_identity(journal_path)
        witness_device, witness_inode = _file_identity(witness_path)
        anchor = {
            "journal_device": journal_device,
            "journal_inode": journal_inode,
            "lock_device": lock_device,
            "lock_inode": lock_inode,
            "schema_version": ANCHOR_SCHEMA,
            "secret": secret,
            "store_id": store_id,
            "witness_device": witness_device,
            "witness_inode": witness_inode,
        }
        _write_new(anchor_path, _canonical_json(anchor))
        anchor_device, anchor_inode = _file_identity(anchor_path)
        operator = cls(directory, anchor)
        genesis = {
            "anchor_device": anchor_device,
            "anchor_inode": anchor_inode,
            "schema_version": ANCHOR_SCHEMA,
            "store_id": store_id,
        }
        operator._append_raw_genesis(genesis)
        _fsync_directory(directory)
        return cls.open(directory)

    @classmethod
    def open(cls, state_directory: Path | str) -> tuple[TrustedRegistrar, BrokeredOperator]:
        """Reopen existing state; absence, replacement, or corruption fails closed."""
        directory = _safe_directory(Path(state_directory).absolute())
        anchor = cls._read_anchor(directory)
        instance = cls(directory, anchor)
        with instance._locked():
            instance._read_state()
        return TrustedRegistrar(instance, _seal=_REGISTRAR_SEAL), instance

    @staticmethod
    def _read_regular(path: Path, maximum: int) -> tuple[bytes, tuple[int, int]]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG
        try:
            descriptor = os.open(path, flags)
            os.lseek(descriptor, 0, os.SEEK_SET)
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_ino <= 0:
                raise BrokeredStoreError("durable state identity is invalid")
            if not 1 <= before.st_size <= maximum:
                raise BrokeredStoreError("durable state size is invalid")
            parts: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise BrokeredStoreError("durable state size is invalid")
                parts.append(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise BrokeredStoreError("durable state changed while being read")
            if total != after.st_size:
                raise BrokeredStoreError("durable state read length mismatch")
            return b"".join(parts), (before.st_dev, before.st_ino)
        except OSError as error:
            raise BrokeredStoreError("durable state is unavailable") from error
        finally:
            if "descriptor" in locals():
                os.close(descriptor)

    @classmethod
    def _read_anchor(cls, directory: Path) -> dict[str, Any]:
        raw, _ = cls._read_regular(directory / ANCHOR_NAME, MAX_ANCHOR_BYTES)
        try:
            anchor = _parse_canonical_json(raw, maximum=MAX_ANCHOR_BYTES)
        except ValueError as error:
            raise BrokeredStoreError("durable anchor is malformed") from error
        if set(anchor) != {
            "journal_device",
            "journal_inode",
            "lock_device",
            "lock_inode",
            "schema_version",
            "secret",
            "store_id",
            "witness_device",
            "witness_inode",
        }:
            raise BrokeredStoreError("durable anchor schema is invalid")
        if (
            anchor["schema_version"] != ANCHOR_SCHEMA
            or not isinstance(anchor["store_id"], str)
            or not _HEX32.fullmatch(anchor["store_id"])
            or not isinstance(anchor["secret"], str)
            or not _HEX64.fullmatch(anchor["secret"])
            or not all(
                _is_int(anchor[key])
                for key in (
                    "journal_device",
                    "journal_inode",
                    "lock_device",
                    "lock_inode",
                    "witness_device",
                    "witness_inode",
                )
            )
            or anchor["journal_inode"] == 0
            or anchor["lock_inode"] == 0
            or anchor["witness_inode"] == 0
        ):
            raise BrokeredStoreError("durable anchor values are invalid")
        if _file_identity(directory / JOURNAL_NAME) != (
            anchor["journal_device"],
            anchor["journal_inode"],
        ) or _file_identity(directory / LOCK_NAME) != (
            anchor["lock_device"],
            anchor["lock_inode"],
        ) or _file_identity(directory / WITNESS_NAME) != (
            anchor["witness_device"],
            anchor["witness_inode"],
        ):
            raise BrokeredStoreError("durable state was replaced")
        return anchor

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self._local_lock.acquire()
        descriptor: int | None = None
        lock_path = self._directory / LOCK_NAME
        try:
            flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG
            descriptor = os.open(lock_path, flags)
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (
                self._anchor["lock_device"],
                self._anchor["lock_inode"],
            ) or not stat.S_ISREG(metadata.st_mode):
                raise BrokeredStoreError("durable lock was replaced")
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as error:
            raise BrokeredStoreError("durable state lock is unavailable") from error
        finally:
            if descriptor is not None:
                try:
                    if os.name == "nt":
                        import msvcrt

                        os.lseek(descriptor, 0, os.SEEK_SET)
                        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
            self._local_lock.release()

    def _append_raw_genesis(self, payload: dict[str, Any]) -> None:
        event = {"kind": "GENESIS", "payload": payload, "prev": "0" * 64, "seq": 0}
        mac = hmac.new(self._key, _canonical_json(event), hashlib.sha256).hexdigest()
        raw = _canonical_json({**event, "mac": mac})
        self._append_bytes(raw, 0, hashlib.sha256(raw).hexdigest())

    def _append_bytes(self, raw: bytes, seq: int, journal_sha256: str) -> None:
        path = self._directory / JOURNAL_NAME
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG
        try:
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (
                self._anchor["journal_device"],
                self._anchor["journal_inode"],
            ) or not stat.S_ISREG(metadata.st_mode):
                raise BrokeredStoreError("durable journal was replaced")
            if metadata.st_size + len(raw) > MAX_JOURNAL_BYTES:
                raise BrokeredStoreError("durable journal capacity is exhausted")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as error:
            raise BrokeredStoreError("durable journal write failed") from error
        finally:
            if "descriptor" in locals():
                os.close(descriptor)
        self._write_witness(seq, journal_sha256)

    def _write_witness(self, seq: int, journal_sha256: str) -> None:
        unsigned = {
            "journal_sha256": journal_sha256,
            "schema_version": WITNESS_SCHEMA,
            "seq": seq,
            "store_id": self._anchor["store_id"],
        }
        mac = hmac.new(self._key, _canonical_json(unsigned), hashlib.sha256).hexdigest()
        raw = _canonical_json({**unsigned, "mac": mac})
        path = self._directory / WITNESS_NAME
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | _BINARY_FLAG,
            )
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != (
                self._anchor["witness_device"],
                self._anchor["witness_inode"],
            ) or not stat.S_ISREG(metadata.st_mode):
                raise BrokeredStoreError("durable witness was replaced")
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as error:
            raise BrokeredStoreError("durable witness write failed") from error
        finally:
            if "descriptor" in locals():
                os.close(descriptor)

    def _append(self, state: _State, kind: str, payload: dict[str, Any]) -> _State:
        if state.record_count >= MAX_JOURNAL_EVENTS:
            raise BrokeredStoreError("durable journal event budget is exhausted")
        event = {
            "kind": kind,
            "payload": payload,
            "prev": state.last_hash,
            "seq": state.last_seq + 1,
        }
        mac = hmac.new(self._key, _canonical_json(event), hashlib.sha256).hexdigest()
        raw = _canonical_json({**event, "mac": mac})
        self._append_bytes(raw, event["seq"], hashlib.sha256(raw).hexdigest())
        return self._read_state()

    def _read_state(self) -> _State:
        anchor = self._read_anchor(self._directory)
        if anchor != self._anchor:
            raise BrokeredStoreError("durable anchor changed")
        raw, identity = self._read_regular(self._directory / JOURNAL_NAME, MAX_JOURNAL_BYTES)
        if identity != (anchor["journal_device"], anchor["journal_inode"]):
            raise BrokeredStoreError("durable journal was replaced")
        lines = raw.splitlines(keepends=True)
        if not lines or any(not line.endswith(b"\n") or line.endswith(b"\r\n") for line in lines):
            raise BrokeredStoreError("durable journal is malformed")
        state: _State | None = None
        prior_hash = "0" * 64
        for expected_seq, line in enumerate(lines):
            try:
                record = _parse_canonical_json(line, maximum=16_384)
            except ValueError as error:
                raise BrokeredStoreError("durable journal is malformed") from error
            if set(record) != {"kind", "mac", "payload", "prev", "seq"}:
                raise BrokeredStoreError("durable journal record schema is invalid")
            if (
                type(record["seq"]) is not int
                or record["seq"] != expected_seq
                or record["prev"] != prior_hash
                or not isinstance(record["kind"], str)
                or not isinstance(record["mac"], str)
                or not _HEX64.fullmatch(record["mac"])
                or not isinstance(record["payload"], dict)
            ):
                raise BrokeredStoreError("durable journal chain is invalid")
            unsigned = {key: record[key] for key in ("kind", "payload", "prev", "seq")}
            expected_mac = hmac.new(self._key, _canonical_json(unsigned), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(record["mac"], expected_mac):
                raise BrokeredStoreError("durable journal authentication failed")
            if expected_seq == 0:
                state = self._replay_genesis(
                    record,
                    anchor,
                    _file_identity(self._directory / ANCHOR_NAME),
                )
            else:
                if state is None:
                    raise BrokeredStoreError("durable journal has no genesis")
                self._replay_event(state, record)
            prior_hash = hashlib.sha256(line).hexdigest()
        if state is None:
            raise BrokeredStoreError("durable journal has no genesis")
        witness_raw, witness_identity = self._read_regular(
            self._directory / WITNESS_NAME,
            MAX_ANCHOR_BYTES,
        )
        if witness_identity != (anchor["witness_device"], anchor["witness_inode"]):
            raise BrokeredStoreError("durable witness was replaced")
        try:
            witness = _parse_canonical_json(witness_raw, maximum=MAX_ANCHOR_BYTES)
        except ValueError as error:
            raise BrokeredStoreError("durable witness is malformed") from error
        if set(witness) != {
            "journal_sha256",
            "mac",
            "schema_version",
            "seq",
            "store_id",
        }:
            raise BrokeredStoreError("durable witness schema is invalid")
        witness_unsigned = {key: witness[key] for key in ("journal_sha256", "schema_version", "seq", "store_id")}
        expected_witness_mac = hmac.new(
            self._key,
            _canonical_json(witness_unsigned),
            hashlib.sha256,
        ).hexdigest()
        if (
            witness["schema_version"] != WITNESS_SCHEMA
            or witness["store_id"] != anchor["store_id"]
            or not _is_int(witness["seq"])
            or witness["seq"] != len(lines) - 1
            or not isinstance(witness["journal_sha256"], str)
            or not _HEX64.fullmatch(witness["journal_sha256"])
            or witness["journal_sha256"] != prior_hash
            or not isinstance(witness["mac"], str)
            or not _HEX64.fullmatch(witness["mac"])
            or not hmac.compare_digest(witness["mac"], expected_witness_mac)
        ):
            raise BrokeredStoreError("durable monotonic witness does not match journal")
        state.last_seq = len(lines) - 1
        state.last_hash = prior_hash
        state.record_count = len(lines)
        return state

    @staticmethod
    def _replay_genesis(
        record: dict[str, Any],
        anchor: dict[str, Any],
        anchor_identity: tuple[int, int],
    ) -> _State:
        payload = record["payload"]
        expected = {
            "anchor_device": anchor_identity[0],
            "anchor_inode": anchor_identity[1],
            "schema_version": ANCHOR_SCHEMA,
            "store_id": anchor["store_id"],
        }
        if (
            record["kind"] != "GENESIS"
            or payload != expected
            or not _is_int(payload.get("anchor_device"))
            or not _is_int(payload.get("anchor_inode"), minimum=1)
        ):
            raise BrokeredStoreError("durable journal genesis identity is invalid")
        return _State(anchor["store_id"], 0, hashlib.sha256(_canonical_json(record)).hexdigest(), 1)

    def _replay_event(self, state: _State, record: dict[str, Any]) -> None:
        kind = record["kind"]
        payload = record["payload"]
        if kind == "RUN_REGISTERED":
            if set(payload) != {"claims"} or not isinstance(payload["claims"], dict):
                raise BrokeredStoreError("durable run record is invalid")
            claims = payload["claims"]
            if not _validate_claims(claims, state.store_id) or claims["generation"] != 0:
                raise BrokeredStoreError("durable run identity is invalid")
            run_id = claims["run_id"]
            if run_id in state.runs or len(state.runs) >= MAX_RUNS:
                raise BrokeredStoreError("durable run identity is duplicated")
            state.runs[run_id] = _Run(dict(claims))
            return
        if kind == "ADMITTED":
            if set(payload) != {
                "operation_id",
                "queue_id",
                "request_b64",
                "request_sha256",
                "run_id",
            }:
                raise BrokeredStoreError("durable admission record is invalid")
            try:
                request_bytes = base64.b64decode(payload["request_b64"], validate=True)
            except (TypeError, binascii.Error) as error:
                raise BrokeredStoreError("durable request bytes are invalid") from error
            request, denial = _validate_request(request_bytes)
            run = state.runs.get(payload["run_id"])
            try:
                claims = (
                    _decode_capability(request.get("capability"), self._key)
                    if denial is None
                    else None
                )
            except ValueError as error:
                raise BrokeredStoreError("durable request capability is invalid") from error
            queue_id = payload["queue_id"]
            operation_id = payload["operation_id"]
            if (
                denial is not None
                or run is None
                or claims != run.claims
                or not isinstance(queue_id, str)
                or not _HEX32.fullmatch(queue_id)
                or queue_id in state.queues
                or not isinstance(operation_id, str)
                or not _OPERATION_ID.fullmatch(operation_id)
                or operation_id in state.operation_ids
                or payload["request_sha256"] != hashlib.sha256(request_bytes).hexdigest()
                or request["run_id"] != run.claims["run_id"]
                or request["generation"] != run.generation
                or run.revoked
                or request["target"] != run.claims["target"]
                or request["action"] != run.claims["action"]
                or request["operation_id"] != operation_id
                or run.admitted >= MAX_ACTIONS_PER_RUN
                or len(state.operation_ids) >= MAX_REPLAY_KEYS
            ):
                raise BrokeredStoreError("durable admission invariants failed")
            state.queues[queue_id] = _Queue(
                queue_id,
                run.claims["run_id"],
                operation_id,
                request_bytes,
                payload["request_sha256"],
            )
            state.operation_ids.add(operation_id)
            state.pending_bytes += len(request_bytes)
            run.admitted += 1
            if state.pending_bytes > MAX_PENDING_BYTES:
                raise BrokeredStoreError("durable pending budget is invalid")
            return
        if kind in {"DISPATCHED", "DISPATCH_REJECTED"}:
            expected_fields = {"queue_id"} if kind == "DISPATCHED" else {"queue_id", "reason"}
            if set(payload) != expected_fields:
                raise BrokeredStoreError("durable dispatch record is invalid")
            queued = state.queues.get(payload["queue_id"])
            if queued is None or queued.status != "QUEUED":
                raise BrokeredStoreError("durable queue transition is invalid")
            state.pending_bytes -= len(queued.request_bytes)
            if kind == "DISPATCHED":
                run = state.runs[queued.run_id]
                if run.revoked or run.generation != 0:
                    raise BrokeredStoreError("durable dispatch bypassed generation fence")
                request, denial = _validate_request(queued.request_bytes)
                if denial is not None or request["operation_id"] != queued.operation_id:
                    raise BrokeredStoreError("durable dispatch request is invalid")
                run.applied += 1
                state.effect_count += 1
                state.applied_operation_ids.add(queued.operation_id)
                queued.status = "APPLIED"
            else:
                if payload["reason"] not in {
                    "BUDGET_EXHAUSTED",
                    "EXPIRED",
                    "REPLAY",
                    "STALE_GENERATION",
                }:
                    raise BrokeredStoreError("durable denial code is invalid")
                queued.status = "REJECTED"
            return
        if kind == "REVOKED":
            if set(payload) != {"new_generation", "reason", "run_id"}:
                raise BrokeredStoreError("durable revocation record is invalid")
            run = state.runs.get(payload["run_id"])
            if (
                run is None
                or run.revoked
                or not _is_int(payload["new_generation"], minimum=1)
                or payload["new_generation"] != run.generation + 1
                or payload["reason"] not in _REASONS
            ):
                raise BrokeredStoreError("durable revocation fence is invalid")
            run.generation = payload["new_generation"]
            run.revoked = True
            run.reason = payload["reason"]
            return
        raise BrokeredStoreError("durable journal event is unknown")

    def _check_claims(self, request: dict[str, Any], state: _State) -> tuple[dict[str, Any] | None, str | None]:
        try:
            claims = _decode_capability(request.get("capability"), self._key)
        except ValueError:
            return None, "CAPABILITY_INVALID"
        run = state.runs.get(claims["run_id"])
        if not _validate_claims(claims, state.store_id) or run is None or claims != run.claims:
            return None, "CAPABILITY_INVALID"
        if request.get("run_id") != claims["run_id"] or request.get("generation") != claims["generation"]:
            return None, "CAPABILITY_INVALID"
        return claims, None

    def _register_run(self) -> CapabilityGrant:
        with self._locked():
            state = self._read_state()
            if len(state.runs) >= MAX_RUNS:
                raise BrokeredStoreError("run capacity is exhausted")
            now_ms = time.time_ns() // 1_000_000
            if not _is_int(now_ms, minimum=1):
                raise BrokeredStoreError("trusted clock is unavailable")
            run_id = secrets.token_hex(16)
            claims = {
                "action": ACTION,
                "expires_at_ms": now_ms + MAX_LIFETIME_MS,
                "generation": 0,
                "max_actions": MAX_ACTIONS_PER_RUN,
                "run_id": run_id,
                "schema_version": CAPABILITY_SCHEMA,
                "store_id": state.store_id,
                "target": TARGET,
            }
            state = self._append(state, "RUN_REGISTERED", {"claims": claims})
            del state
            return CapabilityGrant(
                run_id=run_id,
                generation=0,
                expires_at_ms=claims["expires_at_ms"],
                target=TARGET,
                action=ACTION,
                capability=_capability_token(claims, self._key),
            )

    def client(self, grant: CapabilityGrant) -> OperatorClient:
        """Bind a client to an issued immutable grant; no caller-selected authority."""
        if not isinstance(grant, CapabilityGrant):
            raise TypeError("an issued capability grant is required")
        try:
            claims = _decode_capability(grant.capability, self._key)
        except ValueError as error:
            raise ValueError("capability grant is invalid") from error
        if (
            claims["run_id"] != grant.run_id
            or claims["generation"] != grant.generation
            or claims["expires_at_ms"] != grant.expires_at_ms
            or claims["target"] != grant.target
            or claims["action"] != grant.action
        ):
            raise ValueError("capability grant labels do not match its signature")
        return OperatorClient(self, grant)

    def admit(self, raw: bytes) -> Receipt:
        request, denial = _validate_request(raw)
        if denial is not None:
            return _receipt("admission", "DENIED", denial)
        with self._locked():
            state = self._read_state()
            claims, denial = self._check_claims(request, state)
            if denial is not None or claims is None:
                return _receipt("admission", "DENIED", denial or "CAPABILITY_INVALID")
            run = state.runs[claims["run_id"]]
            if run.revoked:
                return _receipt("admission", "DENIED", "CAPABILITY_REVOKED", run_id=claims["run_id"], generation=run.generation)
            if run.generation != claims["generation"]:
                return _receipt("admission", "DENIED", "STALE_GENERATION", run_id=claims["run_id"], generation=run.generation)
            if time.time_ns() // 1_000_000 >= claims["expires_at_ms"]:
                return _receipt("admission", "DENIED", "EXPIRED", run_id=claims["run_id"], generation=run.generation)
            operation_id = request["operation_id"]
            if operation_id in state.operation_ids:
                return _receipt("admission", "DENIED", "REPLAY", run_id=claims["run_id"], generation=run.generation)
            if len(state.operation_ids) >= MAX_REPLAY_KEYS:
                return _receipt("admission", "DENIED", "REPLAY_CAPACITY_EXHAUSTED", run_id=claims["run_id"], generation=run.generation)
            if run.admitted >= claims["max_actions"]:
                return _receipt("admission", "DENIED", "BUDGET_EXHAUSTED", run_id=claims["run_id"], generation=run.generation)
            if state.pending_bytes + len(raw) > MAX_PENDING_BYTES:
                return _receipt("admission", "DENIED", "GLOBAL_BUDGET_EXHAUSTED", run_id=claims["run_id"], generation=run.generation)
            queue_id = secrets.token_hex(16)
            payload = {
                "operation_id": operation_id,
                "queue_id": queue_id,
                "request_b64": base64.b64encode(raw).decode("ascii"),
                "request_sha256": hashlib.sha256(raw).hexdigest(),
                "run_id": claims["run_id"],
            }
            self._append(state, "ADMITTED", payload)
            return _receipt("admission", "QUEUED", "ADMITTED", run_id=claims["run_id"], queue_id=queue_id, generation=claims["generation"])

    def dispatch(self, queue_id: str) -> Receipt:
        if not isinstance(queue_id, str) or not _HEX32.fullmatch(queue_id):
            return _receipt("dispatch", "DENIED", "INVALID_QUEUE_ID")
        with self._locked():
            state = self._read_state()
            queued = state.queues.get(queue_id)
            if queued is None:
                return _receipt("dispatch", "DENIED", "NOT_FOUND", queue_id=queue_id)
            if queued.status != "QUEUED":
                return _receipt("dispatch", "DENIED", "REPLAY" if queued.status == "APPLIED" else "ALREADY_FINAL", run_id=queued.run_id, queue_id=queue_id)
            if hashlib.sha256(queued.request_bytes).hexdigest() != queued.request_sha256:
                raise BrokeredStoreError("queued canonical bytes changed")
            request, denial = _validate_request(queued.request_bytes)
            if denial is not None:
                raise BrokeredStoreError("queued request is no longer canonical")
            claims, denial = self._check_claims(request, state)
            if denial is not None or claims is None:
                raise BrokeredStoreError("queued capability no longer validates")
            run = state.runs[queued.run_id]
            reason: str | None = None
            if request["run_id"] != queued.run_id or request["operation_id"] != queued.operation_id:
                raise BrokeredStoreError("queued request identity changed")
            if run.generation != claims["generation"]:
                reason = "STALE_GENERATION"
            elif run.revoked:
                reason = "CAPABILITY_REVOKED"
            elif time.time_ns() // 1_000_000 >= claims["expires_at_ms"]:
                reason = "EXPIRED"
            elif queued.operation_id in state.applied_operation_ids:
                reason = "REPLAY"
            elif run.applied >= claims["max_actions"]:
                reason = "BUDGET_EXHAUSTED"
            if reason is not None:
                self._append(state, "DISPATCH_REJECTED", {"queue_id": queue_id, "reason": reason})
                return _receipt("dispatch", "DENIED", reason, run_id=queued.run_id, queue_id=queue_id, generation=run.generation)
            self._append(state, "DISPATCHED", {"queue_id": queue_id})
            return _receipt("dispatch", "APPLIED", "EFFECT_APPLIED", run_id=queued.run_id, queue_id=queue_id, generation=run.generation, effect_applied=True)

    def _revoke(self, run_id: str, reason: str) -> Receipt:
        if not isinstance(run_id, str) or not _HEX32.fullmatch(run_id):
            return _receipt("revocation", "DENIED", "NOT_FOUND")
        with self._locked():
            state = self._read_state()
            run = state.runs.get(run_id)
            if run is None:
                return _receipt("revocation", "DENIED", "NOT_FOUND")
            if run.revoked:
                return _receipt("revocation", "ALREADY_REVOKED", "CAPABILITY_REVOKED", run_id=run_id, generation=run.generation, process_stop="UNSUPPORTED" if reason == "STOP_REQUESTED" else None)
            new_generation = run.generation + 1
            self._append(
                state,
                "REVOKED",
                {"new_generation": new_generation, "reason": reason, "run_id": run_id},
            )
            return _receipt("revocation", "REVOKED", reason, run_id=run_id, generation=new_generation, process_stop="UNSUPPORTED" if reason == "STOP_REQUESTED" else None)

    def revoke(self, run_id: str) -> Receipt:
        """Advance the durable generation fence and revoke this capability."""
        return self._revoke(run_id, "CAPABILITY_REVOKED")

    def request_stop(self, run_id: str) -> Receipt:
        """Revoke admission on a stop request; this does not stop a process."""
        return self._revoke(run_id, "STOP_REQUESTED")

    def verified_process_stop(self, run_id: str) -> Receipt:
        """Report the intentionally unsupported process-termination proof."""
        safe_id = run_id if isinstance(run_id, str) and _HEX32.fullmatch(run_id) else None
        return _receipt(
            "process_stop",
            "UNSUPPORTED",
            "PROCESS_TERMINATION_UNSUPPORTED",
            run_id=safe_id,
            process_stop="UNSUPPORTED",
        )

    def world_snapshot(self) -> WorldSnapshot:
        with self._locked():
            state = self._read_state()
        return WorldSnapshot(state.effect_count, UNRELATED_CANARY_ALLOCATION)


class TrustedRegistrar:
    """Trusted-side-only registration authority for fixed synthetic grants."""

    def __init__(self, operator: BrokeredOperator, *, _seal: object | None = None) -> None:
        if _seal is not _REGISTRAR_SEAL:
            raise PermissionError("registrar authority is reserved for trusted bootstrap")
        self._operator = operator

    def register_run(self) -> CapabilityGrant:
        """Mint a fresh run identity under the fixed local policy."""
        return self._operator._register_run()


class OperatorClient:
    """Client view exposing only admission for its one immutable capability."""

    def __init__(self, operator: BrokeredOperator, grant: CapabilityGrant) -> None:
        self._operator = operator
        self._grant = grant

    def request_bytes(self, operation_id: str) -> bytes:
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("operation identifier is invalid")
        request = {
            "action": self._grant.action,
            "capability": self._grant.capability,
            "generation": self._grant.generation,
            "operation_id": operation_id,
            "payload": {"delta": 1},
            "run_id": self._grant.run_id,
            "schema_version": REQUEST_SCHEMA,
            "target": self._grant.target,
        }
        return _canonical_json(request)

    def admit(self, operation_id: str) -> Receipt:
        return self._operator.admit(self.request_bytes(operation_id))


def _receipt(
    phase: str,
    outcome: str,
    code: str,
    *,
    run_id: str | None = None,
    queue_id: str | None = None,
    generation: int | None = None,
    effect_applied: bool = False,
    process_stop: str | None = None,
) -> Receipt:
    if code not in _DENIALS | _REASONS | {
        "ADMITTED",
        "ALREADY_REVOKED",
        "CAPABILITY_REVOKED",
        "EFFECT_APPLIED",
        "PROCESS_TERMINATION_UNSUPPORTED",
    }:
        raise RuntimeError("internal receipt code is not allow-listed")
    receipt = Receipt(
        phase,
        outcome,
        code,
        run_id,
        queue_id,
        generation,
        effect_applied,
        process_stop,
    )
    receipt.canonical_bytes()
    return receipt
