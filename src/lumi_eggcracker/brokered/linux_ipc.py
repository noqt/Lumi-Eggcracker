"""Linux-only authenticated local IPC for the synthetic brokered operator.

The workload protocol deliberately contains no capability or target selection.
Only the service process holds the registrar-issued grant and private journal.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import sys
import threading
from pathlib import Path
from typing import Any, Self

from .operator import (
    _HEX32,
    _OPERATION_ID,
    BrokeredOperator,
    CapabilityGrant,
    Receipt,
    _canonical_json,
    _parse_canonical_json,
)

IPC_SCHEMA = "lumi-eggcracker.brokered-ipc.v1"
MAX_IPC_REQUEST_BYTES = 1024
MAX_IPC_RESPONSE_BYTES = 2048
MAX_RESULT_BYTES = 1024
_SOCKET_MODE = 0o660
_SOCKET_DIRECTORY_MODE = 0o710
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_SERVICE_SEAL = object()
_PROTOCOL_DENIALS = {
    "MALFORMED_INPUT",
    "NON_CANONICAL_INPUT",
    "PEER_IDENTITY",
    "UNKNOWN_FIELDS",
}
_RECEIPT_PHASES = {"admission", "dispatch", "process_stop", "revocation"}
_RECEIPT_OUTCOMES = {
    "ALREADY_REVOKED",
    "APPLIED",
    "DENIED",
    "QUEUED",
    "REVOKED",
    "UNSUPPORTED",
}
_RECEIPT_CODES = {
    "ADMITTED",
    "ALREADY_FINAL",
    "ALREADY_REVOKED",
    "BUDGET_EXHAUSTED",
    "CAPABILITY_INVALID",
    "CAPABILITY_REVOKED",
    "EFFECT_APPLIED",
    "EXPIRED",
    "GLOBAL_BUDGET_EXHAUSTED",
    "INVALID_QUEUE_ID",
    "MALFORMED_INPUT",
    "NON_CANONICAL_INPUT",
    "NOT_FOUND",
    "PROCESS_TERMINATION_UNSUPPORTED",
    "REPLAY",
    "REPLAY_CAPACITY_EXHAUSTED",
    "STALE_GENERATION",
    "STOP_REQUESTED",
    "UNKNOWN_FIELDS",
}

class BrokeredIPCError(RuntimeError):
    """The Linux local-IPC boundary cannot be established or used safely."""


def _require_linux_ipc() -> None:
    if (
        sys.platform != "linux"
        or not hasattr(socket, "SO_PEERCRED")
        or not hasattr(socket, "SOCK_SEQPACKET")
    ):
        raise BrokeredIPCError("Linux Unix-domain SOCK_SEQPACKET is required")


def _validate_identity_config(
    service_uid: object,
    workload_uid: object,
    workload_gid: object,
    *,
    service_gid: object,
    service_groups: object,
) -> None:
    if (
        type(service_uid) is not int
        or service_uid <= 0
        or type(workload_uid) is not int
        or workload_uid <= 0
        or type(workload_gid) is not int
        or workload_gid <= 0
        or type(service_gid) is not int
        or service_gid <= 0
        or service_uid == workload_uid
        or not isinstance(service_groups, (tuple, list, set, frozenset))
        or any(type(group) is not int or group < 0 for group in service_groups)
        or 0 in service_groups
    ):
        raise BrokeredIPCError("service and workload require distinct non-root identities and groups")


def _same_identity(expected: tuple[int, int], actual: tuple[int, int], label: str) -> None:
    if expected != actual:
        raise BrokeredIPCError(f"{label} was replaced")


def _validate_client_identity(service_uid: object, workload_uid: int, workload_gid: int, groups: set[int]) -> None:
    if (
        type(service_uid) is not int
        or service_uid <= 0
        or type(workload_uid) is not int
        or workload_uid <= 0
        or type(workload_gid) is not int
        or workload_gid <= 0
        or service_uid == workload_uid
        or 0 in groups
    ):
        raise BrokeredIPCError("client and service require distinct non-root identities and groups")


def _client_socket_snapshot(socket_path: Path, service_uid: int) -> tuple[tuple[int, int], tuple[int, int], int]:
    parent = socket_path.parent
    try:
        resolved_parent = parent.resolve(strict=True)
        directory = parent.lstat()
        node = socket_path.lstat()
    except OSError as error:
        raise BrokeredIPCError("broker socket path is unavailable") from error
    if (
        resolved_parent != parent
        or stat.S_ISLNK(directory.st_mode)
        or not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != service_uid
        or stat.S_IMODE(directory.st_mode) != _SOCKET_DIRECTORY_MODE
        or stat.S_ISLNK(node.st_mode)
        or not stat.S_ISSOCK(node.st_mode)
        or node.st_uid != service_uid
        or node.st_gid <= 0
        or directory.st_gid != node.st_gid
        or stat.S_IMODE(node.st_mode) != _SOCKET_MODE
    ):
        raise BrokeredIPCError("broker socket path identity or permissions are invalid")
    return (directory.st_dev, directory.st_ino), (node.st_dev, node.st_ino), node.st_gid


def _parse_request(raw: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        request = _parse_canonical_json(raw, maximum=MAX_IPC_REQUEST_BYTES)
    except ValueError as error:
        code = "NON_CANONICAL_INPUT" if str(error) == "non-canonical" else "MALFORMED_INPUT"
        return None, code

    operation = request.get("op")
    common = {"op", "schema_version"}
    fields_by_operation = {
        "submit": common | {"operation_id"},
        "dispatch": common | {"queue_id"},
        "get_result": common | {"queue_id"},
    }
    allowed = fields_by_operation.get(operation) if isinstance(operation, str) else None
    if allowed is None:
        if set(request) - common:
            return None, "UNKNOWN_FIELDS"
        return None, "MALFORMED_INPUT"
    if set(request) - allowed:
        return None, "UNKNOWN_FIELDS"
    if set(request) != allowed or request.get("schema_version") != IPC_SCHEMA:
        return None, "MALFORMED_INPUT"
    if operation == "submit":
        operation_id = request.get("operation_id")
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            return None, "MALFORMED_INPUT"
    else:
        queue_id = request.get("queue_id")
        if not isinstance(queue_id, str) or not _HEX32.fullmatch(queue_id):
            return None, "MALFORMED_INPUT"
    return request, None


def _valid_receipt(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    required = {"code", "effect_applied", "outcome", "phase"}
    allowed = required | {"generation", "process_stop", "queue_id", "run_id"}
    if not required <= set(value) or set(value) - allowed:
        return False
    if (
        not isinstance(value["code"], str)
        or value["code"] not in _RECEIPT_CODES
        or not isinstance(value["phase"], str)
        or value["phase"] not in _RECEIPT_PHASES
        or not isinstance(value["outcome"], str)
        or value["outcome"] not in _RECEIPT_OUTCOMES
        or type(value["effect_applied"]) is not bool
    ):
        return False
    if "generation" in value and (type(value["generation"]) is not int or value["generation"] < 0):
        return False
    if "process_stop" in value and value["process_stop"] != "UNSUPPORTED":
        return False
    for key in ("queue_id", "run_id"):
        if key in value and (not isinstance(value[key], str) or not _HEX32.fullmatch(value[key])):
            return False
    return True


def _valid_report(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "accepted",
        "dataset_id",
        "dataset_sha256",
        "records_checked",
        "review",
        "units_total",
    }:
        return False
    return (
        value["dataset_id"] == "synthetic.research-batch.v1"
        and isinstance(value["dataset_sha256"], str)
        and len(value["dataset_sha256"]) == 64
        and all(char in "0123456789abcdef" for char in value["dataset_sha256"])
        and type(value["accepted"]) is int
        and type(value["records_checked"]) is int
        and type(value["review"]) is int
        and type(value["units_total"]) is int
        and value["accepted"] >= 0
        and value["records_checked"] >= 0
        and value["review"] >= 0
        and value["records_checked"] == 4
        and 1 <= value["accepted"] <= 3
        and 1 <= value["review"] <= 3
        and value["accepted"] + value["review"] == 4
        and 4 <= value["units_total"] <= 4000
    )


def _parse_response(raw: bytes) -> dict[str, Any]:
    try:
        response = _parse_canonical_json(raw, maximum=MAX_IPC_RESPONSE_BYTES)
    except ValueError as error:
        raise BrokeredIPCError("broker response is malformed") from error
    if response.get("schema_version") != IPC_SCHEMA:
        raise BrokeredIPCError("broker response schema is invalid")
    if (
        set(response) == {"receipt", "schema_version"}
        and _valid_receipt(response["receipt"])
        and "run_id" not in response["receipt"]
    ):
        return response
    if set(response) == {"code", "outcome", "phase", "schema_version"}:
        if (
            response["phase"] == "protocol"
            and response["outcome"] == "DENIED"
            and isinstance(response["code"], str)
            and response["code"] in _PROTOCOL_DENIALS
        ):
            return response
        raise BrokeredIPCError("broker protocol denial is invalid")
    if (
        response.get("phase") == "result"
        and response.get("outcome") == "AVAILABLE"
        and set(response) == {"outcome", "phase", "queue_id", "report", "schema_version"}
        and isinstance(response["queue_id"], str)
        and _HEX32.fullmatch(response["queue_id"])
        and _valid_report(response["report"])
        and len(_canonical_json(response["report"])) <= MAX_RESULT_BYTES
    ):
        return response
    if (
        response.get("phase") == "result"
        and response.get("outcome") == "DENIED"
        and set(response) == {"code", "outcome", "phase", "queue_id", "schema_version"}
        and response["code"] == "NOT_FOUND"
        and isinstance(response["queue_id"], str)
        and _HEX32.fullmatch(response["queue_id"])
    ):
        return response
    raise BrokeredIPCError("broker response fields are invalid")


def _protocol_denial(code: str) -> bytes:
    if code not in _PROTOCOL_DENIALS:
        raise RuntimeError("protocol denial code is not allow-listed")
    raw = _canonical_json(
        {
            "code": code,
            "outcome": "DENIED",
            "phase": "protocol",
            "schema_version": IPC_SCHEMA,
        }
    )
    if len(raw) > MAX_IPC_RESPONSE_BYTES:
        raise RuntimeError("protocol denial exceeded its response bound")
    return raw


def _receipt_response(receipt: Receipt) -> bytes:
    redacted = receipt.as_dict()
    redacted.pop("run_id", None)
    raw = _canonical_json({"receipt": redacted, "schema_version": IPC_SCHEMA})
    if len(raw) > MAX_IPC_RESPONSE_BYTES:
        raise RuntimeError("broker receipt exceeded its response bound")
    return raw


class BrokeredLinuxService:
    """Service-side authority and Linux AF_UNIX request handler.

    The object must remain in the service process. Its grant and registrar are
    never sent over IPC; callers only receive bounded receipts and reports.
    """

    def __init__(
        self,
        operator: BrokeredOperator,
        grant: CapabilityGrant,
        socket_path: Path,
        workload_uid: int,
        workload_gid: int,
        service_uid: int,
        *,
        service_gid: int | None = None,
        service_groups: tuple[int, ...] = (),
        _seal: object | None = None,
    ) -> None:
        if _seal is not _SERVICE_SEAL:
            raise PermissionError("broker service construction is reserved for trusted bootstrap")
        _validate_identity_config(
            service_uid,
            workload_uid,
            workload_gid,
            service_gid=service_gid,
            service_groups=service_groups,
        )
        self._operator = operator
        self._grant = grant
        self._socket_path = socket_path
        self._workload_uid = workload_uid
        self._workload_gid = workload_gid
        self._service_uid = service_uid
        self._service_gid = service_gid
        self._listener: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._socket_directory_identity: tuple[int, int] | None = None
        self._socket_directory_fd: int | None = None
        self._closed = False

    @classmethod
    def _for_trusted_test(
        cls,
        operator: BrokeredOperator,
        grant: CapabilityGrant,
        *,
        workload_uid: int,
        workload_gid: int,
        service_uid: int,
    ) -> BrokeredLinuxService:
        """Construct the protocol core for portable tests, without opening a socket."""
        return cls(
            operator,
            grant,
            Path("/test-only/broker.sock"),
            workload_uid,
            workload_gid,
            service_uid,
            service_gid=service_uid,
            service_groups=(),
            _seal=_SERVICE_SEAL,
        )

    @classmethod
    def open(
        cls,
        state_directory: Path | str,
        socket_path: Path | str,
        *,
        workload_uid: int,
        workload_gid: int,
    ) -> BrokeredLinuxService:
        """Open/create the private singleton service run without rotating it."""
        _require_linux_ipc()
        service_uid = os.geteuid()
        service_gid = os.getegid()
        service_groups = tuple(os.getgroups())
        _validate_identity_config(
            service_uid,
            workload_uid,
            workload_gid,
            service_gid=service_gid,
            service_groups=service_groups,
        )
        operator, grant = BrokeredOperator._open_or_bootstrap_service(state_directory)
        operator._assert_service_state_owner(service_uid)
        path = Path(socket_path)
        if not path.is_absolute():
            raise BrokeredIPCError("socket path must be absolute")
        encoded_path = os.fsencode(path)
        if len(encoded_path) >= 108:
            raise BrokeredIPCError("socket path exceeds the Linux Unix-domain limit")
        return cls(
            operator,
            grant,
            path,
            workload_uid,
            workload_gid,
            service_uid,
            service_gid=service_gid,
            service_groups=service_groups,
            _seal=_SERVICE_SEAL,
        )

    def _validate_socket_directory(self) -> tuple[int, int]:
        parent = self._socket_path.parent
        try:
            resolved_parent = parent.resolve(strict=True)
            metadata = parent.lstat()
        except OSError as error:
            raise BrokeredIPCError("socket directory is unavailable") from error
        if (
            resolved_parent != parent
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self._service_uid
            or metadata.st_gid != self._workload_gid
            or stat.S_IMODE(metadata.st_mode) != _SOCKET_DIRECTORY_MODE
        ):
            raise BrokeredIPCError("socket directory must be service-owned mode 0710 for its IPC group")
        groups = set(os.getgroups()) | {os.getegid()}
        if self._workload_gid not in groups:
            raise BrokeredIPCError("service must belong to the dedicated workload IPC group")
        return metadata.st_dev, metadata.st_ino

    def _assert_pinned_socket_directory(self) -> None:
        descriptor = self._socket_directory_fd
        identity = self._socket_directory_identity
        if descriptor is None or identity is None:
            raise BrokeredIPCError("socket directory identity is not pinned")
        try:
            descriptor_metadata = os.fstat(descriptor)
            path_metadata = self._socket_path.parent.lstat()
            resolved_parent = self._socket_path.parent.resolve(strict=True)
        except OSError as error:
            raise BrokeredIPCError("pinned socket directory is unavailable") from error
        _same_identity(identity, (descriptor_metadata.st_dev, descriptor_metadata.st_ino), "pinned socket directory handle")
        _same_identity(identity, (path_metadata.st_dev, path_metadata.st_ino), "socket directory path")
        if (
            resolved_parent != self._socket_path.parent
            or stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISDIR(path_metadata.st_mode)
            or path_metadata.st_uid != self._service_uid
            or path_metadata.st_gid != self._workload_gid
            or stat.S_IMODE(path_metadata.st_mode) != _SOCKET_DIRECTORY_MODE
        ):
            raise BrokeredIPCError("pinned socket directory metadata changed")

    def _stat_socket_entry(self) -> os.stat_result:
        descriptor = self._socket_directory_fd
        if descriptor is None:
            raise BrokeredIPCError("socket directory identity is not pinned")
        try:
            return os.stat(self._socket_path.name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise BrokeredIPCError("socket entry is unavailable in its pinned directory") from error

    def _assert_bound_socket_identity(self) -> None:
        self._assert_pinned_socket_directory()
        identity = self._socket_identity
        if identity is None:
            raise BrokeredIPCError("socket identity is not pinned")
        try:
            path_metadata = self._socket_path.lstat()
        except OSError as error:
            raise BrokeredIPCError("bound socket path is unavailable") from error
        entry_metadata = self._stat_socket_entry()
        _same_identity(identity, (entry_metadata.st_dev, entry_metadata.st_ino), "bound socket entry")
        _same_identity(identity, (path_metadata.st_dev, path_metadata.st_ino), "bound socket path")
        if (
            not stat.S_ISSOCK(entry_metadata.st_mode)
            or entry_metadata.st_uid != self._service_uid
            or entry_metadata.st_gid != self._workload_gid
            or stat.S_IMODE(entry_metadata.st_mode) != _SOCKET_MODE
        ):
            raise BrokeredIPCError("bound socket metadata changed")

    def start(self) -> None:
        """Bind a fresh protected socket; never replace or unlink an existing path."""
        _require_linux_ipc()
        if self._listener is not None or self._closed:
            raise BrokeredIPCError("service socket cannot be started in its current state")
        directory_identity = self._validate_socket_directory()
        try:
            directory_fd = os.open(self._socket_path.parent, _DIRECTORY_FLAGS)
        except OSError as error:
            raise BrokeredIPCError("socket directory could not be pinned") from error
        self._socket_directory_fd = directory_fd
        self._socket_directory_identity = directory_identity
        try:
            descriptor_metadata = os.fstat(directory_fd)
            _same_identity(directory_identity, (descriptor_metadata.st_dev, descriptor_metadata.st_ino), "socket directory handle")
            self._assert_pinned_socket_directory()
        except (OSError, BrokeredIPCError):
            os.close(directory_fd)
            self._socket_directory_fd = None
            self._socket_directory_identity = None
            raise
        try:
            os.stat(self._socket_path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            self._close_socket_directory()
            raise BrokeredIPCError("socket path could not be checked safely") from error
        else:
            self._close_socket_directory()
            raise BrokeredIPCError("socket path already exists")

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        bound_identity: tuple[int, int] | None = None
        try:
            self._assert_pinned_socket_directory()
            listener.bind(os.fspath(self._socket_path))
            metadata = self._stat_socket_entry()
            bound_identity = (metadata.st_dev, metadata.st_ino)
            os.chown(self._socket_path.name, self._service_uid, self._workload_gid, dir_fd=directory_fd, follow_symlinks=False)
            os.chmod(self._socket_path.name, _SOCKET_MODE, dir_fd=directory_fd, follow_symlinks=False)
            self._socket_identity = bound_identity
            self._assert_pinned_socket_directory()
            self._assert_bound_socket_identity()
            metadata = self._stat_socket_entry()
            if (
                not stat.S_ISSOCK(metadata.st_mode)
                or metadata.st_uid != self._service_uid
                or metadata.st_gid != self._workload_gid
                or stat.S_IMODE(metadata.st_mode) != _SOCKET_MODE
                or (metadata.st_dev, metadata.st_ino) != bound_identity
            ):
                raise BrokeredIPCError("bound socket identity is invalid")
            listener.listen(8)
            listener.settimeout(0.25)
        except (OSError, BrokeredIPCError) as error:
            listener.close()
            if bound_identity is not None:
                try:
                    self._unlink_own_socket(bound_identity, tolerate_missing=True)
                except BrokeredIPCError:
                    pass
            self._socket_identity = None
            self._close_socket_directory()
            if isinstance(error, BrokeredIPCError):
                raise
            raise BrokeredIPCError("Linux broker socket could not be bound safely") from error
        self._socket_identity = bound_identity
        self._listener = listener

    def _unlink_own_socket(
        self,
        identity: tuple[int, int],
        *,
        tolerate_missing: bool = False,
    ) -> None:
        self._assert_pinned_socket_directory()
        try:
            metadata = self._socket_path.lstat()
        except FileNotFoundError:
            if tolerate_missing:
                self._assert_pinned_socket_directory()
                try:
                    os.stat(self._socket_path.name, dir_fd=self._socket_directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return
                except OSError as error:
                    raise BrokeredIPCError("bound socket entry is unavailable") from error
                raise BrokeredIPCError("bound socket path no longer names the pinned entry")
            raise BrokeredIPCError("bound socket disappeared before close")
        except OSError as error:
            raise BrokeredIPCError("bound socket identity is unavailable") from error
        entry_metadata = self._stat_socket_entry()
        if not stat.S_ISSOCK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != _SOCKET_MODE:
            raise BrokeredIPCError("refusing to unlink a replaced socket")
        _same_identity(identity, (metadata.st_dev, metadata.st_ino), "bound socket path")
        _same_identity(identity, (entry_metadata.st_dev, entry_metadata.st_ino), "bound socket entry")
        if metadata.st_uid != self._service_uid or metadata.st_gid != self._workload_gid:
            raise BrokeredIPCError("refusing to unlink a socket with changed ownership")
        try:
            os.unlink(self._socket_path.name, dir_fd=self._socket_directory_fd)
        except OSError as error:
            raise BrokeredIPCError("owned broker socket could not be closed") from error

    def _close_socket_directory(self) -> None:
        descriptor = self._socket_directory_fd
        self._socket_directory_fd = None
        self._socket_directory_identity = None
        if descriptor is not None:
            os.close(descriptor)

    def close(self) -> None:
        """Close this listener and remove only the exact socket inode it bound."""
        if self._closed:
            return
        self._closed = True
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        try:
            if self._socket_identity is not None:
                self._unlink_own_socket(self._socket_identity, tolerate_missing=True)
                self._socket_identity = None
        finally:
            self._close_socket_directory()

    def request_stop(self) -> Receipt:
        """Durably fence this run; this does not terminate a workload process."""
        return self._operator.request_stop(self._grant.run_id)

    def handle_packet(self, peer_uid: int, raw: bytes) -> bytes:
        """Process one authenticated peer packet without exposing service authority."""
        if type(peer_uid) is not int or peer_uid != self._workload_uid:
            return _protocol_denial("PEER_IDENTITY")
        request, denial = _parse_request(raw)
        if denial is not None or request is None:
            return _protocol_denial(denial or "MALFORMED_INPUT")
        client = self._operator.client(self._grant)
        operation = request["op"]
        if operation == "submit":
            receipt = client.admit(request["operation_id"])
            return _receipt_response(receipt)
        queue_id = request["queue_id"]
        if operation == "dispatch":
            receipt = self._operator.dispatch_for_run(queue_id, self._grant.run_id)
            return _receipt_response(receipt)
        if operation == "get_result":
            report = self._operator._result_for_run(queue_id, self._grant.run_id)
            if report is None:
                return _canonical_json(
                    {
                        "code": "NOT_FOUND",
                        "outcome": "DENIED",
                        "phase": "result",
                        "queue_id": queue_id,
                        "schema_version": IPC_SCHEMA,
                    }
                )
            response = {
                "outcome": "AVAILABLE",
                "phase": "result",
                "queue_id": queue_id,
                "report": report,
                "schema_version": IPC_SCHEMA,
            }
            raw_response = _canonical_json(response)
            if (
                len(_canonical_json(response["report"])) > MAX_RESULT_BYTES
                or len(raw_response) > MAX_IPC_RESPONSE_BYTES
            ):
                raise RuntimeError("durable synthetic report exceeded its response bound")
            return raw_response
        raise RuntimeError("validated IPC operation was not handled")

    def serve_once(self) -> bool:
        """Accept and answer one request; return False when the listener timed out."""
        if self._listener is None or self._closed:
            raise BrokeredIPCError("broker socket is not running")
        self._assert_bound_socket_identity()
        try:
            connection, _ = self._listener.accept()
        except TimeoutError:
            return False
        with connection:
            connection.settimeout(2.0)
            try:
                self._assert_bound_socket_identity()
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                )
                _, peer_uid, _ = struct.unpack("3i", credentials)
                if peer_uid != self._workload_uid:
                    connection.send(_protocol_denial("PEER_IDENTITY"))
                    return True
                raw = connection.recv(MAX_IPC_REQUEST_BYTES + 1)
            except (OSError, TimeoutError):
                return True
            response = self.handle_packet(peer_uid, raw)
            try:
                connection.send(response)
            except OSError:
                pass
        return True

    def serve_forever(self, stop_event: threading.Event | None = None) -> None:
        """Serve until the trusted service controller sets ``stop_event``."""
        if self._listener is None:
            self.start()
        while not self._closed and (stop_event is None or not stop_event.is_set()):
            self.serve_once()
        if stop_event is not None and stop_event.is_set():
            self.request_stop()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class BrokeredLinuxClient:
    """Workload-side client; it has no registrar, grant, or target API."""

    def __init__(
        self,
        socket_path: Path | str,
        *,
        service_uid: int,
        timeout: float = 2.0,
    ) -> None:
        self._socket_path = Path(socket_path)
        if type(service_uid) is not int or service_uid <= 0:
            raise ValueError("service UID must be a non-root integer")
        self._service_uid = service_uid
        if not self._socket_path.is_absolute():
            raise ValueError("socket path must be absolute")
        if len(os.fsencode(self._socket_path)) >= 108:
            raise ValueError("socket path exceeds the Linux Unix-domain limit")
        if type(timeout) not in (int, float) or timeout <= 0 or timeout > 10:
            raise ValueError("timeout must be a positive value no greater than ten seconds")
        self._timeout = float(timeout)

    def request_bytes(self, raw: bytes) -> dict[str, Any]:
        """Send one bounded canonical request; exposed for strict-parser tests."""
        _require_linux_ipc()
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_IPC_REQUEST_BYTES:
            raise ValueError("request size is outside the IPC bound")
        workload_uid = os.geteuid()
        workload_gid = os.getegid()
        workload_groups = set(os.getgroups()) | {workload_gid}
        _validate_client_identity(
            self._service_uid,
            workload_uid,
            workload_gid,
            workload_groups,
        )
        before = _client_socket_snapshot(self._socket_path, self._service_uid)
        if before[2] not in workload_groups:
            raise BrokeredIPCError("workload is not a member of the broker IPC group")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(self._timeout)
            connection.connect(os.fspath(self._socket_path))
            try:
                credentials = connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize("3i"),
                )
            except OSError as error:
                raise BrokeredIPCError("broker server credentials are unavailable") from error
            _, peer_uid, _ = struct.unpack("3i", credentials)
            if peer_uid != self._service_uid:
                raise BrokeredIPCError("connected server UID does not match the trusted service")
            after = _client_socket_snapshot(self._socket_path, self._service_uid)
            if before != after:
                raise BrokeredIPCError("broker socket path changed during connection")
            sent = connection.send(raw)
            if sent != len(raw):
                raise BrokeredIPCError("request could not be sent as one packet")
            response = connection.recv(MAX_IPC_RESPONSE_BYTES + 1)
        if not response or len(response) > MAX_IPC_RESPONSE_BYTES:
            raise BrokeredIPCError("broker response is empty or exceeds its bound")
        return _parse_response(response)

    def submit(self, operation_id: str) -> dict[str, Any]:
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            raise ValueError("operation identifier is invalid")
        return self.request_bytes(
            _canonical_json(
                {
                    "op": "submit",
                    "operation_id": operation_id,
                    "schema_version": IPC_SCHEMA,
                }
            )
        )

    def dispatch(self, queue_id: str) -> dict[str, Any]:
        if not isinstance(queue_id, str) or not _HEX32.fullmatch(queue_id):
            raise ValueError("queue identifier is invalid")
        return self.request_bytes(
            _canonical_json({"op": "dispatch", "queue_id": queue_id, "schema_version": IPC_SCHEMA})
        )

    def get_result(self, queue_id: str) -> dict[str, Any]:
        if not isinstance(queue_id, str) or not _HEX32.fullmatch(queue_id):
            raise ValueError("queue identifier is invalid")
        return self.request_bytes(
            _canonical_json(
                {"op": "get_result", "queue_id": queue_id, "schema_version": IPC_SCHEMA}
            )
        )


__all__ = [
    "IPC_SCHEMA",
    "MAX_IPC_REQUEST_BYTES",
    "MAX_IPC_RESPONSE_BYTES",
    "MAX_RESULT_BYTES",
    "BrokeredIPCError",
    "BrokeredLinuxClient",
    "BrokeredLinuxService",
]
