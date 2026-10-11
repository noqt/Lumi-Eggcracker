"""Bounded local client protocol for the protected supervisor."""

from __future__ import annotations

import json
import math
import socket
import struct
import time
from collections.abc import Callable
from typing import Any

from .jsonio import JsonInputError

MAX_FRAME = 32 * 1024
QUERY_SOCKET = "/run/lumi-eggcracker/query.sock"
OPERATOR_SOCKET = "/run/lumi-eggcracker/operator.sock"
ADMIN_SOCKET = "/run/lumi-eggcracker/admin.sock"

SOCKETS = {
    "approvals": QUERY_SOCKET,
    "detections": QUERY_SOCKET,
    "exec_policies": QUERY_SOCKET,
    "doctor": QUERY_SOCKET,
    "list": QUERY_SOCKET,
    "status": QUERY_SOCKET,
    "approve": ADMIN_SOCKET,
    "exec_policy_create": ADMIN_SOCKET,
    "exec_policy_revoke": ADMIN_SOCKET,
    "incidents": QUERY_SOCKET,
    "history": QUERY_SOCKET,
    "incident_show": ADMIN_SOCKET,
    "incident_acknowledge": ADMIN_SOCKET,
    "incident_clear": ADMIN_SOCKET,
    "revoke": ADMIN_SOCKET,
    "check_start": OPERATOR_SOCKET,
    "kill": OPERATOR_SOCKET,
    "start": OPERATOR_SOCKET,
}


class RequestDeadlineExceeded(TimeoutError):
    """The absolute request deadline expired before or during an I/O step."""


class _DeadlineClock:
    """Track one request's monotonic samples and remaining deadline."""

    def __init__(self, deadline_monotonic: float) -> None:
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(deadline_monotonic)
        ):
            raise JsonInputError("invalid request deadline")
        self.deadline = float(deadline_monotonic)
        self._last: float | None = None

    def remaining(self) -> float:
        now = time.monotonic()
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
            or self._last is not None
            and now < self._last
        ):
            raise JsonInputError("request clock is not monotonic")
        self._last = float(now)
        remaining = self.deadline - self._last
        if remaining <= 0:
            raise RequestDeadlineExceeded("request deadline expired")
        return remaining

    def set_timeout(self, connection: socket.socket) -> None:
        connection.settimeout(self.remaining())


def _receive(
    connection: socket.socket,
    *,
    decode: Callable[[str], Any] | None = None,
    deadline_monotonic: float | None = None,
    _deadline_clock: _DeadlineClock | None = None,
) -> dict[str, Any]:
    deadline_clock = _deadline_clock
    if deadline_monotonic is not None:
        if deadline_clock is None:
            deadline_clock = _DeadlineClock(deadline_monotonic)
        elif deadline_clock.deadline != deadline_monotonic:
            raise JsonInputError("request deadlines do not match")

    def receive(size: int) -> bytes:
        if deadline_clock is not None:
            deadline_clock.set_timeout(connection)
        try:
            return connection.recv(size)
        except TimeoutError as error:
            if deadline_clock is not None:
                raise RequestDeadlineExceeded("request deadline expired") from error
            raise

    header_chunks: list[bytes] = []
    remaining = 4
    while remaining:
        chunk = receive(remaining)
        if not chunk:
            raise JsonInputError("truncated supervisor response")
        header_chunks.append(chunk)
        remaining -= len(chunk)
    header = b"".join(header_chunks)
    length = struct.unpack("!I", header)[0]
    if not 1 <= length <= MAX_FRAME:
        raise JsonInputError("invalid supervisor response frame")
    chunks: list[bytes] = []
    while length:
        chunk = receive(length)
        if not chunk:
            raise JsonInputError("truncated supervisor response")
        chunks.append(chunk)
        length -= len(chunk)
    try:
        text = b"".join(chunks).decode("utf-8")
        value = json.loads(text) if decode is None else decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JsonInputError(f"invalid supervisor response: {error}") from error
    if not isinstance(value, dict):
        raise JsonInputError("supervisor response must be an object")
    return value


def request(action: str, **args: Any) -> dict[str, Any]:
    try:
        socket_path = SOCKETS[action]
    except KeyError as error:
        raise JsonInputError("unsupported client action") from error
    payload = json.dumps({"action": action, "args": args}, sort_keys=True, separators=(",", ":")).encode()
    if not 1 <= len(payload) <= MAX_FRAME:
        raise JsonInputError("supervisor request is too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        # A transient systemd unit may take several seconds to schedule under
        # the fork-race qualification load while its launch gate stays closed.
        connection.settimeout(30.0)
        connection.connect(socket_path)
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        response = _receive(connection)
    if set(response) != {"ok", "value"} or not isinstance(response["ok"], bool):
        raise JsonInputError("supervisor response contract is invalid")
    if not response["ok"]:
        raise JsonInputError(str(response["value"]))
    if not isinstance(response["value"], dict):
        raise JsonInputError("supervisor value is invalid")
    return response["value"]


def request_before(action: str, *, deadline_monotonic: float, **args: Any) -> dict[str, Any]:
    """Request one action, bounded by one absolute monotonic deadline.

    This path is intentionally separate from :func:`request`: existing callers
    retain their fixed thirty-second socket timeout, while bounded workflows
    receive a timeout that shrinks before every potentially blocking step.
    """

    try:
        socket_path = SOCKETS[action]
    except KeyError as error:
        raise JsonInputError("unsupported client action") from error
    payload = json.dumps(
        {"action": action, "args": args}, sort_keys=True, separators=(",", ":")
    ).encode()
    if not 1 <= len(payload) <= MAX_FRAME:
        raise JsonInputError("supervisor request is too large")
    deadline_clock = _DeadlineClock(deadline_monotonic)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        deadline_clock.set_timeout(connection)
        try:
            connection.connect(socket_path)
        except TimeoutError as error:
            raise RequestDeadlineExceeded("request deadline expired") from error
        deadline_clock.set_timeout(connection)
        try:
            connection.sendall(struct.pack("!I", len(payload)) + payload)
        except TimeoutError as error:
            raise RequestDeadlineExceeded("request deadline expired") from error
        response = _receive(
            connection,
            deadline_monotonic=deadline_monotonic,
            _deadline_clock=deadline_clock,
        )
    if set(response) != {"ok", "value"} or not isinstance(response["ok"], bool):
        raise JsonInputError("supervisor response contract is invalid")
    if not response["ok"]:
        raise JsonInputError(str(response["value"]))
    if not isinstance(response["value"], dict):
        raise JsonInputError("supervisor value is invalid")
    return response["value"]


def _strict_doctor_json(text: str) -> Any:
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > 64:
                raise ValueError("excessive nesting")
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise ValueError("nonfinite value")

    def number(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite value")
        return result

    def integer(value: str) -> int:
        if len(value.lstrip("-")) > 4096:
            raise ValueError("oversized integer")
        return int(value)

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number, parse_int=integer)


def doctor_strict() -> dict[str, Any]:
    """Query only doctor with empty arguments and strict, redacted response validation."""
    payload = b'{"action":"doctor","args":{}}'
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30.0)
            connection.connect(SOCKETS["doctor"])
            connection.sendall(struct.pack("!I", len(payload)) + payload)
            response = _receive(connection, decode=_strict_doctor_json)
        if (
            set(response) != {"ok", "value"}
            or type(response["ok"]) is not bool
            or not response["ok"]
            or not isinstance(response["value"], dict)
        ):
            raise ValueError("invalid envelope")
    except (OSError, JsonInputError, ValueError, RecursionError):
        raise JsonInputError("doctor response unavailable") from None
    return response["value"]
