"""Bounded local client protocol for the protected supervisor."""

from __future__ import annotations

import json
import socket
import struct
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
    "revoke": ADMIN_SOCKET,
    "kill": OPERATOR_SOCKET,
    "start": OPERATOR_SOCKET,
}


def _receive(connection: socket.socket) -> dict[str, Any]:
    header_chunks: list[bytes] = []
    remaining = 4
    while remaining:
        chunk = connection.recv(remaining)
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
        chunk = connection.recv(length)
        if not chunk:
            raise JsonInputError("truncated supervisor response")
        chunks.append(chunk)
        length -= len(chunk)
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
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
