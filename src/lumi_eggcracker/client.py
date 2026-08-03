"""Bounded local client protocol for the protected supervisor."""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

from .jsonio import JsonInputError

MAX_FRAME = 32 * 1024
SOCKET_PATH = "/run/lumi-eggcracker/control.sock"


def _receive(connection: socket.socket) -> dict[str, Any]:
    header = connection.recv(4)
    if len(header) != 4:
        raise JsonInputError("truncated supervisor response")
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
    payload = json.dumps({"action": action, "args": args}, sort_keys=True, separators=(",", ":")).encode()
    if not 1 <= len(payload) <= MAX_FRAME:
        raise JsonInputError("supervisor request is too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3.0)
        connection.connect(SOCKET_PATH)
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        response = _receive(connection)
    if set(response) != {"ok", "value"} or not isinstance(response["ok"], bool):
        raise JsonInputError("supervisor response contract is invalid")
    if not response["ok"]:
        raise JsonInputError(str(response["value"]))
    if not isinstance(response["value"], dict):
        raise JsonInputError("supervisor value is invalid")
    return response["value"]
