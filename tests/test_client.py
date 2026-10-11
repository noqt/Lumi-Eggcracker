from __future__ import annotations

import json
import struct
import unittest
from typing import Self
from unittest.mock import patch

from lumi_eggcracker.client import (
    RequestDeadlineExceeded,
    request,
    request_before,
)
from lumi_eggcracker.jsonio import JsonInputError


class FakeSocket:
    def __init__(self, response: dict[str, object], *, chunks: list[bytes] | None = None) -> None:
        body = json.dumps(response, separators=(",", ":")).encode("utf-8")
        frame = struct.pack("!I", len(body)) + body
        self._chunks = list(chunks) if chunks is not None else [frame[:4], frame[4:]]
        self.timeouts: list[float] = []
        self.connect_calls: list[str] = []
        self.sendall_calls: list[bytes] = []
        self.recv_calls: list[int] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, path: str) -> None:
        self.connect_calls.append(path)

    def sendall(self, value: bytes) -> None:
        self.sendall_calls.append(value)

    def recv(self, size: int) -> bytes:
        self.recv_calls.append(size)
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class ClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.af_unix = patch("lumi_eggcracker.client.socket.AF_UNIX", 1, create=True)
        self.sock_stream = patch("lumi_eggcracker.client.socket.SOCK_STREAM", 1, create=True)
        self.af_unix.start()
        self.sock_stream.start()

    def tearDown(self) -> None:
        self.sock_stream.stop()
        self.af_unix.stop()

    def response_socket(self) -> FakeSocket:
        return FakeSocket({"ok": True, "value": {"state": "RUNNING"}})

    def test_existing_request_keeps_fixed_thirty_second_timeout(self) -> None:
        connection = self.response_socket()
        with patch("lumi_eggcracker.client.socket.socket", return_value=connection):
            self.assertEqual({"state": "RUNNING"}, request("status", name="demo"))
        self.assertEqual([30.0], connection.timeouts)
        self.assertEqual(["/run/lumi-eggcracker/query.sock"], connection.connect_calls)

    def test_request_before_shrinks_timeout_before_connect_send_and_each_recv(self) -> None:
        response = {"ok": True, "value": {"state": "RUNNING"}}
        body = json.dumps(response, separators=(",", ":")).encode("utf-8")
        frame = struct.pack("!I", len(body)) + body
        connection = FakeSocket(
            response,
            chunks=[
                frame[:1],
                frame[1:3],
                frame[3:4],
                frame[4:5],
                frame[5:8],
                frame[8:],
            ],
        )
        with patch(
            "lumi_eggcracker.client.time.monotonic",
            side_effect=[1.0, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9],
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection):
            value = request_before("status", deadline_monotonic=2.0, name="demo")
        self.assertEqual({"state": "RUNNING"}, value)
        self.assertEqual(8, len(connection.timeouts))
        for actual, expected in zip(
            connection.timeouts, [1.0, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1]
        ):
            self.assertAlmostEqual(expected, actual)
        self.assertEqual(
            [4, 3, 1, len(body), len(body) - 1, len(body) - 4],
            connection.recv_calls,
        )

    def test_request_before_rejects_expiry_without_starting_connect(self) -> None:
        connection = self.response_socket()
        with patch(
            "lumi_eggcracker.client.time.monotonic", return_value=2.0
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection), self.assertRaises(
            RequestDeadlineExceeded
        ):
            request_before("status", deadline_monotonic=2.0, name="demo")
        self.assertEqual([], connection.timeouts)
        self.assertEqual([], connection.connect_calls)
        self.assertEqual([], connection.sendall_calls)

    def test_request_before_rejects_expiry_without_starting_send(self) -> None:
        connection = self.response_socket()
        with patch(
            "lumi_eggcracker.client.time.monotonic", side_effect=[1.0, 2.0]
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection), self.assertRaises(
            RequestDeadlineExceeded
        ):
            request_before("status", deadline_monotonic=2.0, name="demo")
        self.assertEqual([1.0], connection.timeouts)
        self.assertEqual(["/run/lumi-eggcracker/query.sock"], connection.connect_calls)
        self.assertEqual([], connection.sendall_calls)

    def test_request_before_rejects_expiry_before_body_recv(self) -> None:
        response = {"ok": True, "value": {"state": "RUNNING"}}
        body = json.dumps(response, separators=(",", ":")).encode("utf-8")
        connection = FakeSocket(
            response,
            chunks=[struct.pack("!I", len(body)), body[:1], body[1:]],
        )
        with patch(
            "lumi_eggcracker.client.time.monotonic",
            side_effect=[1.0, 1.1, 1.2, 2.0],
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection), self.assertRaises(
            RequestDeadlineExceeded
        ):
            request_before("status", deadline_monotonic=2.0, name="demo")
        self.assertEqual(3, len(connection.timeouts))
        for actual, expected in zip(connection.timeouts, [1.0, 0.9, 0.8]):
            self.assertAlmostEqual(expected, actual)
        self.assertEqual([4], connection.recv_calls)

    def test_request_before_rejects_non_monotonic_clock(self) -> None:
        connection = self.response_socket()
        with patch(
            "lumi_eggcracker.client.time.monotonic", side_effect=[1.0, 0.5]
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection), self.assertRaises(
            JsonInputError
        ):
            request_before("status", deadline_monotonic=2.0, name="demo")
        self.assertEqual([], connection.sendall_calls)

    def test_request_before_converts_socket_timeout_to_deadline_failure(self) -> None:
        connection = self.response_socket()
        connection.recv = lambda _size: (_ for _ in ()).throw(TimeoutError())  # type: ignore[method-assign]
        with patch(
            "lumi_eggcracker.client.time.monotonic", side_effect=[1.0, 1.1, 1.2]
        ), patch("lumi_eggcracker.client.socket.socket", return_value=connection), self.assertRaises(
            RequestDeadlineExceeded
        ):
            request_before("status", deadline_monotonic=2.0, name="demo")


if __name__ == "__main__":
    unittest.main()
