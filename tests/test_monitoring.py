"""Actual source entry-point journey against the unchanged framed query client."""

from __future__ import annotations

import contextlib
import inspect
import io
import json
import math
import os
import runpy
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import client, monitoring
from lumi_eggcracker.jsonio import JsonInputError

ROOT = Path(__file__).resolve().parents[1]
HEALTHY = {
    "autonomous_discovery": True,
    "discovery": {"healthy": True, "receipt_persistence_healthy": True},
    "installation": {"state": "HEALTHY"},
}
STRICT_BAD = [
    b'{"ok":true,"ok":true,"value":{}}',
    b'{"ok":true,"value":{"ignored":{"a":1,"a":2}}}',
    b'{"ok":true,"value":{"ignored":{"a":1,"\\u0061":2}}}',
    *[b'{"ok":true,"value":{"ignored":' + value + b'}}' for value in (b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400")],
    b'{"ok":true,"value":{"ignored":' + b"9" * 5000 + b'}}',
    b'{"ok":true,"value":{"ignored":' + b"[" * 1100 + b"0" + b"]" * 1100 + b'}}',
    b"\xff",
]


def entrypoint(output: Path) -> int:
    with patch.object(sys, "argv", ["export_monitoring_metrics.py", "--output", str(output)]), contextlib.redirect_stderr(io.StringIO()):
        try:
            runpy.run_path(str(ROOT / "scripts/export_monitoring_metrics.py"), run_name="__main__")
        except SystemExit as error:
            return error.code
    raise AssertionError("entry point did not exit")


@contextlib.contextmanager
def framed_response(root: Path, payload: bytes, declared_length: int | None = None, *, fragment: bool = False, expected_args: dict | None = None, wire: bytes | None = None):
    """Map only doctor to one disposable socket; preserve actual production framing."""
    address = str(root / "fixture.sock")
    requests = []
    failures = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(address)
        server.listen(1)
        server.settimeout(5)

        def serve():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    header = b""
                    while len(header) < 4:
                        block = connection.recv(4 - len(header))
                        if not block:
                            raise OSError("truncated fixture request")
                        header += block
                    length = struct.unpack("!I", header)[0]
                    data = b""
                    while len(data) < length:
                        block = connection.recv(length - len(data))
                        if not block:
                            raise OSError("truncated fixture request")
                        data += block
                    requests.append(json.loads(data))
                    frame = wire if wire is not None else struct.pack("!I", len(payload) if declared_length is None else declared_length) + payload
                    if fragment:
                        for byte in frame:
                            connection.sendall(bytes([byte]))
                    else:
                        connection.sendall(frame)
            except OSError as error:
                failures.append(type(error).__name__)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            with patch.dict(client.SOCKETS, {"doctor": address}):
                yield requests
        finally:
            worker.join(6)
            if worker.is_alive() or failures:
                raise AssertionError("fixture did not complete")
    Path(address).unlink()
    if requests != [{"action": "doctor", "args": expected_args or {}}]:
        raise AssertionError("unexpected query action")


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "geteuid"), "Linux Unix socket fixture")
class FramedJourneyTests(unittest.TestCase):
    def test_bad_framed_responses_publish_query_invalid(self):
        responses = [
            (b"not-json", None),
            (b"{}", 32769),
            (b'{"ok":false,"value":"PRIVATE"}', None),
            (b'{"ok":true,"value":{}}', None),
            (b'{"ok":true,"value":{"autonomous_discovery":true,"discovery":{"healthy":true,"receipt_persistence_healthy":true},"installation":{"state":"UNKNOWN"}}}', None),
            (b"{}", 0),
            (b"{}", 5),
            (b'{"ok":1,"value":{}}', None),
            (b'{"ok":true,"value":[]}', None),
            (b'{"ok":true,"value":{},"extra":0}', None),
            (b"[]", None),
            *[(payload, None) for payload in STRICT_BAD],
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "health.prom"
            for payload, declared in responses:
                with self.subTest(payload=payload), framed_response(root, payload, declared):
                    self.assertEqual(entrypoint(output), 1)
                    text = output.read_text()
                    self.assertIn("eggcracker_query_valid 0", text)
                    self.assertNotIn("PRIVATE", text)
                    self.assertNotIn("eggcracker_reported_ready", text)

    def test_strict_fragmentation_redaction_truncated_header_and_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = json.dumps({"ok": True, "value": HEALTHY}).encode()
            with framed_response(root, payload, fragment=True):
                self.assertEqual(client.doctor_strict(), HEALTHY)
            with framed_response(root, b"", wire=b"\x00\x00"), self.assertRaisesRegex(JsonInputError, "^doctor response unavailable$"):
                client.doctor_strict()
            arguments = {"strict": True, "decode": "ordinary forwarded argument", "socket_path": "ordinary argument"}
            with framed_response(root, b'{"ok":true,"value":{"x":1,"x":2}}', expected_args=arguments):
                self.assertEqual(client.request("doctor", **arguments), {"x": 2})
            with framed_response(root, b'{"ok":false,"value":"legacy message"}'), self.assertRaisesRegex(JsonInputError, "^legacy message$"):
                client.request("doctor")
            for bad in STRICT_BAD:
                with self.subTest(bad=bad[:40]), framed_response(root, bad), self.assertRaisesRegex(JsonInputError, "^doctor response unavailable$"):
                    client.doctor_strict()


class StrictAndLegacyTests(unittest.TestCase):
    def test_strict_decoder_and_legacy_json_semantics(self):
        for payload in STRICT_BAD:
            with self.subTest(payload=payload[:40]), self.assertRaises((ValueError, RecursionError)):
                client._strict_doctor_json(payload.decode("utf-8"))
        self.assertEqual(client._strict_doctor_json('{"nested":[{"a":1}]}'), {"nested": [{"a": 1}]})
        literal = {"quoted": '\\"' + "[" * 100}
        self.assertEqual(client._strict_doctor_json(json.dumps(literal)), literal)
        self.assertTrue(math.isnan(json.loads('{"x":NaN}')["x"]))
        self.assertEqual(str(inspect.signature(client.request)), "(action: 'str', **args: 'Any') -> 'dict[str, Any]'")
        self.assertEqual(len(inspect.signature(client.doctor_strict).parameters), 0)

    def test_legacy_roles_framing_timeout_and_arguments(self):
        roles = {
            "approvals": "query", "detections": "query", "exec_policies": "query",
            "doctor": "query", "list": "query", "status": "query", "incidents": "query",
            "approve": "admin", "exec_policy_create": "admin", "exec_policy_revoke": "admin",
            "incident_show": "admin", "incident_acknowledge": "admin", "incident_clear": "admin",
            "revoke": "admin", "kill": "operator", "start": "operator",
        }
        self.assertEqual(client.SOCKETS, {action: f"/run/lumi-eggcracker/{role}.sock" for action, role in roles.items()})
        for action in roles:
            payload = b'{"ok":true,"value":{}}'
            stream = io.BytesIO(struct.pack("!I", len(payload)) + payload)
            with self.subTest(action=action), patch.object(client.socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), create=True), patch.object(client.socket, "socket") as factory:
                connection = factory.return_value.__enter__.return_value
                connection.recv.side_effect = stream.read
                self.assertEqual(client.request(action, decode="forwarded", strict=True), {})
                factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.connect.assert_called_once_with(client.SOCKETS[action])
                connection.settimeout.assert_called_once_with(30.0)
                sent = connection.sendall.call_args.args[0]
                self.assertEqual(struct.unpack("!I", sent[:4])[0], len(sent[4:]))
                self.assertEqual(json.loads(sent[4:]), {"action": action, "args": {"decode": "forwarded", "strict": True}})
        with self.assertRaisesRegex(JsonInputError, "^unsupported client action$"):
            client.request("unknown")
        with self.assertRaisesRegex(JsonInputError, "^supervisor request is too large$"):
            client.request("doctor", large="x" * client.MAX_FRAME)

    def test_legacy_frame_and_envelope_errors(self):
        frames = [
            (b"\x00", "truncated supervisor response"),
            (struct.pack("!I", 0), "invalid supervisor response frame"),
            (struct.pack("!I", 32769), "invalid supervisor response frame"),
            (struct.pack("!I", 4) + b"{}", "truncated supervisor response"),
        ]
        for payload, expected in ((b"[]", "supervisor response must be an object"), (b"{}", "supervisor response contract is invalid"), (b'{"ok":true,"value":[]}', "supervisor value is invalid"), (b'{"ok":false,"value":"original"}', "original")):
            frames.append((struct.pack("!I", len(payload)) + payload, expected))
        for frame, expected in frames:
            stream = io.BytesIO(frame)
            with self.subTest(expected=expected), patch.object(client.socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), create=True), patch.object(client.socket, "socket") as factory:
                factory.return_value.__enter__.return_value.recv.side_effect = stream.read
                with self.assertRaisesRegex(JsonInputError, "^" + expected + "$"):
                    client.request("doctor")

    @unittest.skipUnless(sys.platform == "linux", "Linux Unix socket fixture")
    def test_actual_entrypoint_healthy_loss_stopped_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "health.prom"
            payload = json.dumps({"ok": True, "value": HEALTHY}).encode()
            with framed_response(root, payload):
                self.assertEqual(entrypoint(output), 0)
                self.assertIn("eggcracker_query_valid 1", output.read_text())
            with patch.dict(client.SOCKETS, {"doctor": str(root / "missing.sock")}):
                self.assertEqual(entrypoint(output), 1)
            stopped = output.read_bytes()
            self.assertIn(b"eggcracker_query_valid 0", stopped)
            self.assertNotIn(b"eggcracker_reported_ready", stopped)
            self.assertEqual(output.read_bytes(), stopped)
            with framed_response(root, payload):
                self.assertEqual(entrypoint(output), 0)
                self.assertIn("eggcracker_reported_ready 1", output.read_text())


class MetricTests(unittest.TestCase):
    def test_allowlist_and_unknown(self):
        value = dict(HEALTHY, workload_uid=123, catalogue={"secret": "private"})
        rendered = monitoring.render_metrics(monitoring.selected_health(value), 42)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("123", rendered)
        self.assertEqual(len([line for line in rendered.splitlines() if not line.startswith("#")]), 6)
        for broken in ({}, dict(HEALTHY, autonomous_discovery=1), dict(HEALTHY, autonomous_discovery=float("nan")), dict(HEALTHY, autonomous_discovery="true"), dict(HEALTHY, installation={"state": "NEW"}), dict(HEALTHY, discovery=None)):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                monitoring.selected_health(broken)
        invalid = monitoring.render_metrics(None, 42)
        self.assertNotIn("eggcracker_reported_ready", invalid)
        self.assertIn("eggcracker_query_valid 0", invalid)

    def test_nonfinite_clock_rejected(self):
        for value in (float("nan"), float("inf"), -1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                monitoring.render_metrics(None, value)

    def test_reported_unready_is_valid(self):
        state = dict(HEALTHY, autonomous_discovery=False)
        result = monitoring.selected_health(state)
        self.assertEqual(result["reported_ready"], 0)
        self.assertIn("eggcracker_query_valid 1", monitoring.render_metrics(result, 42))

    def test_atomic_publication_failure_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict", return_value=HEALTHY):
            output = Path(directory) / "health.prom"
            self.assertTrue(monitoring.collect(output))
            previous = output.read_bytes()
            with patch.object(monitoring.os, "replace", side_effect=OSError("private path")), self.assertRaises(OSError):
                monitoring.collect(output)
            self.assertEqual(output.read_bytes(), previous)
            self.assertEqual(list(Path(directory).iterdir()), [output])

    def test_unrelated_and_overlapping_files_preserved(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict") as query:
            output = Path(directory) / "health.prom"
            output.write_text("unrelated")
            with self.assertRaises(ValueError):
                monitoring.collect(output)
            self.assertEqual(output.read_text(), "unrelated")
            output.unlink()
            lock = Path(directory) / "health.prom.lock"
            lock.write_text("other collector")
            with self.assertRaises(FileExistsError):
                monitoring.collect(output)
            self.assertEqual(lock.read_text(), "other collector")
            query.assert_not_called()

    def test_lock_prevents_overlapping_query_and_bad_names(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict") as query:
            root = Path(directory)
            for output in (Path("relative.prom"), root / "metrics.txt", root / ".." / "health.prom"):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    monitoring.collect(output)
            query.assert_not_called()

    def test_marked_oversized_file_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict") as query:
            output = Path(directory) / "health.prom"
            content = monitoring.MARKER + "x" * monitoring.MAX_OUTPUT
            output.write_text(content)
            with self.assertRaises(ValueError):
                monitoring.collect(output)
            self.assertEqual(output.read_text(), content)
            query.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX hard links and permissions")
    def test_hard_link_and_writable_marked_file_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict", return_value=HEALTHY):
            root = Path(directory)
            output = root / "health.prom"
            monitoring.collect(output)
            other = root / "preserved"
            os.link(output, other)
            with self.assertRaises(ValueError):
                monitoring.collect(output)
            self.assertEqual(output.read_bytes(), other.read_bytes())
            other.unlink()
            output.chmod(0o666)
            with self.assertRaises(ValueError):
                monitoring.collect(output)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership and symlinks")
    def test_unsafe_output_and_parent_preserved(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict") as query:
            root = Path(directory)
            output = root / "health.prom"
            output.symlink_to(root / "missing")
            with self.assertRaises(ValueError):
                monitoring.collect(output)
            self.assertTrue(output.is_symlink())
            output.unlink()
            root.chmod(0o777)
            with self.assertRaises(ValueError):
                monitoring.collect(output)
            root.chmod(0o700)
            query.assert_not_called()

    def test_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(monitoring, "doctor_strict", side_effect=OSError("SECRET")), contextlib.redirect_stderr(io.StringIO()) as error:
            output = Path(directory) / "health.prom"
            self.assertEqual(monitoring.main(["--output", str(output)]), 1)
            self.assertNotIn("SECRET", error.getvalue() + output.read_text())
