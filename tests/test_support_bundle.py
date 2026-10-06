from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
import stat
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from lumi_eggcracker import support_bundle
from lumi_eggcracker.jsonio import JsonInputError

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_SPEC = importlib.util.spec_from_file_location(
    "support_bundle_script", ROOT / "scripts" / "support_bundle.py"
)
if SCRIPT_SPEC is None or SCRIPT_SPEC.loader is None:
    raise RuntimeError("cannot load support-bundle script")
support_bundle_script = importlib.util.module_from_spec(SCRIPT_SPEC)
SCRIPT_SPEC.loader.exec_module(support_bundle_script)


class SupportBundleTests(unittest.TestCase):
    @staticmethod
    def host() -> dict[str, object]:
        return {
            "platform": "TestOS",
            "kernel": "test-kernel",
            "machine": "test-machine",
            "python": "3.11.0",
            "cgroup_v2": False,
            "controllers": [],
            "pidfd_open": False,
            "pidfd_send_signal": False,
            "systemd": None,
        }

    @unittest.skipUnless(os.name == "posix", "installed helper is native-Linux behavior")
    def test_release_helper_delegates_to_installed_zipapp(self) -> None:
        installed = Path("/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz")
        with (
            mock.patch.object(support_bundle_script.os, "geteuid", return_value=0),
            mock.patch.object(
                support_bundle_script,
                "validated_installed_app",
                return_value=installed,
            ),
            mock.patch.object(
                support_bundle_script.os,
                "execv",
                side_effect=OSError("sentinel"),
            ) as execute,
            self.assertRaisesRegex(OSError, "sentinel"),
        ):
            support_bundle_script.main(["--output", "/tmp/support.json"])
        execute.assert_called_once_with(
            "/usr/bin/python3",
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                str(installed),
                "support-bundle",
                "--output",
                "/tmp/support.json",
            ],
        )

    @staticmethod
    def query(action: str, **_args: object) -> dict[str, object]:
        if action == "doctor":
            return {
                "result": "PASS",
                "backend": "root-supervisor",
                "version": "0.6.0",
                "workload_uid": 997,
                "autonomous_discovery": True,
                "cgroup_v2": True,
                "pidfd": True,
                "execution_boundary": {
                    "linux": True,
                    "architecture": True,
                    "fcntl": True,
                    "libc": True,
                    "user_notification": True,
                    "supported": True,
                },
                "installation": {
                    "state": "HEALTHY",
                    "journal": False,
                    "files_match": True,
                    "manifest_version": "1.0.10",
                },
                "incidents": {
                    "healthy": True,
                    "count": 2,
                    "active": 1,
                    "lockdown": True,
                },
                "network": {
                    "mode": "offline",
                    "cleanup_healthy": True,
                    "primitives": {"supported": True},
                },
                "discovery": {
                    "healthy": True,
                    "consecutive_failures": 0,
                    "last_scan_duration_ms": 2.0,
                    "last_scan_completed": True,
                    "receipt_persistence_healthy": True,
                    "private_path": "/secret",
                },
            }
        if action == "detections":
            return {
                "detections": [
                    {
                        "event_id": "SENTINEL-EVENT-ID",
                        "result": "TERMINATED",
                        "trigger": "UNAPPROVED_AI",
                        "version": "0.6.0",
                        "detector": {"profile": "content.gguf-llama", "path": "/private/model.gguf"},
                        "boundary": {
                            "address_family": "inet",
                            "mode": "offline",
                            "policy_sha256": "a" * 64,
                            "violation": "DENIED",
                        },
                        "argv": ["--secret"],
                    }
                ]
            }
        if action == "list":
            return {"runs": [{"name": "private-name", "state": "TERMINATED", "unit": "/private"}]}
        if action == "incidents":
            return {"incidents": [{"state": "ACTIVE"}, {"state": "CLOSED"}]}
        raise AssertionError(action)

    def test_collect_is_redacted_and_bounded(self) -> None:
        with mock.patch.object(support_bundle, "_host", return_value=self.host()):
            value = support_bundle.collect(self.query)
        text = str(value)
        self.assertNotIn("/private", text)
        self.assertNotIn("--secret", text)
        self.assertEqual(1, len(value["receipts"]))
        self.assertEqual({"TERMINATED": 1}, value["workloads"]["states"])
        self.assertFalse(value["privacy"]["raw_receipts"])
        self.assertEqual(1, value["incidents"]["active"])
        self.assertEqual({"ACTIVE": 1, "CLOSED": 1}, value["incidents"]["states"])

    def test_validate_returns_only_aggregate_summary_without_modifying_input(self) -> None:
        with mock.patch.object(support_bundle, "_host", return_value=self.host()):
            value = support_bundle.collect(self.query)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bundle.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            original = path.read_bytes()
            digest = hashlib.sha256(original).hexdigest()
            with (
                mock.patch.object(support_bundle, "collect") as collect,
                mock.patch.object(support_bundle, "request") as request,
                mock.patch.object(support_bundle, "_host") as host,
                mock.patch.object(support_bundle.subprocess, "run") as run,
                mock.patch.object(socket, "socket") as create_socket,
            ):
                summary = support_bundle.validate_bundle(path)
            collect.assert_not_called()
            request.assert_not_called()
            host.assert_not_called()
            run.assert_not_called()
            create_socket.assert_not_called()
            self.assertEqual(
                {
                    "result": "STRUCTURE_VALID",
                    "schema_version": "lumi-eggcracker.support-bundle.v1",
                    "receipts": {
                        "included": 1,
                        "maximum_included": 100,
                        "total_represented": False,
                    },
                    "workloads": {"run_count": 1, "reported_state_count": 1},
                    "incidents": {
                        "count": 2,
                        "active_count": 1,
                        "reported_state_count": 2,
                    },
                    "limitations": (
                        "Structural validation only; not authentication, privacy assurance, "
                        "completeness, containment, or incident truth."
                    ),
                },
                summary,
            )
            serialized = json.dumps(summary, sort_keys=True)
            for value_to_hide in (
                "SENTINEL-EVENT-ID",
                "content.gguf-llama",
                "root-supervisor",
                "/private",
                "--secret",
                "997",
            ):
                self.assertNotIn(value_to_hide, serialized)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(original, path.read_bytes())

    def test_validate_uses_nonblocking_open_after_mocked_fifo_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bundle.json"
            path.write_text("{}", encoding="utf-8")
            fake_descriptor = 937
            nonblock_flag = getattr(os, "O_NONBLOCK", 1 << 30)
            fifo_stat = os.stat_result(
                (stat.S_IFIFO | 0o600, 1, 1, 1, 1, 1, 0, 0, 0, 0)
            )
            with (
                mock.patch.object(
                    support_bundle.os, "open", return_value=fake_descriptor
                ) as open_file,
                mock.patch.object(support_bundle.os, "fstat", return_value=fifo_stat),
                mock.patch.object(support_bundle.os, "close") as close_file,
                mock.patch.object(support_bundle.os, "fdopen") as fdopen,
                mock.patch.object(
                    support_bundle.os,
                    "O_NONBLOCK",
                    nonblock_flag,
                    create=True,
                ),
                self.assertRaises(JsonInputError),
            ):
                support_bundle.validate_bundle(path)

            open_file.assert_called_once()
            self.assertEqual(path, open_file.call_args.args[0])
            self.assertTrue(open_file.call_args.args[1] & nonblock_flag)
            close_file.assert_called_once_with(fake_descriptor)
            fdopen.assert_not_called()

    def test_validate_rejects_numeric_privacy_values(self) -> None:
        with mock.patch.object(support_bundle, "_host", return_value=self.host()):
            bundle = support_bundle.collect(self.query)
        privacy_flags = ("raw_receipts", "argv", "paths", "pids", "model_data")
        substitutions = [
            (name, value)
            for name in privacy_flags + ("network",)
            for value in (0, 0.0)
        ]
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "bundle.json"
            for name, value in substitutions:
                with self.subTest(name=name, value=value):
                    invalid = copy.deepcopy(bundle)
                    invalid["privacy"][name] = value
                    path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaises(JsonInputError):
                        support_bundle.validate_bundle(path)

    def test_validate_rejects_injected_fields_duplicate_keys_bad_types_and_unbounded_json(self) -> None:
        with mock.patch.object(support_bundle, "_host", return_value=self.host()):
            bundle = support_bundle.collect(self.query)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "must-not-echo-private-input.json"

            def rejected(content: str | bytes, *secrets: str) -> str:
                if isinstance(content, bytes):
                    path.write_bytes(content)
                else:
                    path.write_text(content, encoding="utf-8")
                errors = io.StringIO()
                with redirect_stderr(errors):
                    self.assertEqual(4, support_bundle.validate_main([str(path)]))
                self.assertNotIn(str(path), errors.getvalue())
                for secret in secrets:
                    self.assertNotIn(secret, errors.getvalue())
                return errors.getvalue()

            for field in ("argv", "path", "pid", "credential", "model_data"):
                injected = copy.deepcopy(bundle)
                injected[field] = "SENTINEL-PRIVATE-VALUE"
                rejected(json.dumps(injected), field, "SENTINEL-PRIVATE-VALUE")

            raw_json = json.dumps(bundle)
            duplicate = raw_json.replace(
                '"schema_version":',
                '"schema_version":"attacker", "schema_version":',
                1,
            )
            rejected(duplicate, "attacker")

            wrong_type = copy.deepcopy(bundle)
            wrong_type["health"]["workload_uid"] = True
            rejected(json.dumps(wrong_type), "true")

            nonfinite = copy.deepcopy(bundle)
            nonfinite["health"]["discovery"]["last_scan_duration_ms"] = float("inf")
            rejected(json.dumps(nonfinite), "Infinity")

            rejected("[" * 40 + "0" + "]" * 40)
            rejected(b"x" * (support_bundle.MAX_VALIDATION_BYTES + 1))

    @unittest.skipUnless(os.name == "posix", "atomic directory fsync is native-Linux behavior")
    def test_write_requires_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "support.json"
            with mock.patch.object(support_bundle, "_host", return_value=self.host()):
                support_bundle.write_bundle(destination, self.query)
            with (
                self.assertRaises(JsonInputError),
                mock.patch.object(support_bundle, "_host", return_value=self.host()),
            ):
                support_bundle.write_bundle(destination, self.query)


if __name__ == "__main__":
    unittest.main()
