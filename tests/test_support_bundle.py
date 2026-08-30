from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
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
                        "event_id": "abc123",
                        "result": "TERMINATED",
                        "trigger": "UNAPPROVED_AI",
                        "version": "0.6.0",
                        "detector": {"profile": "content.gguf-llama", "path": "/private/model.gguf"},
                        "argv": ["--secret"],
                    }
                ]
            }
        if action == "list":
            return {"runs": [{"name": "private-name", "state": "TERMINATED", "unit": "/private"}]}
        if action == "incidents":
            return {"incidents": []}
        raise AssertionError(action)

    def test_collect_is_redacted_and_bounded(self) -> None:
        value = support_bundle.collect(self.query)
        text = str(value)
        self.assertNotIn("/private", text)
        self.assertNotIn("--secret", text)
        self.assertEqual(1, len(value["receipts"]))
        self.assertEqual({"TERMINATED": 1}, value["workloads"]["states"])
        self.assertFalse(value["privacy"]["raw_receipts"])

    @unittest.skipUnless(os.name == "posix", "atomic directory fsync is native-Linux behavior")
    def test_write_requires_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "support.json"
            support_bundle.write_bundle(destination, self.query)
            with self.assertRaises(JsonInputError):
                support_bundle.write_bundle(destination, self.query)


if __name__ == "__main__":
    unittest.main()
