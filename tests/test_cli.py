from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.cli import main


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(["version"]))
        self.assertEqual("1.0.10", output.getvalue().strip())

    def test_public_help_has_only_supported_commands(self) -> None:
        from lumi_eggcracker.cli import _parser
        help_text = _parser().format_help()
        for command in (
            "start",
            "kill",
            "status",
            "list",
            "approve",
            "revoke",
            "approvals",
            "detections",
            "doctor",
            "support-bundle",
            "validate-support-bundle",
            "compare-detection-receipts",
            "version",
        ):
            self.assertIn(command, help_text)
        self.assertIn("exec-policy", help_text)
        self.assertNotIn("_supervisor", help_text)
        self.assertNotIn("network" + "-deny", help_text)

    def test_compare_detection_receipts_help_uses_installed_command(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["compare-detection-receipts", "--help"])
        self.assertEqual(0, raised.exception.code)
        self.assertIn("usage: eggcracker compare-detection-receipts", output.getvalue())
        self.assertIn("--before FILE", output.getvalue())
        self.assertIn("--after FILE", output.getvalue())

    def test_compare_detection_receipts_forwards_arguments_before_connected_commands(
        self,
    ) -> None:
        forwarded = [
            "--before",
            "before-export.json",
            "--after",
            "after-export.json",
            "--output",
            "comparison.json",
        ]
        with (
            patch(
                "lumi_eggcracker.cli.compare_detection_receipts_main", return_value=0
            ) as compare,
            patch("lumi_eggcracker.cli.request") as request,
            patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
            patch("lumi_eggcracker.cli.gate_main") as gate,
            patch("lumi_eggcracker.cli.watchdog_main") as watchdog,
        ):
            self.assertEqual(0, main(["compare-detection-receipts", *forwarded]))
        compare.assert_called_once_with(
            forwarded, prog="eggcracker compare-detection-receipts"
        )
        request.assert_not_called()
        supervisor.assert_not_called()
        gate.assert_not_called()
        watchdog.assert_not_called()

    def test_compare_detection_receipts_success_and_existing_output_refusal(self) -> None:
        def synthetic_export(event_id: str) -> dict[str, object]:
            return {
                "export_schema": "lumi-eggcracker.redacted-detection-receipt-export.v1",
                "source_sha256": "f" * 64,
                "authentication": "NOT_AUTHENTICATED",
                "live_verification": "NOT_PERFORMED",
                "receipt": {
                    "schema_version": "lumi-eggcracker.detection-receipt.v2",
                    "event_id": event_id,
                    "source_commit": "a" * 40,
                    "version": "1.0.10",
                    "catalogue_sha256": "b" * 64,
                    "receipt_written_utc": "2026-10-02T00:00:00Z",
                    "detector": {
                        "profile": "content.gguf-llama",
                        "detection_path": "CONTENT",
                        "catalogue_schema": "lumi-eggcracker.detectors.v3",
                    },
                    "trigger": {"kind": "UNAPPROVED_AI_MATCH"},
                    "recorded_result": "CONTAINMENT_FAILED",
                },
            }

        with tempfile.TemporaryDirectory(prefix="cli-receipt-comparison-") as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(synthetic_export("0" * 24)), encoding="utf-8")
            after.write_text(json.dumps(synthetic_export("1" * 24)), encoding="utf-8")
            output = root / "existing-comparison.json"
            original_output = b"preserve this synthetic report\n"
            output.write_bytes(original_output)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch("lumi_eggcracker.cli.request") as request,
                patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(
                    0,
                    main(
                        [
                            "compare-detection-receipts",
                            "--before",
                            str(before),
                            "--after",
                            str(after),
                        ]
                    ),
                )
                comparison = json.loads(stdout.getvalue())
                self.assertEqual("RECORDED", comparison["comparison_status"])
                self.assertEqual("", stderr.getvalue())
                stdout.seek(0)
                stdout.truncate(0)
                stderr.seek(0)
                stderr.truncate(0)
                self.assertEqual(
                    1,
                    main(
                        [
                            "compare-detection-receipts",
                            "--before",
                            str(before),
                            "--after",
                            str(after),
                            "--output",
                            str(output),
                        ]
                    ),
                )
                self.assertEqual("", stdout.getvalue())
                self.assertIn("OUTPUT_ALREADY_EXISTS", stderr.getvalue())
                request.assert_not_called()
                supervisor.assert_not_called()
            self.assertEqual(original_output, output.read_bytes())

    def test_validate_support_bundle_dispatches_before_connected_commands(self) -> None:
        with (
            patch("lumi_eggcracker.cli.validate_support_bundle_main", return_value=0) as validate,
            patch("lumi_eggcracker.cli.request") as request,
            patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
            patch("lumi_eggcracker.cli.gate_main") as gate,
            patch("lumi_eggcracker.cli.watchdog_main") as watchdog,
        ):
            self.assertEqual(
                0,
                main(["validate-support-bundle", "private-name-must-not-be-echoed.json"]),
            )
        validate.assert_called_once_with(["private-name-must-not-be-echoed.json"])
        request.assert_not_called()
        supervisor.assert_not_called()
        gate.assert_not_called()
        watchdog.assert_not_called()

    def test_internal_supervisor_dispatch_remains_available(self) -> None:
        with patch("lumi_eggcracker.cli.supervisor_main", return_value=7) as supervisor:
            self.assertEqual(main(["_supervisor", "--policy", "/tmp/policy.json"]), 7)
        supervisor.assert_called_once_with(["--policy", "/tmp/policy.json"])

    def test_approve_forwards_only_exact_command_arguments(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=0, create=True), patch("lumi_eggcracker.cli.request", return_value={"result": "APPROVED"}) as request:
            self.assertEqual(0, main(["approve", "--name", "qwen", "--uid", "1001", "--", "/opt/llama-cli", "-m", "/models/qwen.gguf"]))
        request.assert_called_once_with(
            "approve",
            name="qwen",
            uid=1001,
            max_pids=64,
            max_memory_mib=2048,
            cpu_quota_percent=400,
            allow_interface_discovery=False,
            argv=["/opt/llama-cli", "-m", "/models/qwen.gguf"],
        )

    def test_approve_can_grant_interface_discovery(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=0, create=True), patch("lumi_eggcracker.cli.request", return_value={"result": "APPROVED"}) as request:
            self.assertEqual(0, main(["approve", "--name", "qwen", "--uid", "1001", "--allow-interface-discovery", "--", "/opt/llama-cli", "-m", "/models/qwen.gguf"]))
        self.assertTrue(request.call_args.kwargs["allow_interface_discovery"])

    def test_start_includes_resource_limits(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(0, main(["start", "--name", "demo", "--max-pids", "8", "--", "/bin/sleep", "1"]))
        request.assert_called_once_with(
            "start", name="demo", max_pids=8, max_memory_mib=2048,
            cpu_quota_percent=400, argv=["/bin/sleep", "1"],
        )

    def test_start_forwards_selected_execution_policy(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(0, main(["start", "--name", "demo", "--exec-policy", "a" * 24, "--max-pids", "8", "--", "/bin/sleep", "1"]))
        request.assert_called_once_with(
            "start", name="demo", max_pids=8, max_memory_mib=2048,
            cpu_quota_percent=400, argv=["/bin/sleep", "1"], exec_policy="a" * 24,
        )

    def test_start_can_require_exact_approval_at_admission_time(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(
                0,
                main(
                    [
                        "start",
                        "--name",
                        "demo",
                        "--max-pids",
                        "8",
                        "--require-approval",
                        "--",
                        "/bin/sleep",
                        "1",
                    ]
                ),
            )
        request.assert_called_once_with(
            "start",
            name="demo",
            max_pids=8,
            max_memory_mib=2048,
            cpu_quota_percent=400,
            argv=["/bin/sleep", "1"],
            require_approval=True,
        )

    def test_execution_policy_create_requires_root(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=1001, create=True):
            self.assertEqual(4, main(["exec-policy", "create", "--name", "demo", "--", "/bin/sh"]))

    def test_duplicate_identifier_options_are_rejected_before_request(self) -> None:
        policy_a = "a" * 24
        policy_b = "b" * 24
        cases = (
            ["start", "--name", "first", "--name", "second", "--max-pids", "8", "--", "/bin/true"],
            ["start", "--name", "demo", "--exec-policy", policy_a, "--exec-policy", policy_b, "--max-pids", "8", "--", "/bin/true"],
            ["kill", "--name", "first", "--name", "second", "--receipt", "/tmp/receipt.json"],
            ["status", "--name", "first", "--name", "second"],
            ["approve", "--name", "first", "--name", "second", "--uid", "1001", "--", "/bin/true"],
            ["revoke", "--name", "first", "--name", "second"],
            ["exec-policy", "create", "--name", "first", "--name", "second", "--", "/bin/true"],
            ["exec-policy", "revoke", "--policy-id", policy_a, "--policy-id", policy_b],
        )
        for values in cases:
            with self.subTest(values=values), patch(
                "lumi_eggcracker.cli.request"
            ) as request, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(values)
                self.assertEqual(2, raised.exception.code)
                request.assert_not_called()
