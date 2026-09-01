from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from lumi_eggcracker.cli import main


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(["version"]))
        self.assertEqual("1.0.8", output.getvalue().strip())

    def test_public_help_has_only_supported_commands(self) -> None:
        from lumi_eggcracker.cli import _parser
        help_text = _parser().format_help()
        for command in ("start", "kill", "status", "list", "approve", "revoke", "approvals", "detections", "doctor", "version"):
            self.assertIn(command, help_text)
        self.assertIn("exec-policy", help_text)
        self.assertNotIn("_supervisor", help_text)
        self.assertNotIn("network" + "-deny", help_text)

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
            argv=["/opt/llama-cli", "-m", "/models/qwen.gguf"],
        )

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
