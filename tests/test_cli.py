from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lumi_eggcracker.cli import main


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(["version"]))
        self.assertEqual("0.7.0", output.getvalue().strip())

    def test_public_help_has_only_supported_commands(self) -> None:
        from lumi_eggcracker.cli import _parser
        help_text = _parser().format_help()
        for command in ("start", "kill", "status", "list", "approve", "revoke", "approvals", "detections", "doctor", "version"):
            self.assertIn(command, help_text)
        self.assertNotIn("_supervisor", help_text)
        self.assertNotIn("network" + "-deny", help_text)

    def test_internal_supervisor_dispatch_remains_available(self) -> None:
        with patch("lumi_eggcracker.cli.supervisor_main", return_value=7) as supervisor:
            self.assertEqual(main(["_supervisor", "--policy", "/tmp/policy.json"]), 7)
        supervisor.assert_called_once_with(["--policy", "/tmp/policy.json"])

    def test_approve_forwards_only_exact_command_arguments(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=0, create=True), patch("lumi_eggcracker.cli.request", return_value={"result": "APPROVED"}) as request:
            self.assertEqual(0, main(["approve", "--name", "qwen", "--uid", "1001", "--", "/opt/llama-cli", "-m", "/models/qwen.gguf"]))
        request.assert_called_once_with("approve", name="qwen", uid=1001, argv=["/opt/llama-cli", "-m", "/models/qwen.gguf"])

    def test_start_includes_resource_limits(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(0, main(["start", "--name", "demo", "--max-pids", "8", "--", "/bin/sleep", "1"]))
        request.assert_called_once_with(
            "start", name="demo", max_pids=8, max_memory_mib=2048,
            cpu_quota_percent=400, argv=["/bin/sleep", "1"],
        )
