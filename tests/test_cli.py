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
        self.assertEqual("0.1.2", output.getvalue().strip())

    def test_public_help_has_only_supported_commands(self) -> None:
        from lumi_eggcracker.cli import _parser
        help_text = _parser().format_help()
        for command in ("start", "kill", "status", "list", "doctor", "version"):
            self.assertIn(command, help_text)
        self.assertNotIn("_supervisor", help_text)
        self.assertNotIn("network" + "-deny", help_text)

    def test_internal_supervisor_dispatch_remains_available(self) -> None:
        with patch("lumi_eggcracker.cli.supervisor_main", return_value=7) as supervisor:
            self.assertEqual(main(["_supervisor", "--policy", "/tmp/policy.json"]), 7)
        supervisor.assert_called_once_with(["--policy", "/tmp/policy.json"])
