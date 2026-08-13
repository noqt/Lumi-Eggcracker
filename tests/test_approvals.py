from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.approvals import create, load_all, match_launch, revoke, stage_launch
from lumi_eggcracker.discovery import argv_digest
from lumi_eggcracker.jsonio import JsonInputError


class ApprovalTests(unittest.TestCase):
    def test_exact_approval_matches_only_trusted_preexec_uid_and_argv(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"#!/bin/true\n")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
            with patch(
                "lumi_eggcracker.approvals._classify",
                return_value=("NATIVE_LLAMA", []),
            ):
                record = create(
                    root,
                    name="qwen",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                )
            values = load_all(root)
            self.assertEqual(record, match_launch(uid=1001, argv=argv, approvals=values))
            self.assertIsNone(match_launch(uid=1002, argv=argv, approvals=values))
            self.assertIsNone(
                match_launch(
                    uid=1001,
                    argv=[str(binary), "-m", "/models/other.gguf"],
                    approvals=values,
                )
            )
            self.assertNotIn("/models/qwen.gguf", record.values())
            self.assertEqual(argv_digest(argv), record["argv_sha256"])

    def test_revoke_removes_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"x")
            binary.chmod(0o755)
            with patch(
                "lumi_eggcracker.approvals._classify",
                return_value=("NATIVE_LLAMA", []),
            ):
                create(
                    root,
                    name="qwen",
                    uid=1001,
                    argv=[str(binary)],
                    administrator_uid=0,
                )
            self.assertEqual("REVOKED", revoke(root, "qwen")["result"])
            self.assertEqual([], load_all(root))

    def test_python_script_is_staged_from_bound_bytes_and_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            approvals = base / "approvals"
            executable = base / "python3"
            executable.write_bytes(b"python-runtime")
            executable.chmod(0o555)
            script = base / "worker.py"
            script.write_text("print('approved')\n", encoding="utf-8")
            argv = [str(executable), str(script), "safe-mode"]
            with (
                patch("lumi_eggcracker.approvals.inspect_path", return_value=None),
                patch("lumi_eggcracker.approvals._is_cpython", return_value=True),
            ):
                record = create(
                    approvals,
                    name="python-safe",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                )
            self.assertEqual("PYTHON_SCRIPT", record["launch_kind"])
            self.assertEqual(1, len(record["bound_inputs"]))

            stage_root = base / "staged"
            stage_root.mkdir()
            effective = stage_launch(record, argv, stage_root / ("a" * 24))
            self.assertNotEqual(argv[1], effective[1])
            self.assertEqual(script.read_bytes(), Path(effective[1]).read_bytes())

            script.write_text("print('hostile')\n", encoding="utf-8")
            with self.assertRaises(JsonInputError):
                stage_launch(record, argv, stage_root / ("b" * 24))

    def test_python_module_and_command_forms_are_not_approvable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            executable = base / "python3"
            executable.write_bytes(b"python-runtime")
            executable.chmod(0o555)
            for index, suffix in enumerate((["-m", "module"], ["-c", "print(1)"])):
                with (
                    patch("lumi_eggcracker.approvals.inspect_path", return_value=None),
                    patch("lumi_eggcracker.approvals._is_cpython", return_value=True),
                    self.assertRaises(JsonInputError),
                ):
                    create(
                        base / "approvals",
                        name=f"python-unsupported-{index}",
                        uid=1001,
                        argv=[str(executable), *suffix],
                        administrator_uid=0,
                    )
