from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.approvals import create, load_all, match_launch, revoke
from lumi_eggcracker.discovery import argv_digest


class ApprovalTests(unittest.TestCase):
    def test_exact_approval_matches_only_trusted_preexec_uid_and_argv(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"; binary = Path(raw) / "runner"
            binary.write_bytes(b"#!/bin/true\n")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
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
            root = Path(raw) / "approvals"; binary = Path(raw) / "runner"
            binary.write_bytes(b"x"); binary.chmod(0o755)
            create(root, name="qwen", uid=1001, argv=[str(binary)], administrator_uid=0)
            self.assertEqual("REVOKED", revoke(root, "qwen")["result"])
            self.assertEqual([], load_all(root))
