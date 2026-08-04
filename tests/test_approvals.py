from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from lumi_eggcracker.approvals import approved, create, load_all, revoke
from lumi_eggcracker.discovery import argv_digest, executable_digest


@dataclass(frozen=True)
class Sample:
    uid: int
    exe_path: str
    argv: tuple[str, ...]


class ApprovalTests(unittest.TestCase):
    def test_exact_approval_matches_only_exact_uid_and_argv(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"; binary = Path(raw) / "runner"
            binary.write_bytes(b"#!/bin/true\n")
            binary.chmod(0o755)
            record = create(root, name="qwen", uid=1001, argv=[str(binary), "-m", "/models/qwen.gguf"], administrator_uid=0)
            values = load_all(root)
            sample = Sample(1001, str(binary), (str(binary), "-m", "/models/qwen.gguf"))
            self.assertTrue(approved(sample, executable_digest(binary), values))
            self.assertFalse(approved(Sample(1002, str(binary), sample.argv), executable_digest(binary), values))
            self.assertFalse(approved(Sample(1001, str(binary), (str(binary), "-m", "/models/other.gguf")), executable_digest(binary), values))
            self.assertNotIn("/models/qwen.gguf", record.values())
            self.assertEqual(argv_digest(sample.argv), record["argv_sha256"])

    def test_revoke_removes_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"; binary = Path(raw) / "runner"
            binary.write_bytes(b"x"); binary.chmod(0o755)
            create(root, name="qwen", uid=1001, argv=[str(binary)], administrator_uid=0)
            self.assertEqual("REVOKED", revoke(root, "qwen")["result"])
            self.assertEqual([], load_all(root))
