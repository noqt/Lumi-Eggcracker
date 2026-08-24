from __future__ import annotations

import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("first_kill", ROOT / "scripts" / "first_kill.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load first-kill script")
first_kill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_kill)


class FirstKillTests(unittest.TestCase):
    def test_receipt_summary_is_bounded_and_redacts_paths(self) -> None:
        value = first_kill.receipt_summary(
            {
                "result": "TERMINATED",
                "detector": {"profile": "content.gguf-llama", "trigger": "UNAPPROVED"},
                "trigger": {"kind": "UNAPPROVED_AI_MATCH"},
                "capture": {"captured_processes": 2},
                "containment": {
                    "primitive": "pidfd-stop+cgroup.kill",
                    "root_populated": 0,
                    "surviving_pids": [],
                    "trigger_to_empty_ms": 42.5,
                    "local_path": "/tmp/private-model.gguf",
                },
            }
        )
        self.assertEqual("TERMINATED", value["result"])
        self.assertEqual("content.gguf-llama", value["profile"])
        self.assertEqual("UNAPPROVED_AI_MATCH", value["trigger"])
        self.assertEqual(2, value["captured_processes"])
        self.assertEqual(0, value["root_populated"])
        self.assertEqual(42.5, value["trigger_to_empty_ms"])
        self.assertNotIn("local_path", value)
        self.assertNotIn("private-model", str(value))

    def test_checksums_parse_only_sha256_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "SHA256SUMS"
            path.write_text("a" * 64 + "  payload.zip\n", encoding="ascii")
            self.assertEqual({"payload.zip": "a" * 64}, first_kill.parse_checksums(path))

    def test_safe_extract_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../outside.txt", "no")
            with self.assertRaisesRegex(first_kill.FirstKillError, "unsafe path"):
                first_kill.safe_extract(archive, root / "out")

    def test_public_key_fingerprint_is_pinned(self) -> None:
        self.assertEqual(40, len(first_kill.RELEASE_KEY_FINGERPRINT))
        self.assertEqual(first_kill.RELEASE_KEY_FINGERPRINT.upper(), first_kill.RELEASE_KEY_FINGERPRINT)


if __name__ == "__main__":
    unittest.main()
