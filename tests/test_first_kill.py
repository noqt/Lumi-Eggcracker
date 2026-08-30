from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TAG_COMMIT = "a" * 40
SPEC = importlib.util.spec_from_file_location("first_kill", ROOT / "scripts" / "first_kill.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load first-kill script")
first_kill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_kill)


class FirstKillTests(unittest.TestCase):
    def test_default_release_identity_is_the_1_0_candidate(self) -> None:
        self.assertEqual("v1.0.0", first_kill.DEFAULT_TAG)

    def test_preflight_exits_before_every_mutating_or_network_step(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester") as operator,
            mock.patch.object(first_kill, "compatibility") as compatibility,
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill,
                "local_release_identity",
                return_value=TAG_COMMIT,
            ),
            mock.patch.object(first_kill, "prepare_workspace") as prepare_workspace,
            mock.patch.object(first_kill, "release_files") as release_files,
            mock.patch.object(first_kill, "verify_tag") as verify_tag,
            mock.patch.object(first_kill, "install_release") as install_release,
            mock.patch.object(first_kill, "run_real_smoke") as run_real_smoke,
            mock.patch.object(first_kill.tempfile, "mkdtemp") as make_temporary,
            contextlib.redirect_stdout(output),
        ):
            result = first_kill.main(["--operator", "tester", "--preflight-only"])

        self.assertEqual(0, result)
        operator.assert_called_once_with("tester")
        compatibility.assert_called_once_with("tester")
        for forbidden in (
            prepare_workspace,
            release_files,
            verify_tag,
            install_release,
            run_real_smoke,
            make_temporary,
        ):
            forbidden.assert_not_called()
        summary = json.loads(output.getvalue())
        self.assertEqual("PREFLIGHT_PASSED", summary["result"])
        self.assertEqual(TAG_COMMIT, summary["tag_commit"])
        self.assertNotIn("qualified_commit", summary)
        self.assertFalse(summary["changes_made"])
        self.assertNotIn("/checkout", output.getvalue())

    def test_normal_run_still_requires_download_acceptance(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--operator", "tester"])
        self.assertEqual(2, raised.exception.code)

    def test_preflight_rejects_mutation_only_flags(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--preflight-only", "--keep"])
        self.assertEqual(2, raised.exception.code)

    def test_preflight_error_redacts_sudo_user_identity(self) -> None:
        canary = "operator-identity-must-not-appear"
        errors = io.StringIO()
        passwd = mock.Mock()
        passwd.getpwnam.side_effect = KeyError(canary)
        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.dict(os.environ, {"SUDO_USER": canary}),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(["--preflight-only"])
        self.assertEqual(2, result)
        self.assertNotIn(canary, errors.getvalue())
        self.assertIn("operator account does not exist", errors.getvalue())

    def test_local_release_identity_requires_annotated_tag(self) -> None:
        annotated = mock.Mock(returncode=0, stdout="tag\n")
        resolved = mock.Mock(returncode=0, stdout=f"{TAG_COMMIT}\n")
        with mock.patch.object(first_kill, "run", side_effect=[annotated, resolved]):
            result = first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)
        self.assertEqual(TAG_COMMIT, result)

    def test_local_release_identity_rejects_non_commit_output(self) -> None:
        annotated = mock.Mock(returncode=0, stdout="tag\n")
        malformed = mock.Mock(returncode=0, stdout="not-a-commit\n")
        with (
            mock.patch.object(first_kill, "run", side_effect=[annotated, malformed]),
            self.assertRaisesRegex(first_kill.FirstKillError, "does not resolve"),
        ):
            first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)

    def test_local_release_identity_rejects_lightweight_tag(self) -> None:
        lightweight = mock.Mock(returncode=0, stdout="commit\n")
        resolved = mock.Mock(returncode=0, stdout=f"{TAG_COMMIT}\n")
        with (
            mock.patch.object(first_kill, "run", side_effect=[lightweight, resolved]),
            self.assertRaisesRegex(first_kill.FirstKillError, "not an annotated tag"),
        ):
            first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)

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
