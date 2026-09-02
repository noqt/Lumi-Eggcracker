from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
import warnings
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
        self.assertEqual("v1.0.10", first_kill.DEFAULT_TAG)

    def test_preflight_requires_every_fixed_installer_command(self) -> None:
        missing = "/usr/sbin/nft"

        def present(path: Path) -> bool:
            return str(path) != missing

        with (
            mock.patch.object(first_kill.Path, "is_file", autospec=True, side_effect=present),
            mock.patch.object(first_kill.os, "access", return_value=True),
            self.assertRaisesRegex(first_kill.FirstKillError, missing),
        ):
            first_kill.require_host_commands()

        for required in ("/usr/sbin/ip", "/usr/sbin/nft", "/usr/bin/nsenter"):
            self.assertIn(required, first_kill.REQUIRED_HOST_COMMANDS)

    def test_preflight_rejects_residual_workload_identity(self) -> None:
        passwd = mock.Mock()
        group = mock.Mock()
        passwd.getpwnam.return_value = object()

        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.object(first_kill, "grp", group),
            self.assertRaisesRegex(first_kill.FirstKillError, "workload account"),
        ):
            first_kill.require_clean_workload_identity()

        passwd.getpwnam.side_effect = KeyError(first_kill.WORKLOAD_USER)
        group.getgrnam.return_value = object()
        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.object(first_kill, "grp", group),
            self.assertRaisesRegex(first_kill.FirstKillError, "workload group"),
        ):
            first_kill.require_clean_workload_identity()

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
            mock.patch.object(
                first_kill, "verify_checksum_signature"
            ) as verify_checksum_signature,
            mock.patch.object(first_kill, "verify_bundle_checksum") as verify_bundle_checksum,
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
            verify_checksum_signature,
            verify_bundle_checksum,
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

    def test_normal_run_authenticates_checksums_before_extraction_or_install(self) -> None:
        events: list[str] = []
        release = {
            "artifact": "lumi-eggcracker-1.0.0.pyz",
            "sha256": "a" * 64,
            "source_archive": "lumi-eggcracker-1.0.0-source.zip",
            "source_commit": TAG_COMMIT,
            "version": "1.0.0",
        }
        receipt = {
            "result": "TERMINATED",
            "containment": {"surviving_pids": [], "root_populated": 0},
        }
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester"),
            mock.patch.object(first_kill, "compatibility"),
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill, "prepare_workspace", return_value=Path("/private-workspace")
            ),
            mock.patch.object(
                first_kill,
                "release_files",
                return_value=(
                    Path("/bundle.zip"),
                    Path("/key.asc"),
                    Path("/SHA256SUMS"),
                    Path("/SHA256SUMS.asc"),
                ),
            ),
            mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT),
            mock.patch.object(
                first_kill,
                "verify_checksum_signature",
                side_effect=lambda *_: events.append("signature"),
            ),
            mock.patch.object(
                first_kill,
                "verify_bundle_checksum",
                side_effect=lambda *_: events.append("checksum"),
            ),
            mock.patch.object(
                first_kill,
                "extracted_release",
                side_effect=lambda *_: events.append("extract") or Path("/release"),
            ),
            mock.patch.object(first_kill, "manifest", return_value=release),
            mock.patch.object(first_kill, "run"),
            mock.patch.object(
                first_kill,
                "install_release",
                side_effect=lambda *_: events.append("install"),
            ),
            mock.patch.object(
                first_kill, "installed_workload_user", return_value="workload"
            ),
            mock.patch.object(first_kill, "run_real_smoke", return_value=receipt),
            mock.patch.object(first_kill, "remove_installation"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = first_kill.main(
                [
                    "--operator",
                    "tester",
                    "--workspace",
                    "/private-workspace",
                    "--accept-third-party-downloads",
                    "--remove",
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(["signature", "checksum", "extract", "install"], events)

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

    def test_checksums_reject_non_hex_and_duplicate_names(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "SHA256SUMS"
            path.write_text("z" * 64 + "  payload.zip\n", encoding="ascii")
            with self.assertRaisesRegex(first_kill.FirstKillError, "invalid line"):
                first_kill.parse_checksums(path)
            path.write_text(
                "a" * 64 + "  payload.zip\n" + "b" * 64 + "  payload.zip\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(first_kill.FirstKillError, "duplicate"):
                first_kill.parse_checksums(path)

    def test_safe_extract_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../outside.txt", "no")
            with self.assertRaisesRegex(first_kill.FirstKillError, "unsafe path"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_noncanonical_components(self) -> None:
        for member_name in ("release/./install.py", "release//install.py"):
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                archive = root / "noncanonical.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(member_name, "untrusted")
                with self.assertRaisesRegex(first_kill.FirstKillError, "unsafe path"):
                    first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr("release/install.py", "trusted")
                    bundle.writestr("release/install.py", "hostile")
            with self.assertRaisesRegex(first_kill.FirstKillError, "duplicate path"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_symlink_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "link.zip"
            member = zipfile.ZipInfo("release/install.py")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(member, "../../outside")
            with self.assertRaisesRegex(first_kill.FirstKillError, "link or special"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_trailing_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "appended.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("release/install.py", "trusted")
            with archive.open("ab") as handle:
                handle.write(b"DAYBREAK-TRAILING-DATA")
            with self.assertRaisesRegex(first_kill.FirstKillError, "trailing data"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_prepended_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            original = root / "original.zip"
            archive = root / "prepended.zip"
            with zipfile.ZipFile(original, "w") as bundle:
                bundle.writestr("release/install.py", "trusted")
            archive.write_bytes(b"DAYBREAK-PREFIX" + original.read_bytes())
            with self.assertRaisesRegex(first_kill.FirstKillError, "prepended"):
                first_kill.safe_extract(archive, root / "out")

    def test_checksum_signature_requires_valid_pinned_key_signature(self) -> None:
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
            ),
            stderr="",
        )
        verified = mock.Mock(
            returncode=0,
            stdout=(
                "[GNUPG:] VALIDSIG "
                f"{first_kill.RELEASE_KEY_FINGERPRINT} 2026 0 0 4 0 1 10 00 "
                f"{first_kill.RELEASE_KEY_FINGERPRINT}\n"
            ),
            stderr="",
        )
        with mock.patch.object(first_kill, "run", side_effect=[imported, shown, verified]) as run:
            first_kill.verify_checksum_signature(
                Path("/release-key.asc"),
                Path("/SHA256SUMS"),
                Path("/SHA256SUMS.asc"),
            )
        self.assertIn("--verify", run.call_args_list[-1].args[0])

    def test_checksum_signature_failure_is_fatal(self) -> None:
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
            ),
            stderr="",
        )
        rejected = mock.Mock(returncode=1, stdout="", stderr="BAD signature")
        with (
            mock.patch.object(first_kill, "run", side_effect=[imported, shown, rejected]),
            self.assertRaisesRegex(first_kill.FirstKillError, "signature verification failed"),
        ):
            first_kill.verify_checksum_signature(
                Path("/release-key.asc"),
                Path("/SHA256SUMS"),
                Path("/SHA256SUMS.asc"),
            )

    def test_release_key_bundle_cannot_add_an_attacker_primary_key(self) -> None:
        attacker = "B" * 40
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
                "pub:::::::::\n"
                f"fpr:::::::::{attacker}:\n"
            ),
            stderr="",
        )
        with (
            mock.patch.object(first_kill, "run", side_effect=[imported, shown]),
            self.assertRaisesRegex(first_kill.FirstKillError, "exactly the published"),
        ):
            first_kill.import_release_key(Path("/gpg-home"), Path("/release-key.asc"))

    def test_public_key_fingerprint_is_pinned(self) -> None:
        self.assertEqual(40, len(first_kill.RELEASE_KEY_FINGERPRINT))
        self.assertEqual(first_kill.RELEASE_KEY_FINGERPRINT.upper(), first_kill.RELEASE_KEY_FINGERPRINT)


if __name__ == "__main__":
    unittest.main()
