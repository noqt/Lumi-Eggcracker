from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "collect_supported_path_receipt.py"
SCHEMA = json.loads(
    (ROOT / "schemas" / "supported-path-receipt-v1.schema.json").read_text(encoding="utf-8")
)

spec = importlib.util.spec_from_file_location("collect_supported_path_receipt", SCRIPT)
if spec is None or spec.loader is None:
    raise AssertionError("supported-path receipt collector is not importable")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
SOURCE_COMMIT = "a" * 40
SOURCE_TREE_SHA256 = "b" * 64


def success_observed(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "outcome": "supported-success",
        "result": "TERMINATED",
        "target_survivors": 0,
        "canary_survived": True,
        "root_populated": 0,
        "cleanup_complete": True,
        "source_commit": SOURCE_COMMIT,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    value.update(updates)
    return value


def blocker_observed(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "outcome": "reproducible-blocker",
        "blocker_stage": "host-preflight",
        "blocker_code": "CGROUP_V2_REQUIRED",
        "source_commit": SOURCE_COMMIT,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    value.update(updates)
    return value


def submission(*, quote: bool, observed: dict[str, object]) -> dict[str, object]:
    return {
        "supported_environment": collector.SUPPORTED_ENVIRONMENT,
        "supported_path": collector.SUPPORTED_PATH,
        "exact_command": collector.EXACT_COMMAND,
        "expected_result": collector.EXPECTED_RESULT,
        "observed_result": observed,
        "permission_to_quote": quote,
    }


class SupportedPathReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        validator_class = validator_for(SCHEMA)
        validator_class.check_schema(SCHEMA)
        cls.validator = validator_class(SCHEMA)

    def run_collector(
        self, directory: str, value: object, *, opt_in: bool = True
    ) -> tuple[int, StringIO, StringIO, Path]:
        source = Path(directory) / "input.json"
        output = Path(directory) / "receipt.json"
        source.write_text(json.dumps(value), encoding="utf-8")
        arguments = ["--input", str(source), "--output", str(output)]
        if opt_in:
            arguments.insert(0, "--i-opt-in-to-write-local-receipt")
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = collector.main(arguments)
        return status, stdout, stderr, output

    def test_supported_success_writes_closed_redacted_receipt(self) -> None:
        with TemporaryDirectory() as directory:
            status, stdout, stderr, output = self.run_collector(
                directory,
                submission(quote=True, observed=success_observed()),
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, status)
        self.assertEqual("WROTE local redacted supported-path receipt\n", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())
        self.validator.validate(receipt)
        self.assertTrue(receipt["permission_to_quote"])
        self.assertEqual(collector.EXACT_COMMAND, receipt["exact_command"])
        self.assertEqual(success_observed(), receipt["observed_result"])

    def test_collector_has_only_local_standard_library_dependencies(self) -> None:
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported_roots = {
            name.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for name in node.names
        }
        imported_roots.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertEqual(
            {
                "__future__",
                "argparse",
                "collections",
                "datetime",
                "json",
                "hashlib",
                "os",
                "pathlib",
                "re",
                "secrets",
                "stat",
                "sys",
            },
            imported_roots,
        )

    def test_reproducible_blocker_and_quote_refusal_are_recorded(self) -> None:
        observed = blocker_observed()
        with TemporaryDirectory() as directory:
            status, _stdout, _stderr, output = self.run_collector(
                directory, submission(quote=False, observed=observed)
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(0, status)
        self.validator.validate(receipt)
        self.assertFalse(receipt["permission_to_quote"])
        self.assertEqual(observed, receipt["observed_result"])

    def test_explicit_opt_in_is_required_before_input_is_read(self) -> None:
        private_marker = "private-input-marker"
        with TemporaryDirectory() as directory:
            status, stdout, stderr, output = self.run_collector(
                directory, {"private": private_marker}, opt_in=False
            )
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("explicit opt-in is required", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertFalse(output.exists())

    def test_permission_to_quote_must_be_an_explicit_boolean(self) -> None:
        value = submission(quote=False, observed=success_observed())
        value["permission_to_quote"] = "yes"
        with TemporaryDirectory() as directory:
            status, _stdout, stderr, output = self.run_collector(directory, value)
        self.assertEqual(2, status)
        self.assertIn("explicit boolean", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_private_or_unknown_fields_are_rejected_without_echoing_values(self) -> None:
        private_marker = "do-not-echo-private-value"
        value = submission(quote=False, observed=success_observed())
        value["email"] = private_marker
        with TemporaryDirectory() as directory:
            status, stdout, stderr, output = self.run_collector(directory, value)
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("closed schema", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertFalse(output.exists())

    def test_arbitrary_command_is_rejected_without_echoing_it(self) -> None:
        private_marker = "--token=do-not-echo"
        value = submission(quote=False, observed=success_observed())
        value["exact_command"] = f"{collector.EXACT_COMMAND} {private_marker}"
        with TemporaryDirectory() as directory:
            status, _stdout, stderr, output = self.run_collector(directory, value)
        self.assertEqual(2, status)
        self.assertIn("supported fixed value", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertFalse(output.exists())

    def test_invalid_utf8_is_rejected_without_echoing_contents(self) -> None:
        private_marker = "private-utf8-marker"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / "receipt.json"
            source.write_bytes(b"\xff" + private_marker.encode("ascii"))
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = collector.main(
                    [
                        "--i-opt-in-to-write-local-receipt",
                        "--input", str(source),
                        "--output", str(output),
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("bounded UTF-8 JSON", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertFalse(output.exists())

    def test_oversized_input_is_rejected_before_json_parsing(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / "receipt.json"
            source.write_bytes(b" " * (collector.MAX_INPUT_BYTES + 1))
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = collector.main(
                    [
                        "--i-opt-in-to-write-local-receipt",
                        "--input", str(source),
                        "--output", str(output),
                    ]
                )
        self.assertEqual(2, status)
        self.assertIn("safe size bound", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_existing_output_is_not_overwritten_and_path_is_not_echoed(self) -> None:
        private_marker = "private-output-name"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            output = Path(directory) / f"{private_marker}.json"
            source.write_text(
                json.dumps(submission(quote=False, observed=success_observed())),
                encoding="utf-8",
            )
            output.write_text("keep", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = collector.main(
                    [
                        "--i-opt-in-to-write-local-receipt",
                        "--input", str(source),
                        "--output", str(output),
                    ]
                )
            preserved = output.read_text(encoding="utf-8")
        self.assertEqual(2, status)
        self.assertEqual("keep", preserved)
        self.assertIn("refusing to overwrite", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_output_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            target = Path(directory) / "target.json"
            output = Path(directory) / "receipt.json"
            source.write_text(
                json.dumps(submission(quote=False, observed=success_observed())),
                encoding="utf-8",
            )
            target.write_text("keep", encoding="utf-8")
            try:
                output.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted")
            stderr = StringIO()
            with redirect_stderr(stderr):
                status = collector.main(
                    [
                        "--i-opt-in-to-write-local-receipt",
                        "--input", str(source),
                        "--output", str(output),
                    ]
                )
            preserved = target.read_text(encoding="utf-8")
        self.assertEqual(2, status)
        self.assertEqual("keep", preserved)
        self.assertIn("must not be a link", stderr.getvalue())

    def test_blocker_free_text_and_private_fields_are_not_collectable(self) -> None:
        private_marker = "private raw failure output"
        observed = blocker_observed(
            blocker_stage="probe-execution",
            blocker_code="COMMAND_FAILED",
            raw_output=private_marker,
        )
        with TemporaryDirectory() as directory:
            status, _stdout, stderr, output = self.run_collector(
                directory, submission(quote=False, observed=observed)
            )
        self.assertEqual(2, status)
        self.assertIn("closed schema", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertFalse(output.exists())

    def test_unhashable_blocker_stage_and_code_fail_closed(self) -> None:
        for field, invalid_value in (("blocker_stage", []), ("blocker_code", {})):
            with self.subTest(field=field), TemporaryDirectory() as directory:
                status, stdout, stderr, output = self.run_collector(
                    directory,
                    submission(
                        quote=False,
                        observed=blocker_observed(**{field: invalid_value}),
                    ),
                )
                self.assertEqual(2, status)
                self.assertEqual("", stdout.getvalue())
                self.assertTrue(stderr.getvalue().startswith("NOT WRITTEN:"))
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertNotIn(str(invalid_value), stderr.getvalue())
                self.assertFalse(output.exists())

    def test_success_and_blocker_require_complete_source_identity(self) -> None:
        cases = [success_observed(), blocker_observed()]
        for index, observed in enumerate(cases):
            observed.pop("source_tree_sha256")
            with self.subTest(outcome=observed["outcome"]), TemporaryDirectory() as directory:
                status, _stdout, stderr, output = self.run_collector(
                    directory, submission(quote=False, observed=observed)
                )
                self.assertEqual(2, status)
                self.assertIn("closed schema", stderr.getvalue())
                self.assertFalse(output.exists(), index)

    def test_invalid_source_identity_is_rejected_without_value_echo(self) -> None:
        private_marker = "NOT-A-PRIVATE-COMMIT-VALUE"
        cases = [
            success_observed(source_commit=private_marker),
            blocker_observed(source_tree_sha256=private_marker),
        ]
        for observed in cases:
            with self.subTest(outcome=observed["outcome"]), TemporaryDirectory() as directory:
                status, _stdout, stderr, output = self.run_collector(
                    directory, submission(quote=False, observed=observed)
                )
                self.assertEqual(2, status)
                self.assertIn("exact lowercase", stderr.getvalue())
                self.assertNotIn(private_marker, stderr.getvalue())
                self.assertFalse(output.exists())

    def test_false_or_nonzero_success_invariants_are_rejected(self) -> None:
        invalid_observations = {
            "result": "FAILED",
            "target_survivors": 1,
            "canary_survived": False,
            "root_populated": 1,
            "cleanup_complete": False,
        }
        for field, invalid_value in invalid_observations.items():
            with self.subTest(field=field), TemporaryDirectory() as directory:
                status, _stdout, stderr, output = self.run_collector(
                    directory,
                    submission(quote=False, observed=success_observed(**{field: invalid_value})),
                )
                self.assertEqual(2, status)
                self.assertIn("not the required value", stderr.getvalue())
                self.assertNotIn(str(invalid_value), stderr.getvalue())
                self.assertFalse(output.exists())

    def write_final_receipt(
        self,
        directory: str,
        *,
        observed: dict[str, object] | None = None,
        quote: bool = False,
        suffix: bytes = b"\n",
    ) -> tuple[Path, bytes]:
        receipt = collector._build_receipt(
            submission(quote=quote, observed=observed or success_observed())
        )
        encoded = (
            json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + suffix
        )
        path = Path(directory) / "final-receipt.json"
        path.write_bytes(encoded)
        return path, encoded

    def run_verifier(
        self,
        receipt: Path,
        *,
        source_commit: str = SOURCE_COMMIT,
        source_tree_sha256: str = SOURCE_TREE_SHA256,
        extra: list[str] | None = None,
    ) -> tuple[int, StringIO, StringIO]:
        arguments = [
            "--verify-receipt",
            str(receipt),
            "--expect-source-commit",
            source_commit,
            "--expect-source-tree-sha256",
            source_tree_sha256,
        ]
        if extra:
            arguments.extend(extra)
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = collector.main(arguments)
        return status, stdout, stderr

    def test_verify_receipt_emits_only_outcome_and_digest_of_exact_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, encoded = self.write_final_receipt(directory, suffix=b" \n")
            status, stdout, stderr = self.run_verifier(receipt)
        self.assertEqual(0, status)
        self.assertEqual(
            {
                "outcome": "supported-success",
                "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
            },
            json.loads(stdout.getvalue()),
        )
        self.assertEqual("", stderr.getvalue())

    def test_verify_receipt_accepts_reproducible_blocker_outcome(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(
                directory, observed=blocker_observed(), quote=True
            )
            status, stdout, stderr = self.run_verifier(receipt)
        self.assertEqual(0, status)
        self.assertEqual("reproducible-blocker", json.loads(stdout.getvalue())["outcome"])
        self.assertEqual("", stderr.getvalue())

    def test_verify_receipt_rejects_schema_timestamp_privacy_and_outcome_drift(self) -> None:
        cases = (
            ("schema_version", "other-schema"),
            ("recorded_at_utc", "2026-13-14T00:00:00Z"),
            ("permission_to_quote", "yes"),
            ("privacy", {**collector.PRIVACY, "raw_output_collected": True}),
            ("observed_result", success_observed(outcome="unsupported")),
        )
        for field, invalid_value in cases:
            with self.subTest(field=field), TemporaryDirectory() as directory:
                receipt_value = collector._build_receipt(
                    submission(quote=False, observed=success_observed())
                )
                receipt_value[field] = invalid_value
                encoded = (json.dumps(receipt_value, sort_keys=True) + "\n").encode("utf-8")
                receipt = Path(directory) / "receipt.json"
                receipt.write_bytes(encoded)
                status, stdout, stderr = self.run_verifier(receipt)
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertTrue(stderr.getvalue().startswith("NOT VERIFIED:"))
            self.assertNotIn(str(invalid_value), stderr.getvalue())

    def test_verify_receipt_rejects_duplicate_members_invalid_utf8_and_oversize(self) -> None:
        cases = (
            b'{"schema_version":"one","schema_version":"two"}',
            b"\xffprivate-marker",
            b" " * (collector.MAX_RECEIPT_BYTES + 1),
        )
        for encoded in cases:
            with self.subTest(encoded=encoded[:10]), TemporaryDirectory() as directory:
                receipt = Path(directory) / "receipt.json"
                receipt.write_bytes(encoded)
                status, stdout, stderr = self.run_verifier(receipt)
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertTrue(stderr.getvalue().startswith("NOT VERIFIED:"))
            self.assertNotIn("private-marker", stderr.getvalue())

    def test_verify_receipt_rejects_integer_digit_limit_without_file_changes(self) -> None:
        private_marker = "private-integer-limit-marker"
        digits = "9" * 4_301
        encoded = b'{"integer": ' + digits.encode("ascii") + b"}\n"
        self.assertLess(len(encoded), collector.MAX_RECEIPT_BYTES)
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / f"{private_marker}.json"
            sibling = Path(directory) / "sibling.json"
            sibling_bytes = b"stable sibling\n"
            receipt.write_bytes(encoded)
            sibling.write_bytes(sibling_bytes)
            before_entries = sorted(path.name for path in Path(directory).iterdir())
            before_receipt_mtime = receipt.stat().st_mtime_ns
            before_sibling_mtime = sibling.stat().st_mtime_ns

            status, stdout, stderr = self.run_verifier(receipt)

            after_entries = sorted(path.name for path in Path(directory).iterdir())
            after_receipt_mtime = receipt.stat().st_mtime_ns
            after_sibling_mtime = sibling.stat().st_mtime_ns
            after_receipt_bytes = receipt.read_bytes()
            after_sibling_bytes = sibling.read_bytes()
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual("NOT VERIFIED: receipt is not bounded UTF-8 JSON\n", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())
        self.assertNotIn(digits, stderr.getvalue())
        self.assertEqual(before_entries, after_entries)
        self.assertEqual(encoded, after_receipt_bytes)
        self.assertEqual(before_receipt_mtime, after_receipt_mtime)
        self.assertEqual(sibling_bytes, after_sibling_bytes)
        self.assertEqual(before_sibling_mtime, after_sibling_mtime)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_verify_receipt_rejects_symlink_without_reading_target(self) -> None:
        with TemporaryDirectory() as directory:
            target, _encoded = self.write_final_receipt(directory)
            receipt = Path(directory) / "receipt-link.json"
            try:
                receipt.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted")
            status, stdout, stderr = self.run_verifier(receipt)
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("regular file", stderr.getvalue())

    def test_verify_receipt_requires_matching_source_ids_and_read_only_mode(self) -> None:
        private_marker = "private-source-marker"
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            status, stdout, stderr = self.run_verifier(
                receipt, source_commit=private_marker
            )
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertIn("exact lowercase source identity", stderr.getvalue())
            self.assertNotIn(private_marker, stderr.getvalue())

            status, stdout, stderr = self.run_verifier(
                receipt,
                extra=["--i-opt-in-to-write-local-receipt"],
            )
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertEqual("NOT VERIFIED: invalid command-line arguments\n", stderr.getvalue())

    def test_verify_receipt_rejects_independent_valid_but_mismatched_source_ids(self) -> None:
        cases = (
            ("commit", "c" * 40, SOURCE_TREE_SHA256),
            ("tree", SOURCE_COMMIT, "d" * 64),
        )
        for label, expected_commit, expected_tree in cases:
            with self.subTest(identity=label), TemporaryDirectory() as directory:
                receipt, _encoded = self.write_final_receipt(directory)
                status, stdout, stderr = self.run_verifier(
                    receipt,
                    source_commit=expected_commit,
                    source_tree_sha256=expected_tree,
                )
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertTrue(stderr.getvalue().startswith("NOT VERIFIED:"))
            self.assertIn("does not match", stderr.getvalue())
            self.assertNotIn(expected_commit, stderr.getvalue())
            self.assertNotIn(expected_tree, stderr.getvalue())

    def test_verify_receipt_rejects_missing_and_additional_top_level_members(self) -> None:
        private_marker = "private-top-level-marker"
        cases = ("missing", "additional")
        for case in cases:
            with self.subTest(case=case), TemporaryDirectory() as directory:
                receipt_value = collector._build_receipt(
                    submission(quote=False, observed=success_observed())
                )
                if case == "missing":
                    receipt_value.pop("privacy")
                else:
                    receipt_value[private_marker] = "private-top-level-value"
                receipt = Path(directory) / "receipt.json"
                receipt.write_text(json.dumps(receipt_value), encoding="utf-8")
                status, stdout, stderr = self.run_verifier(receipt)
            self.assertEqual(2, status)
            self.assertEqual("", stdout.getvalue())
            self.assertIn("closed schema", stderr.getvalue())
            self.assertNotIn(private_marker, stderr.getvalue())
            self.assertNotIn("private-top-level-value", stderr.getvalue())

    def test_verify_receipt_rejects_non_regular_directory_path_without_echoing_it(self) -> None:
        private_marker = "private-receipt-directory"
        with TemporaryDirectory() as directory:
            receipt = Path(directory) / private_marker
            receipt.mkdir()
            status, stdout, stderr = self.run_verifier(receipt)
        self.assertEqual(2, status)
        self.assertEqual("", stdout.getvalue())
        self.assertIn("regular file", stderr.getvalue())
        self.assertNotIn(private_marker, stderr.getvalue())

    def test_verify_receipt_does_not_create_or_modify_sibling_or_receipt_files(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, encoded = self.write_final_receipt(directory)
            sibling = Path(directory) / "sibling.json"
            sibling_bytes = b"stable sibling\n"
            sibling.write_bytes(sibling_bytes)
            before_entries = sorted(path.name for path in Path(directory).iterdir())
            before_receipt_mtime = receipt.stat().st_mtime_ns
            before_sibling_mtime = sibling.stat().st_mtime_ns

            status, stdout, stderr = self.run_verifier(receipt)

            after_entries = sorted(path.name for path in Path(directory).iterdir())
            after_receipt_mtime = receipt.stat().st_mtime_ns
            after_sibling_mtime = sibling.stat().st_mtime_ns
            after_receipt_bytes = receipt.read_bytes()
            after_sibling_bytes = sibling.read_bytes()
        self.assertEqual(0, status)
        self.assertNotEqual("", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())
        self.assertEqual(before_entries, after_entries)
        self.assertEqual(encoded, after_receipt_bytes)
        self.assertEqual(before_receipt_mtime, after_receipt_mtime)
        self.assertEqual(sibling_bytes, after_sibling_bytes)
        self.assertEqual(before_sibling_mtime, after_sibling_mtime)


if __name__ == "__main__":
    unittest.main()
