from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

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
        name: str = "final-receipt.json",
    ) -> tuple[Path, bytes]:
        receipt = collector._build_receipt(
            submission(quote=quote, observed=observed or success_observed())
        )
        encoded = (
            json.dumps(receipt, indent=2, sort_keys=True).encode("utf-8") + suffix
        )
        path = Path(directory) / name
        path.write_bytes(encoded)
        return path, encoded

    def run_compare_cli(
        self,
        before: Path,
        after: Path,
        *,
        before_source_commit: str = SOURCE_COMMIT,
        before_source_tree_sha256: str = SOURCE_TREE_SHA256,
        after_source_commit: str = SOURCE_COMMIT,
        after_source_tree_sha256: str = SOURCE_TREE_SHA256,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            str(SCRIPT),
            "--compare-receipts",
            "--before",
            str(before),
            "--after",
            str(after),
            "--before-source-commit",
            before_source_commit,
            "--before-source-tree-sha256",
            before_source_tree_sha256,
            "--after-source-commit",
            after_source_commit,
            "--after-source-tree-sha256",
            after_source_tree_sha256,
        ]
        if extra:
            arguments.extend(extra)
        return subprocess.run(
            arguments,
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
        )

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

    def run_summary_cli(
        self,
        manifest: Path,
        *,
        opt_in: bool = True,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            str(SCRIPT),
            "--summary-receipts",
            "--manifest",
            str(manifest),
        ]
        if opt_in:
            arguments.insert(3, "--i-opt-in-to-summarize-receipts")
        if extra:
            arguments.extend(extra)
        return subprocess.run(
            arguments,
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
        )

    def write_summary_manifest(
        self,
        directory: str,
        entries: list[dict[str, object]],
        *,
        name: str = "manifest.json",
    ) -> Path:
        path = Path(directory) / name
        path.write_text(json.dumps({"receipts": entries}), encoding="utf-8")
        return path

    def summary_entry(self, path: Path, *, commit: str = SOURCE_COMMIT, tree: str = SOURCE_TREE_SHA256) -> dict[str, object]:
        return {
            "path": str(path),
            "source_commit": commit,
            "source_tree_sha256": tree,
        }

    def test_summary_cli_preserves_manifest_order_and_aggregates_stably(self) -> None:
        with TemporaryDirectory() as directory:
            first, _first_encoded = self.write_final_receipt(
                directory, observed=success_observed(), name="first.json"
            )
            second_commit = "c" * 40
            second_tree = "d" * 64
            second, _second_encoded = self.write_final_receipt(
                directory,
                observed=blocker_observed(
                    source_commit=second_commit,
                    source_tree_sha256=second_tree,
                ),
                name="second.json",
            )
            manifest = self.write_summary_manifest(
                directory,
                [
                    self.summary_entry(second, commit=second_commit, tree=second_tree),
                    self.summary_entry(first),
                ],
            )
            result = self.run_summary_cli(manifest)
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual("supported-receipt-set-summary", summary["outcome"])
        self.assertEqual(
            ["reproducible-blocker", "supported-success"],
            [row["outcome"] for row in summary["rows"]],
        )
        self.assertEqual(
            {
                "receipt_count": 2,
                "outcome_counts": {
                    "reproducible-blocker": 1,
                    "supported-success": 1,
                },
            },
            summary["aggregate"],
        )
        self.assertNotIn("first.json", result.stdout)
        self.assertNotIn("second.json", result.stdout)
        self.assertNotIn("permission_to_quote", result.stdout)
        self.assertLessEqual(len(result.stdout.encode("utf-8")), collector.MAX_SUMMARY_OUTPUT_BYTES)

    def test_summary_cli_accepts_eight_receipts_with_bounded_output(self) -> None:
        with TemporaryDirectory() as directory:
            entries: list[dict[str, object]] = []
            for index in range(8):
                commit = f"{index + 1:040x}"
                tree = f"{index + 1:064x}"
                receipt, _encoded = self.write_final_receipt(
                    directory,
                    observed=success_observed(
                        source_commit=commit,
                        source_tree_sha256=tree,
                    ),
                    name=f"receipt-{index}.json",
                )
                entries.append(self.summary_entry(receipt, commit=commit, tree=tree))
            manifest = self.write_summary_manifest(directory, entries)
            result = self.run_summary_cli(manifest)
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(8, summary["aggregate"]["receipt_count"])
        self.assertEqual(8, len(summary["rows"]))
        self.assertEqual(8, summary["aggregate"]["outcome_counts"]["supported-success"])
        self.assertLessEqual(len(result.stdout.encode("utf-8")), collector.MAX_SUMMARY_OUTPUT_BYTES)

    def test_require_all_supported_keeps_all_success_summary_bytes_and_exits_zero(self) -> None:
        with TemporaryDirectory() as directory:
            entries: list[dict[str, object]] = []
            for index in range(8):
                commit = f"{index + 1:040x}"
                tree = f"{index + 1:064x}"
                receipt, _encoded = self.write_final_receipt(
                    directory,
                    observed=success_observed(
                        source_commit=commit,
                        source_tree_sha256=tree,
                    ),
                    name=f"success-{index}.json",
                )
                entries.append(self.summary_entry(receipt, commit=commit, tree=tree))
            manifest = self.write_summary_manifest(directory, entries)
            unflagged = self.run_summary_cli(manifest)
            flagged = self.run_summary_cli(manifest, extra=["--require-all-supported"])
        self.assertEqual(0, unflagged.returncode)
        self.assertEqual(0, flagged.returncode)
        self.assertEqual(unflagged.stdout, flagged.stdout)
        self.assertEqual("", flagged.stderr)

    def test_require_all_supported_returns_one_for_blocker_with_identical_summary_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            first, _first_encoded = self.write_final_receipt(
                directory, observed=success_observed(), name="success.json"
            )
            blocker_commit = "c" * 40
            blocker_tree = "d" * 64
            second, _second_encoded = self.write_final_receipt(
                directory,
                observed=blocker_observed(
                    source_commit=blocker_commit,
                    source_tree_sha256=blocker_tree,
                ),
                name="blocker.json",
            )
            manifest = self.write_summary_manifest(
                directory,
                [
                    self.summary_entry(first),
                    self.summary_entry(second, commit=blocker_commit, tree=blocker_tree),
                ],
            )
            unflagged = self.run_summary_cli(manifest)
            flagged = self.run_summary_cli(manifest, extra=["--require-all-supported"])
        self.assertEqual(0, unflagged.returncode)
        self.assertEqual(1, flagged.returncode)
        self.assertEqual(unflagged.stdout, flagged.stdout)
        self.assertEqual("", flagged.stderr)

    def test_require_all_supported_rejects_non_summary_modes_without_partial_output(self) -> None:
        private_marker = "private-require-all-input"
        with TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source_bytes = json.dumps({"private": private_marker}).encode("utf-8")
            source.write_bytes(source_bytes)
            output = Path(directory) / "receipt.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--require-all-supported",
                    "--i-opt-in-to-write-local-receipt",
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(source_bytes, source.read_bytes())
            self.assertFalse(output.exists())
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))
        self.assertNotIn(private_marker, result.stderr)

    def test_require_all_supported_requires_summary_opt_in_without_stdout_or_writes(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, receipt_bytes = self.write_final_receipt(directory, name="valid.json")
            manifest = self.write_summary_manifest(
                directory,
                [self.summary_entry(receipt), self.summary_entry(receipt.with_name("missing.json"))],
            )
            manifest_bytes = manifest.read_bytes()
            result = self.run_summary_cli(
                manifest,
                opt_in=False,
                extra=["--require-all-supported"],
            )
            self.assertEqual(receipt_bytes, receipt.read_bytes())
            self.assertEqual(manifest_bytes, manifest.read_bytes())
            self.assertFalse((Path(directory) / "summary.json").exists())
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))

    def test_require_all_supported_invalid_set_has_no_partial_output_or_input_changes(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, receipt_bytes = self.write_final_receipt(directory, name="valid.json")
            missing = Path(directory) / "missing.json"
            manifest = self.write_summary_manifest(
                directory,
                [self.summary_entry(receipt), self.summary_entry(missing)],
            )
            manifest_bytes = manifest.read_bytes()
            result = self.run_summary_cli(manifest, extra=["--require-all-supported"])
            self.assertEqual(receipt_bytes, receipt.read_bytes())
            self.assertEqual(manifest_bytes, manifest.read_bytes())
            self.assertFalse((Path(directory) / "summary.json").exists())
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))

    def test_summary_cli_requires_distinct_opt_in(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            manifest = self.write_summary_manifest(directory, [
                self.summary_entry(receipt),
                self.summary_entry(receipt.with_name("missing.json")),
            ])
            result = self.run_summary_cli(manifest, opt_in=False)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))
        self.assertFalse((Path(directory) / "summary.json").exists())

    def test_summary_cli_rejects_manifest_shape_and_duplicate_paths_without_stdout(self) -> None:
        private_marker = "private-summary-marker"
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            cases = (
                {
                    "receipts": [
                        self.summary_entry(receipt),
                        {**self.summary_entry(receipt), private_marker: "private"},
                    ],
                },
                {
                    "receipts": [
                        self.summary_entry(receipt),
                        self.summary_entry(Path(directory) / "missing.json"),
                    ],
                    private_marker: True,
                },
                {
                    "receipts": [
                        self.summary_entry(receipt),
                        self.summary_entry(Path(directory) / "nested" / ".." / receipt.name),
                    ],
                },
            )
            for index, value in enumerate(cases):
                with self.subTest(index=index):
                    manifest = Path(directory) / f"{private_marker}-{index}.json"
                    manifest.write_text(json.dumps(value), encoding="utf-8")
                    result = self.run_summary_cli(manifest)
                    self.assertEqual(2, result.returncode)
                    self.assertEqual("", result.stdout)
                    self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))
                    self.assertNotIn(private_marker, result.stderr)

    def test_summary_cli_rejects_duplicate_member_digest_and_source_mismatch(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, encoded = self.write_final_receipt(directory, name="one.json")
            duplicate = Path(directory) / "two.json"
            duplicate.write_bytes(encoded)
            cases: list[tuple[str, Path]] = []
            cases.append(
                (
                    "duplicate-digest",
                    self.write_summary_manifest(
                        directory,
                        [self.summary_entry(receipt), self.summary_entry(duplicate)],
                        name="duplicate-digest.json",
                    ),
                )
            )
            mismatch = self.write_summary_manifest(
                directory,
                [
                    self.summary_entry(receipt, commit="e" * 40),
                    self.summary_entry(duplicate),
                ],
                name="source-mismatch.json",
            )
            cases.append(("source-mismatch", mismatch))
            for label, manifest in cases:
                with self.subTest(label=label):
                    result = self.run_summary_cli(manifest)
                    self.assertEqual(2, result.returncode)
                    self.assertEqual("", result.stdout)
                    self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))
                    self.assertNotIn(str(manifest), result.stderr)

    def test_summary_cli_rejects_invalid_manifest_and_receipt_files(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            invalid_manifest = Path(directory) / "invalid-manifest.json"
            invalid_manifest.write_bytes(b"\xffprivate-invalid-utf8")
            oversized_manifest = Path(directory) / "oversized-manifest.json"
            oversized_manifest.write_bytes(b" " * (collector.MAX_MANIFEST_BYTES + 1))
            invalid_receipt = Path(directory) / "invalid-receipt.json"
            invalid_receipt.write_bytes(b"\xffprivate-invalid-utf8")
            invalid_receipt_manifest = self.write_summary_manifest(
                directory,
                [self.summary_entry(invalid_receipt), self.summary_entry(receipt)],
                name="invalid-receipt-manifest.json",
            )
            missing_manifest = self.write_summary_manifest(
                directory,
                [
                    self.summary_entry(Path(directory) / "missing-receipt.json"),
                    self.summary_entry(receipt),
                ],
                name="missing-receipt-manifest.json",
            )
            receipt_directory = Path(directory) / "receipt-directory"
            receipt_directory.mkdir()
            directory_manifest = self.write_summary_manifest(
                directory,
                [self.summary_entry(receipt_directory), self.summary_entry(receipt)],
                name="directory-receipt-manifest.json",
            )
            manifests = [
                ("invalid-manifest", invalid_manifest),
                ("oversized-manifest", oversized_manifest),
                ("invalid-receipt", invalid_receipt_manifest),
                ("missing-receipt", missing_manifest),
                ("directory-receipt", directory_manifest),
            ]
            if hasattr(os, "symlink"):
                linked = Path(directory) / "receipt-link.json"
                try:
                    linked.symlink_to(receipt)
                except OSError:
                    pass
                else:
                    manifests.append(
                        (
                            "linked-receipt",
                            self.write_summary_manifest(
                                directory,
                                [self.summary_entry(linked), self.summary_entry(receipt)],
                                name="linked-receipt-manifest.json",
                            ),
                        )
                    )
            for label, manifest in manifests:
                with self.subTest(label=label):
                    result = self.run_summary_cli(manifest)
                    self.assertEqual(2, result.returncode)
                    self.assertEqual("", result.stdout)
                    self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))

    def test_summary_cli_rejects_duplicate_manifest_members(self) -> None:
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            manifest = Path(directory) / "duplicate-member.json"
            entry = json.dumps(self.summary_entry(receipt), separators=(",", ":"))
            manifest.write_text(
                '{"receipts":['
                + entry.replace('"path":', '"path":"first","path":', 1)
                + ","
                + json.dumps(self.summary_entry(Path(directory) / "other.json"))
                + "]}",
                encoding="utf-8",
            )
            result = self.run_summary_cli(manifest)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT SUMMARIZED:"))

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

    def test_final_receipt_mocked_fifo_replacement_uses_nonblocking_open(self) -> None:
        """Use a deterministic mock replacement, not an actual POSIX FIFO."""
        sentinel_nonblock = 0x4000
        with TemporaryDirectory() as directory:
            receipt, _encoded = self.write_final_receipt(directory)
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            seen_flags: list[int] = []

            def mocked_open(_path: Path, flags: int) -> int:
                seen_flags.append(flags)
                if not flags & sentinel_nonblock:
                    raise AssertionError("mocked FIFO replacement would block")
                return read_fd

            try:
                with (
                    patch.object(collector.os, "O_NONBLOCK", sentinel_nonblock, create=True),
                    patch.object(collector.os, "open", side_effect=mocked_open),
                    self.assertRaisesRegex(collector.ReceiptInputError, "regular file, not a link"),
                ):
                    collector._read_final_receipt(receipt)
            finally:
                try:
                    os.close(read_fd)
                except OSError:
                    pass

        self.assertEqual(1, len(seen_flags))
        self.assertTrue(seen_flags[0] & sentinel_nonblock)

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

    def test_compare_cli_reports_source_transition_and_allowlisted_changes(self) -> None:
        after_commit = "c" * 40
        after_tree = "d" * 64
        with TemporaryDirectory() as directory:
            before, before_encoded = self.write_final_receipt(directory, name="before.json")
            after, _after_encoded = self.write_final_receipt(
                directory,
                observed=blocker_observed(
                    source_commit=after_commit,
                    source_tree_sha256=after_tree,
                ),
                name="after.json",
            )
            result = self.run_compare_cli(
                before,
                after,
                after_source_commit=after_commit,
                after_source_tree_sha256=after_tree,
            )
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        comparison = json.loads(result.stdout)
        self.assertTrue(comparison["changed"])
        self.assertEqual(hashlib.sha256(before_encoded).hexdigest(), comparison["before_receipt_sha256"])
        self.assertEqual(
            {
                "before": {
                    "source_commit": SOURCE_COMMIT,
                    "source_tree_sha256": SOURCE_TREE_SHA256,
                },
                "after": {
                    "source_commit": after_commit,
                    "source_tree_sha256": after_tree,
                },
            },
            comparison["source_transition"],
        )
        self.assertEqual(
            {
                "outcome": {"before": "supported-success", "after": "reproducible-blocker"},
                "result": {"before": "TERMINATED", "after": None},
                "target_survivors": {"before": 0, "after": None},
                "canary_survived": {"before": True, "after": None},
                "root_populated": {"before": 0, "after": None},
                "cleanup_complete": {"before": True, "after": None},
                "blocker_stage": {"before": None, "after": "host-preflight"},
                "blocker_code": {"before": None, "after": "CGROUP_V2_REQUIRED"},
            },
            comparison["observed_result_changes"],
        )
        self.assertNotIn("permission_to_quote", result.stdout)

    def test_compare_cli_identical_receipts_are_unchanged(self) -> None:
        with TemporaryDirectory() as directory:
            source, encoded = self.write_final_receipt(directory, name="source.json")
            before = Path(directory) / "before.json"
            after = Path(directory) / "after.json"
            before.write_bytes(encoded)
            after.write_bytes(encoded)
            result = self.run_compare_cli(before, after)
        self.assertEqual(0, result.returncode)
        self.assertEqual("", result.stderr)
        comparison = json.loads(result.stdout)
        self.assertFalse(comparison["changed"])
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(), comparison["before_receipt_sha256"]
        )
        self.assertEqual(comparison["before_receipt_sha256"], comparison["after_receipt_sha256"])
        self.assertEqual({}, comparison["observed_result_changes"])
        self.assertNotEqual(source, before)

    def test_compare_cli_rejects_invalid_receipt_without_stdout_or_echo(self) -> None:
        private_marker = "private-compare-receipt-marker"
        with TemporaryDirectory() as directory:
            before, _encoded = self.write_final_receipt(directory, name="before.json")
            after = Path(directory) / f"{private_marker}.json"
            after.write_bytes(b'{"schema_version":"one","schema_version":"two"}')
            result = self.run_compare_cli(before, after)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT COMPARED:"))
        self.assertNotIn(private_marker, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_compare_cli_rejects_bounded_file_failures(self) -> None:
        invalid_contents = (
            b'{"schema_version":"one","schema_version":"two"}',
            b" " * (collector.MAX_RECEIPT_BYTES + 1),
            b"\xffprivate-invalid-utf8",
        )
        for invalid_content in invalid_contents:
            with self.subTest(invalid_content=invalid_content[:8]), TemporaryDirectory() as directory:
                before, _before_encoded = self.write_final_receipt(directory, name="before.json")
                after = Path(directory) / "after.json"
                after.write_bytes(invalid_content)
                result = self.run_compare_cli(before, after)
            self.assertEqual(2, result.returncode)
            self.assertEqual("", result.stdout)
            self.assertTrue(result.stderr.startswith("NOT COMPARED:"))
            self.assertNotIn("Traceback", result.stderr)

        with TemporaryDirectory() as directory:
            before, _before_encoded = self.write_final_receipt(directory, name="before.json")
            after = Path(directory) / "after-directory"
            after.mkdir()
            result = self.run_compare_cli(before, after)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT COMPARED:"))
        self.assertNotIn("Traceback", result.stderr)

        if hasattr(os, "symlink"):
            with TemporaryDirectory() as directory:
                before, _before_encoded = self.write_final_receipt(directory, name="before.json")
                target, _target_encoded = self.write_final_receipt(directory, name="target.json")
                after = Path(directory) / "after-link"
                try:
                    after.symlink_to(target)
                except OSError:
                    pass
                else:
                    result = self.run_compare_cli(before, after)
                    self.assertEqual(2, result.returncode)
                    self.assertEqual("", result.stdout)
                    self.assertTrue(result.stderr.startswith("NOT COMPARED:"))
                    self.assertNotIn("Traceback", result.stderr)

    def test_compare_cli_rejects_source_mismatch_and_never_writes(self) -> None:
        private_marker = "private-source-mismatch-marker"
        with TemporaryDirectory() as directory:
            before, _before_encoded = self.write_final_receipt(directory, name="before.json")
            after, _after_encoded = self.write_final_receipt(
                directory, name=f"{private_marker}.json"
            )
            result = self.run_compare_cli(
                before,
                after,
                after_source_commit="e" * 40,
            )
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertTrue(result.stderr.startswith("NOT COMPARED:"))
        self.assertIn("source identity does not match", result.stderr)
        self.assertNotIn("e" * 40, result.stderr)
        self.assertNotIn(private_marker, result.stderr)
        self.assertNotIn(str(after), result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
