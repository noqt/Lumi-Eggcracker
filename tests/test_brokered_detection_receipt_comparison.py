"""Focused tests for the offline redacted detection receipt comparator."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

_MODULE_PATH = (
    Path(__file__).parents[1]
    / "src"
    / "lumi_eggcracker"
    / "brokered"
    / "compare_detection_receipts.py"
)
_MODULE_SPEC = importlib.util.spec_from_file_location("compare_detection_receipts", _MODULE_PATH)
if _MODULE_SPEC is None or _MODULE_SPEC.loader is None:  # pragma: no cover - test setup guard
    raise ImportError("comparison module could not be loaded")
comparison = importlib.util.module_from_spec(_MODULE_SPEC)
_MODULE_SPEC.loader.exec_module(comparison)


def _document(
    *,
    result: str = "TERMINATED",
    profile: str = "content.gguf-llama",
    export_schema: str = comparison.EXPORT_SCHEMA,
    classification_basis: object = comparison.CLASSIFICATION_BASIS,
    source_commit: str = "a" * 40,
    version: str = "1.0.10",
    catalogue_sha256: str = "b" * 64,
    event_id: str = "0" * 24,
    qualification_to_first_stop_ms: float = 5.0,
    trigger_to_empty_ms: float = 0.25,
    first_stop_ns: int = 1_000_000_000,
    empty_ns: int = 1_000_250_000,
) -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema_version": comparison.RECEIPT_SCHEMA,
        "event_id": event_id,
        "source_commit": source_commit,
        "version": version,
        "catalogue_sha256": catalogue_sha256,
        "receipt_written_utc": "2026-10-02T00:00:00Z",
        "detector": {
            "profile": profile,
            "detection_path": "CONTENT",
            "catalogue_schema": comparison.DETECTOR_SCHEMA,
        },
        "trigger": {"kind": comparison._PROFILE_TRIGGER[profile]},
        "recorded_result": result,
    }
    if export_schema == comparison.EXPORT_SCHEMA_V2:
        receipt["classification_basis"] = classification_basis
    if result == "TERMINATED":
        receipt["recorded_empty_evidence"] = {
            "empty_verified_monotonic_ns": empty_ns,
            "first_stop_monotonic_ns": first_stop_ns,
            "kill_write_completed_monotonic_ns": first_stop_ns + 200,
            "kill_write_started_monotonic_ns": first_stop_ns + 100,
            "primitive": comparison._CONTAINMENT_PRIMITIVE,
            "qualification_to_first_stop_ms": qualification_to_first_stop_ms,
            "root_populated": 0,
            "surviving_pids": [],
            "trigger_to_empty_ms": trigger_to_empty_ms,
        }
    return {
        "export_schema": export_schema,
        "source_sha256": "f" * 64,
        "authentication": "NOT_AUTHENTICATED",
        "live_verification": "NOT_PERFORMED",
        "receipt": receipt,
    }


def _write(path: Path, document: object, *, allow_nan: bool = False) -> None:
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=allow_nan) + "\n",
        encoding="utf-8",
    )


class DetectionReceiptComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        # Leave the task-scoped fixtures in place so the guarded test runner can
        # preserve its bounded artifacts without deleting any repository file.
        self.root = Path(tempfile.mkdtemp(prefix="receipt-comparison-"))

    def _write_document(self, name: str, **kwargs: object) -> Path:
        path = self.root / name
        _write(path, _document(**kwargs))
        return path

    @staticmethod
    def _run_cli(before: Path, after: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = comparison.main(
                ["--before", str(before), "--after", str(after)]
            )
        return status, stdout.getvalue(), stderr.getvalue()

    def test_v2_accepts_all_profiles_and_result_branches(self) -> None:
        for profile in comparison._PROFILE_TRIGGER:
            for result in ("TERMINATED", "CONTAINMENT_FAILED"):
                with self.subTest(profile=profile, result=result):
                    path = self._write_document(
                        f"{profile}-{result}.json",
                        export_schema=comparison.EXPORT_SCHEMA_V2,
                        profile=profile,
                        result=result,
                    )
                    validated = comparison._validate_export(path.read_bytes())
                    self.assertEqual(profile, validated["profile"])
                    self.assertEqual(
                        comparison._PROFILE_TRIGGER[profile],
                        validated["trigger"],
                    )
                    self.assertEqual(result, validated["recorded_result"])

    def test_versions_require_known_exact_fields_and_v2_basis(self) -> None:
        invalid_documents: list[tuple[str, dict[str, object]]] = []

        missing_basis = _document(export_schema=comparison.EXPORT_SCHEMA_V2)
        missing_basis["receipt"].pop("classification_basis")
        invalid_documents.append(("missing basis", missing_basis))

        wrong_basis = _document(
            export_schema=comparison.EXPORT_SCHEMA_V2,
            classification_basis="NOT_THE_RECORDED_BASIS",
        )
        invalid_documents.append(("wrong basis", wrong_basis))

        extra_field = _document(export_schema=comparison.EXPORT_SCHEMA_V2)
        extra_field["receipt"]["unexpected"] = "reject"
        invalid_documents.append(("extra v2 field", extra_field))

        v1_with_basis = _document()
        v1_with_basis["receipt"]["classification_basis"] = comparison.CLASSIFICATION_BASIS
        invalid_documents.append(("v1 basis", v1_with_basis))

        unknown_version = _document()
        unknown_version["export_schema"] = "lumi-eggcracker.redacted-detection-receipt-export.v3"
        invalid_documents.append(("unknown version", unknown_version))

        for label, document in invalid_documents:
            with self.subTest(label=label):
                path = self.root / f"invalid-{label.replace(' ', '-')}.json"
                _write(path, document)
                with self.assertRaises(comparison.ComparisonError):
                    comparison._validate_export(path.read_bytes())

    def test_mixed_v1_v2_comparison_uses_common_semantics(self) -> None:
        before = self._write_document("mixed-before-v1.json")
        after = self._write_document(
            "mixed-after-v2.json",
            export_schema=comparison.EXPORT_SCHEMA_V2,
        )

        output = comparison.compare_receipts(before, after)

        self.assertEqual("RECORDED", output["comparison_status"])
        self.assertEqual("UNCHANGED", output["changes"]["recorded_result"])
        self.assertEqual("COMPARABLE", output["timing_comparison"]["status"])
        self.assertNotIn("classification_basis", json.dumps(output))

    def test_matching_recorded_context_compares_durations_without_absolute_clock_subtraction(self) -> None:
        before = self._write_document(
            "before.json",
            event_id="0" * 24,
            qualification_to_first_stop_ms=5.0,
            trigger_to_empty_ms=0.25,
            first_stop_ns=3_000_000_000,
            empty_ns=3_000_250_000,
        )
        after = self._write_document(
            "after.json",
            event_id="1" * 24,
            qualification_to_first_stop_ms=7.0,
            trigger_to_empty_ms=0.5,
            first_stop_ns=1_000_000_000,
            empty_ns=1_000_500_000,
        )

        output = comparison.compare_receipts(before, after)

        self.assertEqual("RECORDED", output["comparison_status"])
        self.assertEqual("NOT_AUTHENTICATED", output["authentication"])
        self.assertEqual("NOT_PERFORMED", output["live_verification"])
        self.assertEqual(
            {
                "source_commit": "UNCHANGED",
                "version": "UNCHANGED",
                "catalogue_sha256": "UNCHANGED",
                "profile": "UNCHANGED",
                "recorded_result": "UNCHANGED",
            },
            output["changes"],
        )
        self.assertEqual("COMPARABLE", output["timing_comparison"]["status"])
        self.assertEqual(
            "MATCHING_RECORDED_CONTEXT_ONLY",
            output["timing_comparison"]["basis"],
        )
        self.assertEqual(
            {"qualification_to_first_stop_ms": 2.0, "trigger_to_empty_ms": 0.25},
            output["timing_comparison"]["delta_ms"],
        )
        self.assertNotIn("monotonic", json.dumps(output).lower())
        self.assertLessEqual(len(comparison._encode_output(output)), comparison.MAX_OUTPUT_BYTES)

    def test_terminated_to_failure_shows_transition_and_unavailable_timing(self) -> None:
        before = self._write_document("before.json")
        after = self._write_document(
            "after.json",
            result="CONTAINMENT_FAILED",
            profile="content.gguf-ollama",
            source_commit="d" * 40,
            version="1.0.11",
            catalogue_sha256="e" * 64,
            event_id="2" * 24,
        )

        output = comparison.compare_receipts(before, after)

        self.assertEqual("TERMINATED_TO_CONTAINMENT_FAILED", output["changes"]["recorded_result"])
        self.assertEqual("UNAVAILABLE", output["timing_comparison"]["status"])
        self.assertEqual("MISSING_RECORDED_TIMING", output["timing_comparison"]["basis"])
        self.assertNotIn("delta_ms", output["timing_comparison"])
        self.assertEqual("CONTAINMENT_FAILED", output["after"]["recorded_result"])

    def test_mismatched_recorded_context_is_incomparable_without_durations(self) -> None:
        before = self._write_document("before.json")
        after = self._write_document(
            "after.json",
            profile="content.gguf-ollama",
            source_commit="c" * 40,
            version="1.0.11",
            catalogue_sha256="d" * 64,
            event_id="3" * 24,
            first_stop_ns=10_000_000_000,
            empty_ns=10_000_100_000,
            trigger_to_empty_ms=0.1,
        )

        output = comparison.compare_receipts(before, after)

        self.assertEqual("CHANGED", output["changes"]["profile"])
        self.assertEqual("INCOMPARABLE", output["timing_comparison"]["status"])
        self.assertEqual("RECORDED_CONTEXT_MISMATCH", output["timing_comparison"]["basis"])
        self.assertNotIn("before_durations_ms", output["timing_comparison"])

    def test_cli_normal_files_is_stdout_only_and_uses_fixed_safe_fields(self) -> None:
        before = self._write_document("before.json")
        after = self._write_document("after.json", event_id="4" * 24)
        before_names = {entry.name for entry in self.root.iterdir()}

        status, stdout, stderr = self._run_cli(before, after)

        self.assertEqual(0, status)
        self.assertEqual("", stderr)
        parsed = json.loads(stdout)
        self.assertEqual(comparison.COMPARISON_SCHEMA, parsed["comparison_schema"])
        self.assertEqual(before_names, {entry.name for entry in self.root.iterdir()})
        self.assertNotIn(str(before), stdout)
        self.assertNotIn(str(after), stdout)
        self.assertLessEqual(len(stdout.encode("utf-8")), comparison.MAX_OUTPUT_BYTES)

    def test_strict_parser_rejects_malformed_oversized_duplicate_nonfinite_deep_and_extra_fields(self) -> None:
        valid = self._write_document("valid.json")
        cases: list[tuple[str, bytes, str]] = [
            ("malformed", b"{", "malformed"),
            (
                "oversized",
                b"{" + (b" " * comparison.MAX_INPUT_BYTES),
                "oversized",
            ),
            (
                "duplicate",
                b'{"authentication":"NOT_AUTHENTICATED","authentication":"NOT_AUTHENTICATED"}',
                "duplicate",
            ),
            (
                "deep",
                (b"[" * (comparison.MAX_JSON_DEPTH + 1))
                + (b"]" * (comparison.MAX_JSON_DEPTH + 1)),
                "deep",
            ),
        ]
        extra = copy.deepcopy(_document())
        extra["receipt"]["detector"]["raw"] = "SENSITIVE_SHOULD_NOT_ECHO"
        cases.append(
            (
                "extra",
                (
                    json.dumps(extra, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode("utf-8"),
                "extra",
            )
        )
        nonfinite = copy.deepcopy(_document())
        nonfinite["receipt"]["recorded_empty_evidence"]["trigger_to_empty_ms"] = float("nan")
        cases.append(
            (
                "nonfinite",
                (
                    json.dumps(nonfinite, sort_keys=True, separators=(",", ":"), allow_nan=True)
                    + "\n"
                ).encode("utf-8"),
                "nonfinite",
            )
        )

        for name, raw, _label in cases:
            with self.subTest(case=name):
                bad = self.root / f"{name}.json"
                bad.write_bytes(raw)
                status, stdout, stderr = self._run_cli(bad, valid)
                self.assertEqual(1, status)
                self.assertEqual("", stdout)
                self.assertEqual(
                    "comparison failed: invalid redacted export or filesystem path\n", stderr
                )
                self.assertNotIn(str(bad), stderr)
                self.assertNotIn("SENSITIVE_SHOULD_NOT_ECHO", stderr)

    def test_inconsistent_timing_and_failure_evidence_are_rejected(self) -> None:
        inconsistent = copy.deepcopy(_document())
        inconsistent["receipt"]["recorded_empty_evidence"]["trigger_to_empty_ms"] = 9.0
        first = self.root / "inconsistent.json"
        _write(first, inconsistent)
        second = self._write_document("second.json")
        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_receipts(first, second)

        failure_with_evidence = _document(result="CONTAINMENT_FAILED")
        failure_with_evidence["receipt"]["recorded_empty_evidence"] = {}
        failure = self.root / "failure-extra-evidence.json"
        _write(failure, failure_with_evidence)
        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_receipts(failure, second)

    def test_symlink_input_is_rejected_when_platform_supports_symlinks(self) -> None:
        source = self._write_document("source.json")
        other = self._write_document("other.json", event_id="5" * 24)
        linked = self.root / "linked.json"
        try:
            os.symlink(source, linked)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable on this host")
        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_receipts(linked, other)

    def test_cli_argument_errors_and_windows_stream_spellings_are_generic(self) -> None:
        source = self._write_document("source.json")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            redirect_stdout(stdout),
            redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            comparison.main(["--before", str(source)])
        self.assertEqual(2, raised.exception.code)
        self.assertEqual("", stdout.getvalue())
        self.assertTrue(stderr.getvalue().endswith("compare_detection_receipts.py: invalid command line\n"))
        self.assertNotIn(str(source), stderr.getvalue())

        with self.assertRaises(comparison.ComparisonError):
            comparison.compare_receipts(str(source) + ":hidden-stream", source)


if __name__ == "__main__":
    unittest.main()
