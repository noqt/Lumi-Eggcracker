from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.export_detection_receipt import (
    EXPORT_SCHEMA,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_OUTPUT_BYTES,
    ExportError,
    export_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export_detection_receipt.py"
EVENT_ID = "a" * 24


def receipt(*, result: str = "TERMINATED") -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "lumi-eggcracker.detection-receipt.v2",
        "event_id": EVENT_ID,
        "source_commit": "c" * 40,
        "version": "1.0.10",
        "catalogue_sha256": "d" * 64,
        "receipt_written_utc": "2026-10-01T10:30:00.123456Z",
        "detector": {
            "profile": "content.gguf-llama",
            "detection_path": "CONTENT",
            "catalogue_schema": "lumi-eggcracker.detectors.v3",
            "model": {"path": "CANARY_MODEL_PATH"},
        },
        "trigger": {"kind": "UNAPPROVED_AI_MATCH", "observed_monotonic_ns": 100},
        "result": result,
        "observed": {"pid": 414141, "uid": 31337, "argv": ["CANARY_ARGUMENT"]},
        "executable": {"basename": "CANARY_EXECUTABLE_PATH"},
        "workload": {"cgroup": "CANARY_CGROUP_PATH"},
        "runtime": {"environment": "CANARY_ENVIRONMENT_VALUE"},
        "correlation": {"evidence_bearing": [{"pid": 515151}]},
        "capture": {"quarantine_cgroup": "CANARY_CAPTURE_PATH"},
    }
    if result == "TERMINATED":
        value["containment"] = {
            "empty_verified_monotonic_ns": 130,
            "first_stop_monotonic_ns": 100,
            "kill_write_completed_monotonic_ns": 120,
            "kill_write_started_monotonic_ns": 110,
            "primitive": "pidfd-stop+cgroup.kill",
            "qualification_to_first_stop_ms": 0.01,
            "root_populated": 0,
            "surviving_pids": [],
            "trigger_to_empty_ms": 0.00003,
        }
        value["trigger"] = {"kind": "UNAPPROVED_AI_MATCH", "observed_monotonic_ns": 100}
    else:
        value["error"] = "CANARY_RAW_ERROR"
        value["trigger"] = {"kind": "UNAPPROVED_AI_MATCH"}
    return value


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, allow_nan=True), encoding="utf-8")


class DetectionReceiptExportTests(unittest.TestCase):
    def test_terminated_export_is_allowlisted_and_hashes_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            write_json(source, receipt())
            source_bytes = source.read_bytes()

            export_receipt(source, EVENT_ID, output)

            exported_bytes = output.read_bytes()
            self.assertLessEqual(len(exported_bytes), MAX_OUTPUT_BYTES)
            document = json.loads(exported_bytes)
            self.assertEqual(EXPORT_SCHEMA, document["export_schema"])
            self.assertEqual(hashlib.sha256(source_bytes).hexdigest(), document["source_sha256"])
            self.assertEqual("NOT_AUTHENTICATED", document["authentication"])
            self.assertEqual("NOT_PERFORMED", document["live_verification"])
            projected = document["receipt"]
            self.assertEqual("TERMINATED", projected["recorded_result"])
            self.assertEqual(EVENT_ID, projected["event_id"])
            self.assertEqual(0, projected["recorded_empty_evidence"]["root_populated"])
            self.assertEqual([], projected["recorded_empty_evidence"]["surviving_pids"])
            self.assertEqual(
                {
                    "schema_version",
                    "event_id",
                    "source_commit",
                    "version",
                    "catalogue_sha256",
                    "receipt_written_utc",
                    "detector",
                    "trigger",
                    "recorded_result",
                    "recorded_empty_evidence",
                },
                set(projected),
            )
            self.assertEqual(
                {"profile", "detection_path", "catalogue_schema"},
                set(projected["detector"]),
            )
            for canary in (
                b"CANARY_MODEL_PATH",
                b"CANARY_ARGUMENT",
                b"CANARY_EXECUTABLE_PATH",
                b"CANARY_CGROUP_PATH",
                b"CANARY_ENVIRONMENT_VALUE",
                b"CANARY_CAPTURE_PATH",
                b"CANARY_RAW_ERROR",
                b"414141",
                b"31337",
                b"515151",
            ):
                self.assertNotIn(canary, exported_bytes)

    def test_containment_failure_remains_failure_and_raw_error_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            write_json(source, receipt(result="CONTAINMENT_FAILED"))

            export_receipt(source, EVENT_ID, output)

            exported = json.loads(output.read_text(encoding="utf-8"))
            projected = exported["receipt"]
            self.assertEqual("CONTAINMENT_FAILED", projected["recorded_result"])
            self.assertNotIn("recorded_empty_evidence", projected)
            self.assertNotIn("error", projected)
            self.assertNotIn("CANARY_RAW_ERROR", output.read_text(encoding="utf-8"))

    def test_rejects_unsupported_or_mismatched_receipt_identities(self) -> None:
        invalid_cases = (
            ("schema", lambda item: item.__setitem__("schema_version", "other")),
            ("event", lambda item: item.__setitem__("event_id", "b" * 24)),
            (
                "overlong version",
                lambda item: item.__setitem__("version", "1.0.10+" + "a" * 65),
            ),
            ("profile", lambda item: item["detector"].__setitem__("profile", "CANARY_PATH")),
            ("path", lambda item: item["detector"].__setitem__("detection_path", "CANARY_PATH")),
            (
                "catalogue schema",
                lambda item: item["detector"].__setitem__("catalogue_schema", "other"),
            ),
            ("trigger", lambda item: item["trigger"].__setitem__("kind", "other")),
            ("result", lambda item: item.__setitem__("result", "OTHER")),
        )
        for label, mutate in invalid_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "receipt.json"
                output = root / "export.json"
                invalid = receipt()
                mutate(invalid)
                write_json(source, invalid)
                with self.assertRaises(ExportError):
                    export_receipt(source, EVENT_ID, output)
                self.assertFalse(output.exists())

    def test_rejects_inconsistent_terminated_empty_evidence(self) -> None:
        invalid_cases = (
            ("root populated", lambda item: item["containment"].__setitem__("root_populated", 1)),
            ("boolean root count", lambda item: item["containment"].__setitem__("root_populated", False)),
            ("survivor", lambda item: item["containment"].__setitem__("surviving_pids", [42])),
            (
                "time order",
                lambda item: item["containment"].__setitem__("kill_write_started_monotonic_ns", 90),
            ),
            (
                "empty duration",
                lambda item: item["containment"].__setitem__("trigger_to_empty_ms", 9.0),
            ),
            (
                "trigger time",
                lambda item: item["trigger"].__setitem__("observed_monotonic_ns", 101),
            ),
        )
        for label, mutate in invalid_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "receipt.json"
                output = root / "export.json"
                invalid = receipt()
                mutate(invalid)
                write_json(source, invalid)
                with self.assertRaises(ExportError):
                    export_receipt(source, EVENT_ID, output)
                self.assertFalse(output.exists())

    def test_rejects_failed_receipt_with_termination_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            invalid = receipt(result="CONTAINMENT_FAILED")
            invalid["containment"] = receipt()["containment"]
            write_json(source, invalid)
            with self.assertRaises(ExportError):
                export_receipt(source, EVENT_ID, output)
            self.assertFalse(output.exists())

    def test_rejects_duplicate_keys_at_nested_depth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            text = json.dumps(receipt())
            text = text.replace('"observed": {', '"observed": {"x": 1, "x": 2,', 1)
            source.write_text(text, encoding="utf-8")
            with self.assertRaises(ExportError):
                export_receipt(source, EVENT_ID, output)
            self.assertFalse(output.exists())

    def test_rejects_oversized_deep_nonfinite_and_extreme_numeric_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"

            deep_value: object = 0
            for _ in range(MAX_JSON_DEPTH):
                deep_value = [deep_value]
            deep_receipt = {**receipt(), "opaque": deep_value}
            cases = (
                b" " * (MAX_INPUT_BYTES + 1),
                json.dumps(deep_receipt).encode(),
                json.dumps({**receipt(), "opaque": float("nan")}).encode(),
                json.dumps(receipt()).rstrip("}").encode() + b',"opaque":1e9999}',
                b'{"schema_version":',
                b"\xff",
            )
            for index, raw in enumerate(cases):
                with self.subTest(index=index):
                    source.write_bytes(raw)
                    with self.assertRaises(ExportError):
                        export_receipt(source, EVENT_ID, output)
                    self.assertFalse(output.exists())

    def test_rejects_nonregular_input_and_existing_or_nonregular_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            write_json(source, receipt())

            with self.assertRaises(ExportError):
                export_receipt(root, EVENT_ID, output)

            output.mkdir()
            with self.assertRaises(ExportError):
                export_receipt(source, EVENT_ID, output)
            output.rmdir()

            output.write_text("preserve me", encoding="utf-8")
            with self.assertRaises(ExportError):
                export_receipt(source, EVENT_ID, output)
            self.assertEqual("preserve me", output.read_text(encoding="utf-8"))

    def test_rejects_symlinks_and_reparse_point_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            write_json(source, receipt())
            target = root / "target.json"
            target.write_text("preserve me", encoding="utf-8")
            input_link = root / "input-link.json"
            output_link = root / "output-link.json"
            parent_link = root / "parent-link"
            try:
                os.symlink(source, input_link)
                os.symlink(target, output_link)
                os.symlink(root, parent_link, target_is_directory=True)
            except (NotImplementedError, OSError):
                real_lstat = os.lstat

                def fake_lstat(path: object) -> object:
                    candidate = Path(path)
                    if candidate in (source, output):
                        return SimpleNamespace(
                            st_mode=stat.S_IFREG | 0o600,
                            st_file_attributes=0x400,
                        )
                    if candidate == parent_link:
                        return SimpleNamespace(
                            st_mode=stat.S_IFDIR | 0o700,
                            st_file_attributes=0x400,
                        )
                    return real_lstat(path)

                with patch("scripts.export_detection_receipt.os.lstat", side_effect=fake_lstat):
                    for input_path, output_path in (
                        (source, output),
                        (source, parent_link / "new-output.json"),
                        (parent_link / source.name, root / "parent-output.json"),
                    ):
                        with (
                            self.subTest(input=input_path.name, output=output_path.name),
                            self.assertRaises(ExportError),
                        ):
                            export_receipt(input_path, EVENT_ID, output_path)
            else:
                for input_path, output_path in (
                    (input_link, output),
                    (source, output_link),
                    (parent_link / source.name, root / "parent-output.json"),
                    (source, parent_link / "new-output.json"),
                ):
                    with (
                        self.subTest(input=input_path.name, output=output_path.name),
                        self.assertRaises(ExportError),
                    ):
                        export_receipt(input_path, EVENT_ID, output_path)
            self.assertEqual("preserve me", target.read_text(encoding="utf-8"))
            self.assertFalse(output.exists())

    def test_cli_subprocess_exports_one_synthetic_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "receipt.json"
            output = root / "export.json"
            write_json(source, receipt())
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = str(ROOT / "src")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--expected-event-id",
                    EVENT_ID,
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("detection receipt export complete\n", result.stdout)
            self.assertEqual("TERMINATED", json.loads(output.read_text())["receipt"]["recorded_result"])

    def test_cli_diagnostics_do_not_echo_ids_or_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "CANARY_INPUT_PATH.json"
            output = root / "CANARY_OUTPUT_PATH.json"
            write_json(source, receipt())
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            environment["PYTHONPATH"] = str(ROOT / "src")
            canary_id = "z" * 24
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--expected-event-id",
                    canary_id,
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(1, result.returncode)
            self.assertNotIn(str(source), result.stderr)
            self.assertNotIn(str(output), result.stderr)
            self.assertNotIn(canary_id, result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
