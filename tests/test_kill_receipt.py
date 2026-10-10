from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import kill_receipt
from lumi_eggcracker.cli import main


def receipt(
    *,
    post_cleanup: bool = False,
    response: bool = False,
    cleanup_update_error: bool = False,
    boundary_resolution_error: bool = False,
) -> dict[str, object]:
    run_id = "a" * 24
    value: dict[str, object] = {
        "cleanup": {"attempted": False},
        "containment": {
            "cgroup_kill_written": True,
            "descendant_cgroups_checked": 1,
            "empty_verified_monotonic_ns": 2_200,
            "kill_write_completed_monotonic_ns": 1_200,
            "kill_write_started_monotonic_ns": 1_100,
            "primitive": "cgroup.kill",
            "root_populated": 0,
            "surviving_pids": [],
            "trigger_to_empty_ms": 0.0012,
        },
        "event_id": "b" * 24,
        "receipt_written_utc": "2026-10-11T00:00:00Z",
        "result": "TERMINATED",
        "schema_version": kill_receipt.RECEIPT_SCHEMA,
        "source_commit": "c" * 40,
        "trigger": {"kind": "OPERATOR", "observed_monotonic_ns": 1_000},
        "version": "1.0.10",
        "workload": {
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service",
            "cgroup_device": 1,
            "cgroup_inode": 2,
            "name": "manual-test",
            "run_id": run_id,
            "unit": f"lumi-eggcracker-workload-{run_id}.service",
            "workload_uid": 2001,
        },
    }
    if post_cleanup:
        cleanup: dict[str, object] = {
            "attempted": True,
            "offline_boundary": {
                "removed": 0,
                "sink_namespace_removed": True,
                "workload_namespace_removed": True,
            },
            "systemctl_stop_returncode": 0,
            "systemctl_stop_stderr": "",
        }
        if boundary_resolution_error:
            del cleanup["offline_boundary"]
            cleanup["offline_boundary_error"] = "boundary lookup unavailable"
        value["cleanup"] = cleanup
    if response:
        value["receipt_path"] = "/private/canary/receipt.json"
    if cleanup_update_error:
        value["cleanup_update_error"] = True
    return value


class KillReceiptTests(unittest.TestCase):
    def write(self, directory: str, value: object, *, raw: bytes | None = None) -> Path:
        path = Path(directory) / "receipt-canary.json"
        path.write_bytes(
            raw
            if raw is not None
            else json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
        )
        return path

    def assert_fixed_success(self, path: Path) -> None:
        output = io.StringIO()
        error = io.StringIO()
        expected = {
            "limitations": kill_receipt.LIMITATIONS,
            "result": "STRUCTURE_VALID",
            "schema_version": kill_receipt.VALIDATION_SCHEMA,
        }
        before = path.read_bytes()
        with redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(0, kill_receipt.main([str(path)]))
        self.assertEqual(
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n",
            output.getvalue(),
        )
        self.assertEqual("", error.getvalue())
        self.assertEqual(before, path.read_bytes())
        for canary in ("canary", "private", "receipt.json", "manual-test"):
            self.assertNotIn(canary, output.getvalue())

    def assert_safe_failure(self, path: Path) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(4, kill_receipt.main([str(path)]))
        self.assertEqual("", output.getvalue())
        self.assertEqual(kill_receipt.SAFE_ERROR + "\n", error.getvalue())
        self.assertNotIn("canary", error.getvalue())

    def test_accepts_pre_cleanup_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assert_fixed_success(self.write(directory, receipt()))

    def test_accepts_post_cleanup_file_and_normal_response_forms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assert_fixed_success(self.write(directory, receipt(post_cleanup=True)))
            self.assert_fixed_success(
                self.write(directory, receipt(post_cleanup=True, response=True))
            )

    def test_accepts_cleanup_update_error_response_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assert_fixed_success(
                self.write(
                    directory,
                    receipt(post_cleanup=True, response=True, cleanup_update_error=True),
                )
            )

    def test_accepts_boundary_resolution_error_post_cleanup_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assert_fixed_success(
                self.write(
                    directory,
                    receipt(post_cleanup=True, boundary_resolution_error=True),
                )
            )

    def test_invalid_and_adversarial_values_fail_closed(self) -> None:
        cases: list[dict[str, object]] = []

        wrong_result = receipt()
        wrong_result["result"] = "CONTAINMENT_FAILED"
        cases.append(wrong_result)

        wrong_trigger = receipt()
        wrong_trigger["trigger"] = {"kind": "PID_LIMIT", "observed_monotonic_ns": 1_000}
        cases.append(wrong_trigger)

        false_kill = receipt()
        false_kill["containment"] = dict(false_kill["containment"], cgroup_kill_written=False)
        cases.append(false_kill)

        wrong_primitive = receipt()
        wrong_primitive["containment"] = dict(wrong_primitive["containment"], primitive="kill")
        cases.append(wrong_primitive)

        populated = receipt()
        populated["containment"] = dict(populated["containment"], root_populated=1)
        cases.append(populated)

        surviving = receipt()
        surviving["containment"] = dict(surviving["containment"], surviving_pids=[7])
        cases.append(surviving)

        missing = receipt()
        del missing["workload"]
        cases.append(missing)

        unexpected = receipt()
        unexpected["secret"] = "secret-canary"
        cases.append(unexpected)

        confused_bool = receipt()
        confused_bool["containment"] = dict(confused_bool["containment"], root_populated=False)
        cases.append(confused_bool)

        contradictory = receipt()
        contradictory["containment"] = dict(
            contradictory["containment"],
            empty_verified_monotonic_ns=1_150,
        )
        cases.append(contradictory)

        mismatched_duration = receipt()
        mismatched_duration["containment"] = dict(
            mismatched_duration["containment"], trigger_to_empty_ms=9.0
        )
        cases.append(mismatched_duration)

        top_level_update_without_path = receipt(post_cleanup=True)
        top_level_update_without_path["cleanup_update_error"] = True
        cases.append(top_level_update_without_path)

        with tempfile.TemporaryDirectory() as directory:
            for value in cases:
                self.assert_safe_failure(self.write(directory, value))

            duplicate = json.dumps(receipt(), separators=(",", ":")).replace(
                '"result":"TERMINATED"', '"result":"TERMINATED","result":"TERMINATED"'
            )
            self.assert_safe_failure(self.write(directory, {}, raw=duplicate.encode()))

            nonfinite = json.dumps(receipt(), separators=(",", ":")).replace(
                '"trigger_to_empty_ms":0.0012', '"trigger_to_empty_ms":NaN'
            )
            self.assert_safe_failure(self.write(directory, {}, raw=nonfinite.encode()))

            deep = ("[" * (kill_receipt.MAX_JSON_DEPTH + 1) + "0" + "]" *
                    (kill_receipt.MAX_JSON_DEPTH + 1)).encode()
            self.assert_safe_failure(self.write(directory, {}, raw=deep))

            oversized = b"{" + b"x" * kill_receipt.MAX_INPUT_BYTES + b"}"
            self.assert_safe_failure(self.write(directory, {}, raw=oversized))

            malformed = self.write(directory, {}, raw=b'{"secret-canary":')
            self.assert_safe_failure(malformed)

            self.assert_safe_failure(Path(directory) / "missing-canary.json")

    def test_cli_validation_is_offline_and_does_not_echo_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, receipt(post_cleanup=True, response=True))
            output = io.StringIO()
            error = io.StringIO()
            with (
                patch("lumi_eggcracker.cli.request", side_effect=AssertionError),
                patch("lumi_eggcracker.cli.supervisor_main", side_effect=AssertionError),
                redirect_stdout(output),
                redirect_stderr(error),
            ):
                self.assertEqual(0, main(["validate-kill-receipt", str(path)]))
            self.assertEqual("", error.getvalue())
            self.assertNotIn("canary", output.getvalue())

    def test_existing_dispatches_remain_separate(self) -> None:
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.request", return_value={"result": "PASS"}), redirect_stdout(output):
            self.assertEqual(0, main(["doctor"]))
        self.assertEqual('{"result": "PASS"}\n', output.getvalue())

        with patch("lumi_eggcracker.cli.validate_support_bundle_main", return_value=7):
            self.assertEqual(7, main(["validate-support-bundle", "input.json"]))
        with patch("lumi_eggcracker.cli.compare_detection_receipts_main", return_value=8):
            self.assertEqual(8, main(["compare-detection-receipts"]))

    def test_existing_kill_dispatch_remains_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "new-receipt.json"
            value = {"result": "TERMINATED"}
            output = io.StringIO()
            with (
                patch("lumi_eggcracker.cli.request", return_value=value) as request,
                patch("lumi_eggcracker.cli.write_new_json") as write_new_json,
                redirect_stdout(output),
            ):
                self.assertEqual(
                    0,
                    main(
                        [
                            "kill",
                            "--name",
                            "manual-test",
                            "--receipt",
                            str(output_path),
                        ]
                    ),
                )
            request.assert_called_once_with("kill", name="manual-test")
            write_new_json.assert_called_once_with(output_path, value)
            self.assertEqual(json.dumps(value, sort_keys=True) + "\n", output.getvalue())

    def test_symlink_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = self.write(directory, receipt())
            link = Path(directory) / "receipt-link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable")
            self.assert_safe_failure(link)


if __name__ == "__main__":
    unittest.main()
