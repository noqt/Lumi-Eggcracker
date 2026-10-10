from __future__ import annotations

import io
import json
import os
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
    cleanup_returncode: int = 0,
) -> dict[str, object]:
    run_id = "d" * 24
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
        "event_id": "e" * 24,
        "receipt_written_utc": "2026-10-11T12:34:56.123456Z",
        "result": "TERMINATED",
        "schema_version": kill_receipt.RECEIPT_SCHEMA,
        "source_commit": "f" * 40,
        "trigger": {"kind": "OPERATOR", "observed_monotonic_ns": 1_000},
        "version": "9.8.7-canary",
        "workload": {
            "boot_id": "fedcba98-7654-3210-fedc-ba9876543210",
            "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service",
            "cgroup_device": 31337,
            "cgroup_inode": 424242,
            "name": "manual-name-canary",
            "run_id": run_id,
            "unit": f"lumi-eggcracker-workload-{run_id}.service",
            "workload_uid": 3987,
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
            "systemctl_stop_returncode": cleanup_returncode,
            "systemctl_stop_stderr": "systemctl-stderr-canary",
        }
        if boundary_resolution_error:
            del cleanup["offline_boundary"]
            cleanup["offline_boundary_error"] = "boundary lookup unavailable"
        value["cleanup"] = cleanup
    if response:
        value["receipt_path"] = "/private/receipt-path-canary.json"
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

    def assert_handoff_failure(self, arguments: list[str]) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(4, main(arguments))
        self.assertEqual("", output.getvalue())
        self.assertEqual(kill_receipt.HANDOFF_SAFE_ERROR + "\n", error.getvalue())
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

    def test_handoff_projection_is_fixed_for_all_routes_and_cleanup_forms(self) -> None:
        routes = ("q-and-a", "bug-report", "private-security")
        cleanup_forms = (
            receipt(),
            receipt(post_cleanup=True, response=True),
            receipt(post_cleanup=True, boundary_resolution_error=True),
        )
        expected_keys = {
            "schema_version",
            "result",
            "trigger",
            "primitive",
            "cgroup_kill_written",
            "root_populated",
            "surviving_pids_count",
            "descendant_cgroups_checked",
            "trigger_to_empty_ms",
            "cleanup_outcome",
            "route",
            "limitations",
        }
        with tempfile.TemporaryDirectory() as directory:
            for route, value in zip(routes, cleanup_forms):
                receipt_path = self.write(directory, value)
                before = receipt_path.read_bytes()
                output_path = Path(directory) / f"handoff-{route}.json"
                output = io.StringIO()
                error = io.StringIO()
                with (
                    patch("lumi_eggcracker.kill_receipt.write_new_json") as write_new_json,
                    patch("lumi_eggcracker.cli.request", side_effect=AssertionError),
                    patch("lumi_eggcracker.cli.supervisor_main", side_effect=AssertionError),
                    patch("socket.socket", side_effect=AssertionError),
                    redirect_stdout(output),
                    redirect_stderr(error),
                ):
                    self.assertEqual(
                        0,
                        main(
                            [
                                "prepare-kill-receipt-handoff",
                                str(receipt_path),
                                "--route",
                                route,
                                "--output",
                                str(output_path),
                            ]
                        ),
                )
                self.assertEqual("", error.getvalue())
                self.assertEqual(before, receipt_path.read_bytes())
                write_new_json.assert_called_once()
                destination, projection = write_new_json.call_args.args
                self.assertEqual(output_path, destination)
                self.assertEqual(expected_keys, set(projection))
                self.assertEqual(route, projection["route"])
                self.assertEqual("HANDOFF_PREPARED", projection["result"])
                self.assertEqual("OPERATOR", projection["trigger"])
                self.assertEqual("cgroup.kill", projection["primitive"])
                self.assertEqual(True, projection["cgroup_kill_written"])
                self.assertEqual(0, projection["root_populated"])
                self.assertEqual(0, projection["surviving_pids_count"])
                self.assertEqual(1, projection["descendant_cgroups_checked"])
                self.assertEqual(0.0012, projection["trigger_to_empty_ms"])
                cleanup = value["cleanup"]
                self.assertEqual(
                    (
                        "NOT_ATTEMPTED"
                        if cleanup["attempted"] is False
                        else "ATTEMPTED_WITH_ERRORS"
                        if "offline_boundary_error" in cleanup
                        else "ATTEMPTED"
                    ),
                    projection["cleanup_outcome"],
                )
                self.assertEqual(kill_receipt.HANDOFF_SCHEMA, projection["schema_version"])
                self.assertEqual(kill_receipt.HANDOFF_LIMITATIONS, projection["limitations"])
                serialized = output.getvalue()
                workload = value["workload"]
                excluded_values = (
                    value["event_id"],
                    value["source_commit"],
                    value["receipt_written_utc"],
                    value["version"],
                    value["trigger"]["observed_monotonic_ns"],
                    workload["boot_id"],
                    workload["run_id"],
                    workload["unit"],
                    workload["cgroup"],
                    workload["name"],
                    workload["workload_uid"],
                    workload["cgroup_device"],
                    workload["cgroup_inode"],
                )
                if "receipt_path" in value:
                    excluded_values += (value["receipt_path"],)
                if "systemctl_stop_stderr" in cleanup:
                    excluded_values += (cleanup["systemctl_stop_stderr"],)
                if "offline_boundary_error" in cleanup:
                    excluded_values += (cleanup["offline_boundary_error"],)
                projection_serialized = json.dumps(projection, sort_keys=True)
                for excluded in excluded_values:
                    self.assertNotIn(str(excluded), serialized)
                    self.assertNotIn(str(excluded), projection_serialized)
                self.assertNotIn("/system.slice/", serialized)

    def test_handoff_nonzero_cleanup_return_is_bounded_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = self.write(
                directory,
                receipt(post_cleanup=True, response=True, cleanup_returncode=1),
            )
            output_path = Path(directory) / "handoff.json"
            with patch("lumi_eggcracker.kill_receipt.write_new_json") as write_new_json:
                self.assertEqual(
                    0,
                    main(
                        [
                            "prepare-kill-receipt-handoff",
                            str(receipt_path),
                            "--route",
                            "bug-report",
                            "--output",
                            str(output_path),
                        ]
                    ),
                )
            projection = write_new_json.call_args.args[1]
            self.assertEqual("ATTEMPTED_WITH_ERRORS", projection["cleanup_outcome"])

    def test_handoff_boundary_error_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = self.write(
                directory,
                receipt(post_cleanup=True, boundary_resolution_error=True),
            )
            output_path = Path(directory) / "handoff.json"
            with patch("lumi_eggcracker.kill_receipt.write_new_json") as write_new_json:
                self.assertEqual(
                    0,
                    main(
                        [
                            "prepare-kill-receipt-handoff",
                            str(receipt_path),
                            "--route",
                            "private-security",
                            "--output",
                            str(output_path),
                        ]
                    ),
                )
            projection = write_new_json.call_args.args[1]
            self.assertEqual("ATTEMPTED_WITH_ERRORS", projection["cleanup_outcome"])
            self.assertNotIn("boundary", json.dumps(projection))

    def test_handoff_rejects_bad_routes_and_outputs_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = self.write(directory, receipt())
            output_path = Path(directory) / "output-canary.json"
            with patch("lumi_eggcracker.kill_receipt.write_new_json") as write_new_json:
                self.assert_handoff_failure(
                    [
                        "prepare-kill-receipt-handoff",
                        str(receipt_path),
                        "--route",
                        "route-canary",
                        "--output",
                        str(output_path),
                    ]
                )
            write_new_json.assert_not_called()
            self.assertFalse(output_path.exists())

            invalid_parent = Path(directory) / "missing-parent" / "output.json"
            self.assert_handoff_failure(
                [
                    "prepare-kill-receipt-handoff",
                    str(receipt_path),
                    "--route",
                    "q-and-a",
                    "--output",
                    str(invalid_parent),
                ]
            )
            self.assertFalse(invalid_parent.exists())

            existing = Path(directory) / "existing.json"
            existing_bytes = b"existing-output-canary"
            existing.write_bytes(existing_bytes)
            self.assert_handoff_failure(
                [
                    "prepare-kill-receipt-handoff",
                    str(receipt_path),
                    "--route",
                    "bug-report",
                    "--output",
                    str(existing),
                ]
            )
            self.assertEqual(existing_bytes, existing.read_bytes())

    def test_handoff_preserves_raced_output_and_cleans_no_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = self.write(directory, receipt())
            raced = Path(directory) / "raced.json"
            raced_bytes = b"raced-existing-canary"
            owned_temps: list[Path] = []

            def race(temporary: str, destination: str) -> None:
                owned_temps.append(Path(temporary))
                Path(destination).write_bytes(raced_bytes)
                raise FileExistsError

            with patch("lumi_eggcracker.jsonio.os.link", side_effect=race):
                self.assert_handoff_failure(
                    [
                        "prepare-kill-receipt-handoff",
                        str(receipt_path),
                        "--route",
                        "q-and-a",
                        "--output",
                        str(raced),
                    ]
                )
            self.assertEqual(raced_bytes, raced.read_bytes())
            self.assertEqual(1, len(owned_temps))
            self.assertFalse(owned_temps[0].exists())

            failed = Path(directory) / "failed.json"
            failed_temps: list[Path] = []

            def fail(temporary: str, _destination: str) -> None:
                failed_temps.append(Path(temporary))
                raise OSError("write-canary")

            with patch("lumi_eggcracker.jsonio.os.link", side_effect=fail):
                self.assert_handoff_failure(
                    [
                        "prepare-kill-receipt-handoff",
                        str(receipt_path),
                        "--route",
                        "q-and-a",
                        "--output",
                        str(failed),
                    ]
                )
            self.assertFalse(failed.exists())
            self.assertEqual(1, len(failed_temps))
            self.assertFalse(failed_temps[0].exists())

    def test_handoff_real_publication_when_hard_links_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            probe_source = Path(directory) / "link-probe-source"
            probe_destination = Path(directory) / "link-probe-destination"
            probe_source.write_bytes(b"probe")
            try:
                os.link(probe_source, probe_destination)
            except OSError:
                if os.name == "nt":
                    self.skipTest(
                        "Windows F: filesystem does not support hard-link publication"
                    )
                raise
            finally:
                probe_destination.unlink(missing_ok=True)
                probe_source.unlink(missing_ok=True)

            if os.name == "nt":
                try:
                    directory_descriptor = os.open(
                        directory,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                    )
                    try:
                        os.fsync(directory_descriptor)
                    finally:
                        os.close(directory_descriptor)
                except OSError:
                    self.skipTest(
                        "Windows F: filesystem cannot fsync the publication directory"
                    )

            receipt_path = self.write(directory, receipt(post_cleanup=True, response=True))
            output_path = Path(directory) / "real-handoff.json"
            output = io.StringIO()
            error = io.StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                result = main(
                    [
                        "prepare-kill-receipt-handoff",
                        str(receipt_path),
                        "--route",
                        "q-and-a",
                        "--output",
                        str(output_path),
                    ]
                )
            if result != 0 and os.name == "nt":
                if output_path.exists():
                    self.assertEqual("HANDOFF_PREPARED", json.loads(output_path.read_text())["result"])
                    output_path.unlink()
                self.assertEqual([], list(Path(directory).glob(".real-handoff.json.*")))
                self.skipTest("Windows F: filesystem cannot complete atomic hard-link publication")
            self.assertEqual(0, result)
            self.assertEqual("", error.getvalue())
            self.assertEqual("HANDOFF_PREPARED", json.loads(output_path.read_text())["result"])
            self.assertEqual([], list(Path(directory).glob(".real-handoff.json.*")))

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
