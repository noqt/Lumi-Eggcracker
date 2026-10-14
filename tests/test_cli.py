from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.cli import main


def doctor_response(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "autonomous_discovery": True,
        "backend": "root-supervisor",
        "cgroup_v2": True,
        "catalogue": {"secret": "catalogue-canary"},
        "discovery": {
            "healthy": True,
            "receipt_persistence_healthy": True,
            "path": "/private/discovery-canary",
        },
        "execution_boundary": {"supported": True, "argv": ["argv-canary"]},
        "incidents": {"healthy": True, "lockdown": False, "secret": "incident-canary"},
        "installation": {"state": "HEALTHY", "path": "/private/install-canary"},
        "network": {
            "cleanup_healthy": True,
            "mode": "offline",
            "primitives": {"supported": True, "uid": "uid-canary"},
        },
        "pidfd": True,
        "result": "PASS",
        "version": "1.0.10",
        "workload_identity": {"healthy": True, "uid": 4242},
        "workload_uid": 4242,
    }
    value.update(overrides)
    return value


def wait_status(*, state: str = "RUNNING", run_id: str = "a" * 24) -> dict[str, object]:
    return {
        "exec_policy_digest": "0" * 64,
        "exec_policy_id": "legacy",
        "incident_lockdown": False,
        "name": "demo",
        "network_mode": "offline",
        "run_id": run_id,
        "state": state,
        "unit": f"lumi-eggcracker-workload-{run_id}.service",
        "workload_uid": 4242,
    }


class CliTests(unittest.TestCase):
    def test_version(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, main(["version"]))
        self.assertEqual("1.0.10", output.getvalue().strip())

    def test_public_help_has_only_supported_commands(self) -> None:
        from lumi_eggcracker.cli import _parser
        help_text = _parser().format_help()
        for command in (
            "start",
            "check-start",
            "kill",
            "status",
            "wait",
            "list",
            "history",
            "approve",
            "revoke",
            "approvals",
            "detections",
            "doctor",
            "support-bundle",
            "validate-support-bundle",
            "compare-detection-receipts",
            "version",
        ):
            self.assertIn(command, help_text)
        self.assertIn("exec-policy", help_text)
        self.assertNotIn("_supervisor", help_text)
        self.assertNotIn("network" + "-deny", help_text)
        self.assertIn(
            "retained terminal records in recorded monotonic order",
            " ".join(help_text.split()),
        )
        self.assertNotIn("recent", help_text)
        self.assertNotIn("chronological", help_text)
        doctor_help = io.StringIO()
        with redirect_stdout(doctor_help), self.assertRaises(SystemExit) as raised:
            main(["doctor", "--help"])
        self.assertEqual(0, raised.exception.code)
        self.assertIn("--recovery-plan", doctor_help.getvalue())

    def test_history_defaults_to_twenty_and_forwards_explicit_limit(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"runs": []}) as request:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["history"]))
            request.assert_called_once_with("history", limit=20)
            output.seek(0)
            self.assertEqual({"runs": []}, json.loads(output.read()))

        with patch("lumi_eggcracker.cli.request", return_value={"runs": []}) as request:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["history", "--limit", "7"]))
            request.assert_called_once_with("history", limit=7)

    def test_history_limit_rejects_invalid_duplicate_and_extra_arguments(self) -> None:
        cases = (
            ["history", "--limit", "0"],
            ["history", "--limit", "21"],
            ["history", "--limit", "true"],
            ["history", "--limit", "1.0"],
            ["history", "--limit", "1", "--limit", "2"],
            ["history", "--limit", "1", "unexpected"],
        )
        for values in cases:
            with self.subTest(values=values), patch(
                "lumi_eggcracker.cli.request"
            ) as request, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(values)
                self.assertEqual(2, raised.exception.code)
                request.assert_not_called()

    def test_doctor_summary_ready_is_fixed_and_nonidentifying(self) -> None:
        response = doctor_response()
        output = io.StringIO()
        error = io.StringIO()
        with (
            patch("lumi_eggcracker.cli.request", return_value=response) as request,
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(0, main(["doctor", "--summary"]))
        self.assertEqual(
            {
                "failed_checks": [],
                "next_action": "NONE",
                "result": "READY",
                "schema": "lumi-eggcracker.doctor-summary.v1",
            },
            json.loads(output.getvalue()),
        )
        self.assertEqual("", error.getvalue())
        self.assertNotIn("canary", output.getvalue())
        request.assert_called_once_with("doctor")

    def test_doctor_summary_mixed_failures_are_sorted_and_deduplicated(self) -> None:
        response = doctor_response(
            autonomous_discovery=False,
            cgroup_v2=False,
            execution_boundary={"supported": False},
            discovery={"healthy": False, "receipt_persistence_healthy": False},
            incidents={"healthy": False, "lockdown": True},
            installation={"state": "DRIFT"},
            network={
                "cleanup_healthy": False,
                "mode": "unsupported",
                "primitives": {"supported": False},
            },
            pidfd=False,
            result="UNSUPPORTED",
            workload_identity={"healthy": False},
        )
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.request", return_value=response), redirect_stdout(output):
            self.assertEqual(6, main(["doctor", "--summary"]))
        summary = json.loads(output.getvalue())
        self.assertEqual(
            [
                "cgroup_v2",
                "discovery",
                "execution_boundary",
                "incidents",
                "installation",
                "network_cleanup",
                "network_mode",
                "network_primitives",
                "pidfd",
                "receipt_persistence",
                "workload_identity",
            ],
            summary["failed_checks"],
        )
        self.assertEqual(len(summary["failed_checks"]), len(set(summary["failed_checks"])))
        self.assertEqual("NOT_READY", summary["result"])
        self.assertEqual("REVIEW_SUPERVISOR_READINESS", summary["next_action"])
        self.assertEqual(
            {"failed_checks", "next_action", "result", "schema"},
            set(summary),
        )
        self.assertNotIn("canary", output.getvalue())

    def test_doctor_summary_unsupported_without_visible_failure_is_honest(self) -> None:
        response = doctor_response(autonomous_discovery=False, result="UNSUPPORTED")
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.request", return_value=response), redirect_stdout(output):
            self.assertEqual(6, main(["doctor", "--summary"]))
        self.assertEqual(
            {
                "failed_checks": ["supervisor_readiness"],
                "next_action": "REVIEW_SUPERVISOR_READINESS",
                "result": "NOT_READY",
                "schema": "lumi-eggcracker.doctor-summary.v1",
            },
            json.loads(output.getvalue()),
        )

    def test_doctor_summary_malformed_or_contradictory_response_is_constant_error(self) -> None:
        malformed = [
            {},
            doctor_response(result=True),
            doctor_response(cgroup_v2="true"),
            doctor_response(network={"mode": "secret-path-canary"}),
            doctor_response(autonomous_discovery=False),
            doctor_response(autonomous_discovery=True, result="UNSUPPORTED"),
            doctor_response(incidents={"healthy": False, "lockdown": False}),
            doctor_response(installation={"state": "PRIVATE-CANARY"}),
        ]
        for response in malformed:
            with self.subTest(response=response):
                output = io.StringIO()
                error = io.StringIO()
                with (
                    patch("lumi_eggcracker.cli.request", return_value=response),
                    redirect_stdout(output),
                    redirect_stderr(error),
                ):
                    self.assertEqual(6, main(["doctor", "--summary"]))
                self.assertEqual("", output.getvalue())
                self.assertEqual("eggcracker: doctor summary unavailable\n", error.getvalue())
                self.assertNotIn("canary", error.getvalue())

        output = io.StringIO()
        error = io.StringIO()
        with patch("lumi_eggcracker.cli.request", side_effect=OSError("/private/CANARY")), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(6, main(["doctor", "--summary"]))
        self.assertEqual("", output.getvalue())
        self.assertEqual("eggcracker: doctor summary unavailable\n", error.getvalue())
        self.assertNotIn("CANARY", error.getvalue())

    def test_default_doctor_output_and_exit_remain_unchanged(self) -> None:
        for result, expected_exit in (("PASS", 0), ("UNSUPPORTED", 6)):
            with self.subTest(result=result):
                response = doctor_response(
                    autonomous_discovery=result == "PASS", result=result
                )
                output = io.StringIO()
                error = io.StringIO()
                with patch("lumi_eggcracker.cli.request", return_value=response), redirect_stdout(output), redirect_stderr(error):
                    self.assertEqual(expected_exit, main(["doctor"]))
                self.assertEqual(json.dumps(response, sort_keys=True) + "\n", output.getvalue())
                self.assertEqual("", error.getvalue())

    def test_doctor_recovery_plan_ready_is_closed_and_empty(self) -> None:
        response = doctor_response()
        output = io.StringIO()
        error = io.StringIO()
        with (
            patch("lumi_eggcracker.cli.request", return_value=response) as request,
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(0, main(["doctor", "--recovery-plan"]))
        self.assertEqual(
            {
                "actions": [],
                "failed_checks": [],
                "installation_state": "HEALTHY",
                "result": "READY",
                "schema": "lumi-eggcracker.doctor-recovery-plan.v1",
            },
            json.loads(output.getvalue()),
        )
        self.assertEqual("", error.getvalue())
        self.assertNotIn("canary", output.getvalue())
        request.assert_called_once_with("doctor")

    def test_doctor_recovery_plan_distinguishes_installation_states(self) -> None:
        expected_actions = {
            "NOT_INSTALLED": ["MANUAL_INSTALLATION_REQUIRED"],
            "DRIFT": ["MANUAL_INSTALLATION_REPAIR"],
            "RECOVERY_REQUIRED": ["MANUAL_INSTALLATION_RECOVERY"],
        }
        for state, actions in expected_actions.items():
            with self.subTest(state=state):
                output = io.StringIO()
                response = doctor_response(
                    autonomous_discovery=False,
                    installation={"state": state, "path": "/private/install-canary"},
                    result="UNSUPPORTED",
                )
                with (
                    patch("lumi_eggcracker.cli.request", return_value=response),
                    redirect_stdout(output),
                ):
                    self.assertEqual(6, main(["doctor", "--recovery-plan"]))
                plan = json.loads(output.getvalue())
                self.assertEqual(state, plan["installation_state"])
                self.assertEqual(["installation"], plan["failed_checks"])
                self.assertEqual(actions, plan["actions"])
                self.assertNotIn("canary", output.getvalue())

    def test_doctor_recovery_plan_hidden_readiness_is_manual_supervisor_review(self) -> None:
        response = doctor_response(autonomous_discovery=False, result="UNSUPPORTED")
        output = io.StringIO()
        with (
            patch("lumi_eggcracker.cli.request", return_value=response),
            redirect_stdout(output),
        ):
            self.assertEqual(6, main(["doctor", "--recovery-plan"]))
        self.assertEqual(
            {
                "actions": ["MANUAL_SUPERVISOR_REVIEW"],
                "failed_checks": ["supervisor_readiness"],
                "installation_state": "HEALTHY",
                "result": "NOT_READY",
                "schema": "lumi-eggcracker.doctor-recovery-plan.v1",
            },
            json.loads(output.getvalue()),
        )

    def test_doctor_recovery_plan_failures_are_sorted_and_deduplicated(self) -> None:
        response = doctor_response(
            autonomous_discovery=False,
            cgroup_v2=False,
            execution_boundary={"supported": False},
            discovery={"healthy": False, "receipt_persistence_healthy": False},
            incidents={"healthy": False, "lockdown": True},
            installation={"state": "DRIFT"},
            network={
                "cleanup_healthy": False,
                "mode": "unsupported",
                "primitives": {"supported": False},
            },
            pidfd=False,
            result="UNSUPPORTED",
            workload_identity={"healthy": False},
        )
        output = io.StringIO()
        with (
            patch("lumi_eggcracker.cli.request", return_value=response),
            redirect_stdout(output),
        ):
            self.assertEqual(6, main(["doctor", "--recovery-plan"]))
        plan = json.loads(output.getvalue())
        self.assertEqual(
            [
                "cgroup_v2",
                "discovery",
                "execution_boundary",
                "incidents",
                "installation",
                "network_cleanup",
                "network_mode",
                "network_primitives",
                "pidfd",
                "receipt_persistence",
                "workload_identity",
            ],
            plan["failed_checks"],
        )
        self.assertEqual(
            [
                "MANUAL_HOST_REVIEW",
                "MANUAL_IDENTITY_REVIEW",
                "MANUAL_INCIDENT_REVIEW",
                "MANUAL_INSTALLATION_REPAIR",
                "MANUAL_POLICY_REVIEW",
                "MANUAL_SUPERVISOR_REVIEW",
            ],
            plan["actions"],
        )
        self.assertEqual(len(plan["failed_checks"]), len(set(plan["failed_checks"])))
        self.assertEqual(len(plan["actions"]), len(set(plan["actions"])))

    def test_doctor_recovery_plan_malformed_or_transport_response_is_constant_error(self) -> None:
        malformed = [
            {},
            doctor_response(result=True),
            doctor_response(installation={"state": "PRIVATE-CANARY"}),
            doctor_response(autonomous_discovery=True, result="UNSUPPORTED"),
        ]
        for response in malformed:
            with self.subTest(response=response):
                output = io.StringIO()
                error = io.StringIO()
                with (
                    patch("lumi_eggcracker.cli.request", return_value=response),
                    redirect_stdout(output),
                    redirect_stderr(error),
                ):
                    self.assertEqual(6, main(["doctor", "--recovery-plan"]))
                self.assertEqual("", output.getvalue())
                self.assertEqual(
                    "eggcracker: doctor recovery plan unavailable\n", error.getvalue()
                )
                self.assertNotIn("canary", error.getvalue())

        output = io.StringIO()
        error = io.StringIO()
        with (
            patch("lumi_eggcracker.cli.request", side_effect=OSError("/private/CANARY")),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(6, main(["doctor", "--recovery-plan"]))
        self.assertEqual("", output.getvalue())
        self.assertEqual(
            "eggcracker: doctor recovery plan unavailable\n", error.getvalue()
        )
        self.assertNotIn("CANARY", error.getvalue())

    def test_doctor_projections_cannot_be_combined_before_transport(self) -> None:
        with (
            patch("lumi_eggcracker.cli.request") as request,
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            main(["doctor", "--summary", "--recovery-plan"])
        self.assertEqual(2, raised.exception.code)
        request.assert_not_called()

    def test_compare_detection_receipts_help_uses_installed_command(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["compare-detection-receipts", "--help"])
        self.assertEqual(0, raised.exception.code)
        self.assertIn("usage: eggcracker compare-detection-receipts", output.getvalue())
        self.assertIn("--before FILE", output.getvalue())
        self.assertIn("--after FILE", output.getvalue())

    def test_compare_detection_receipts_forwards_arguments_before_connected_commands(
        self,
    ) -> None:
        forwarded = [
            "--before",
            "before-export.json",
            "--after",
            "after-export.json",
            "--output",
            "comparison.json",
        ]
        with (
            patch(
                "lumi_eggcracker.cli.compare_detection_receipts_main", return_value=0
            ) as compare,
            patch("lumi_eggcracker.cli.request") as request,
            patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
            patch("lumi_eggcracker.cli.gate_main") as gate,
            patch("lumi_eggcracker.cli.watchdog_main") as watchdog,
        ):
            self.assertEqual(0, main(["compare-detection-receipts", *forwarded]))
        compare.assert_called_once_with(
            forwarded, prog="eggcracker compare-detection-receipts"
        )
        request.assert_not_called()
        supervisor.assert_not_called()
        gate.assert_not_called()
        watchdog.assert_not_called()

    def test_compare_detection_receipts_success_and_existing_output_refusal(self) -> None:
        def synthetic_export(event_id: str) -> dict[str, object]:
            return {
                "export_schema": "lumi-eggcracker.redacted-detection-receipt-export.v1",
                "source_sha256": "f" * 64,
                "authentication": "NOT_AUTHENTICATED",
                "live_verification": "NOT_PERFORMED",
                "receipt": {
                    "schema_version": "lumi-eggcracker.detection-receipt.v2",
                    "event_id": event_id,
                    "source_commit": "a" * 40,
                    "version": "1.0.10",
                    "catalogue_sha256": "b" * 64,
                    "receipt_written_utc": "2026-10-02T00:00:00Z",
                    "detector": {
                        "profile": "content.gguf-llama",
                        "detection_path": "CONTENT",
                        "catalogue_schema": "lumi-eggcracker.detectors.v3",
                    },
                    "trigger": {"kind": "UNAPPROVED_AI_MATCH"},
                    "recorded_result": "CONTAINMENT_FAILED",
                },
            }

        with tempfile.TemporaryDirectory(prefix="cli-receipt-comparison-") as directory:
            root = Path(directory)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(synthetic_export("0" * 24)), encoding="utf-8")
            after.write_text(json.dumps(synthetic_export("1" * 24)), encoding="utf-8")
            output = root / "existing-comparison.json"
            original_output = b"preserve this synthetic report\n"
            output.write_bytes(original_output)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch("lumi_eggcracker.cli.request") as request,
                patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                self.assertEqual(
                    0,
                    main(
                        [
                            "compare-detection-receipts",
                            "--before",
                            str(before),
                            "--after",
                            str(after),
                        ]
                    ),
                )
                comparison = json.loads(stdout.getvalue())
                self.assertEqual("RECORDED", comparison["comparison_status"])
                self.assertEqual("", stderr.getvalue())
                stdout.seek(0)
                stdout.truncate(0)
                stderr.seek(0)
                stderr.truncate(0)
                self.assertEqual(
                    1,
                    main(
                        [
                            "compare-detection-receipts",
                            "--before",
                            str(before),
                            "--after",
                            str(after),
                            "--output",
                            str(output),
                        ]
                    ),
                )
                self.assertEqual("", stdout.getvalue())
                self.assertIn("OUTPUT_ALREADY_EXISTS", stderr.getvalue())
                request.assert_not_called()
                supervisor.assert_not_called()
            self.assertEqual(original_output, output.read_bytes())

    def test_validate_support_bundle_dispatches_before_connected_commands(self) -> None:
        with (
            patch("lumi_eggcracker.cli.validate_support_bundle_main", return_value=0) as validate,
            patch("lumi_eggcracker.cli.request") as request,
            patch("lumi_eggcracker.cli.supervisor_main") as supervisor,
            patch("lumi_eggcracker.cli.gate_main") as gate,
            patch("lumi_eggcracker.cli.watchdog_main") as watchdog,
        ):
            self.assertEqual(
                0,
                main(["validate-support-bundle", "private-name-must-not-be-echoed.json"]),
            )
        validate.assert_called_once_with(["private-name-must-not-be-echoed.json"])
        request.assert_not_called()
        supervisor.assert_not_called()
        gate.assert_not_called()
        watchdog.assert_not_called()

    def test_internal_supervisor_dispatch_remains_available(self) -> None:
        with patch("lumi_eggcracker.cli.supervisor_main", return_value=7) as supervisor:
            self.assertEqual(main(["_supervisor", "--policy", "/tmp/policy.json"]), 7)
        supervisor.assert_called_once_with(["--policy", "/tmp/policy.json"])

    def test_approve_forwards_only_exact_command_arguments(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=0, create=True), patch("lumi_eggcracker.cli.request", return_value={"result": "APPROVED"}) as request:
            self.assertEqual(0, main(["approve", "--name", "qwen", "--uid", "1001", "--", "/opt/llama-cli", "-m", "/models/qwen.gguf"]))
        request.assert_called_once_with(
            "approve",
            name="qwen",
            uid=1001,
            max_pids=64,
            max_memory_mib=2048,
            cpu_quota_percent=400,
            allow_interface_discovery=False,
            argv=["/opt/llama-cli", "-m", "/models/qwen.gguf"],
        )

    def test_approve_can_grant_interface_discovery(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=0, create=True), patch("lumi_eggcracker.cli.request", return_value={"result": "APPROVED"}) as request:
            self.assertEqual(0, main(["approve", "--name", "qwen", "--uid", "1001", "--allow-interface-discovery", "--", "/opt/llama-cli", "-m", "/models/qwen.gguf"]))
        self.assertTrue(request.call_args.kwargs["allow_interface_discovery"])

    def test_start_includes_resource_limits(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(0, main(["start", "--name", "demo", "--max-pids", "8", "--", "/bin/sleep", "1"]))
        request.assert_called_once_with(
            "start", name="demo", max_pids=8, max_memory_mib=2048,
            cpu_quota_percent=400, argv=["/bin/sleep", "1"],
        )

    def test_start_forwards_selected_execution_policy(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(0, main(["start", "--name", "demo", "--exec-policy", "a" * 24, "--max-pids", "8", "--", "/bin/sleep", "1"]))
        request.assert_called_once_with(
            "start", name="demo", max_pids=8, max_memory_mib=2048,
            cpu_quota_percent=400, argv=["/bin/sleep", "1"], exec_policy="a" * 24,
        )

    def test_start_can_require_exact_approval_at_admission_time(self) -> None:
        with patch("lumi_eggcracker.cli.request", return_value={"result": "STARTED"}) as request:
            self.assertEqual(
                0,
                main(
                    [
                        "start",
                        "--name",
                        "demo",
                        "--max-pids",
                        "8",
                        "--require-approval",
                        "--",
                        "/bin/sleep",
                        "1",
                    ]
                ),
            )
        request.assert_called_once_with(
            "start",
            name="demo",
            max_pids=8,
            max_memory_mib=2048,
            cpu_quota_percent=400,
            argv=["/bin/sleep", "1"],
            require_approval=True,
        )

    def test_check_start_forwards_exact_tuple_and_emits_fixed_projection(self) -> None:
        response = {
            "next_action": (
                "run start --require-approval immediately; admission is revalidated"
            ),
            "reason_code": "EXACT_APPROVAL_MATCHED",
            "result": "READY_TO_ATTEMPT",
            "schema": "lumi-eggcracker.check-start.v1",
        }
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.request", return_value=response) as request, redirect_stdout(output):
            self.assertEqual(
                0,
                main(
                    [
                        "check-start",
                        "--name",
                        "demo",
                        "--max-pids",
                        "8",
                        "--max-memory-mib",
                        "4096",
                        "--cpu-quota-percent",
                        "700",
                        "--exec-policy",
                        "a" * 24,
                        "--",
                        "/bin/sleep",
                        "1",
                    ]
                ),
            )
        request.assert_called_once_with(
            "check_start",
            name="demo",
            max_pids=8,
            max_memory_mib=4096,
            cpu_quota_percent=700,
            argv=["/bin/sleep", "1"],
            exec_policy="a" * 24,
        )
        self.assertEqual(response, json.loads(output.getvalue()))

    def test_check_start_malformed_or_transport_response_is_constant_safe_error(self) -> None:
        cases = (
            {"result": "READY_TO_ATTEMPT", "name": "/private/name"},
            {
                "next_action": "raw /private/path",
                "reason_code": "EXACT_APPROVAL_MATCHED",
                "result": "READY_TO_ATTEMPT",
                "schema": "lumi-eggcracker.check-start.v1",
            },
        )
        for response in (*cases, OSError("/private/socket")):
            with self.subTest(response=response):
                output = io.StringIO()
                error = io.StringIO()
                with patch(
                    "lumi_eggcracker.cli.request",
                    side_effect=response if isinstance(response, BaseException) else None,
                    return_value=None if isinstance(response, BaseException) else response,
                ) as request, redirect_stdout(output), redirect_stderr(error):
                    self.assertEqual(
                        4,
                        main(
                            [
                                "check-start",
                                "--name",
                                "demo",
                                "--max-pids",
                                "8",
                                "--",
                                "/private/executable",
                            ]
                        ),
                    )
                self.assertEqual("", output.getvalue())
                self.assertEqual(
                    "eggcracker: check-start response unavailable\n",
                    error.getvalue(),
                )
                self.assertNotIn("/private", error.getvalue())
                request.assert_called_once()

    def test_check_start_parse_failure_is_constant_and_excludes_canary(self) -> None:
        output = io.StringIO()
        error = io.StringIO()
        with patch("lumi_eggcracker.cli.request") as request, redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(
                4,
                main(
                    [
                        "check-start",
                        "--name",
                        "demo",
                        "--max-pids",
                        "/private/parse-canary",
                        "--",
                        "/private/executable-canary",
                    ]
                ),
            )
        self.assertEqual("", output.getvalue())
        self.assertEqual(
            "eggcracker: check-start response unavailable\n",
            error.getvalue(),
        )
        self.assertNotIn("/private", error.getvalue())
        request.assert_not_called()

    def test_check_start_not_ready_is_a_nonzero_snapshot_result(self) -> None:
        response = {
            "next_action": (
                "create or restore the exact root approval for this tuple, then check again"
            ),
            "reason_code": "APPROVAL_MISSING",
            "result": "NOT_READY",
            "schema": "lumi-eggcracker.check-start.v1",
        }
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.request", return_value=response), redirect_stdout(output):
            self.assertEqual(
                6,
                main(
                    [
                        "check-start",
                        "--name",
                        "demo",
                        "--max-pids",
                        "8",
                        "--",
                        "/bin/sleep",
                        "1",
                    ]
                ),
            )
        self.assertEqual(response, json.loads(output.getvalue()))

    def test_wait_immediate_terminal_emits_fixed_marker_and_validated_state(self) -> None:
        response = wait_status(state="TERMINATED")
        output = io.StringIO()
        error = io.StringIO()
        with patch("lumi_eggcracker.cli.time.monotonic", return_value=10.0), patch(
            "lumi_eggcracker.cli.request_before", return_value=response
        ) as request_before, patch("lumi_eggcracker.cli.time.sleep") as sleep, redirect_stdout(
            output
        ), redirect_stderr(error):
            self.assertEqual(0, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        self.assertEqual("TERMINAL\n", output.getvalue().splitlines()[0] + "\n")
        self.assertEqual(response, json.loads(output.getvalue().splitlines()[1]))
        self.assertEqual("", error.getvalue())
        request_before.assert_called_once_with(
            "status", deadline_monotonic=11.0, name="demo"
        )
        sleep.assert_not_called()

    def test_wait_active_to_terminal_pins_run_id_and_uses_bounded_sleep(self) -> None:
        active = wait_status()
        terminal = wait_status(state="CONTAINMENT_FAILED")
        output = io.StringIO()
        with patch(
            "lumi_eggcracker.cli.time.monotonic",
            side_effect=[10.0, 10.0, 10.1, 10.1, 10.2, 10.2],
        ), patch(
            "lumi_eggcracker.cli.request_before", side_effect=[active, terminal]
        ) as request_before, patch("lumi_eggcracker.cli.time.sleep") as sleep, redirect_stdout(
            output
        ):
            self.assertEqual(0, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        self.assertEqual("TERMINAL", output.getvalue().splitlines()[0])
        self.assertEqual(terminal, json.loads(output.getvalue().splitlines()[1]))
        self.assertEqual(2, request_before.call_count)
        self.assertEqual([((0.1,), {})], sleep.call_args_list)
        for call in request_before.call_args_list:
            self.assertEqual("status", call.args[0])
            self.assertEqual(11.0, call.kwargs["deadline_monotonic"])
            self.assertEqual("demo", call.kwargs["name"])

    def test_wait_timeout_emits_last_validated_state_without_postdeadline_request(self) -> None:
        active = wait_status()
        output = io.StringIO()
        with patch(
            "lumi_eggcracker.cli.time.monotonic",
            side_effect=[0.0, 0.0, 0.1, 0.1, 1.0],
        ), patch("lumi_eggcracker.cli.request_before", return_value=active) as request_before, patch(
            "lumi_eggcracker.cli.time.sleep"
        ) as sleep, redirect_stdout(output):
            self.assertEqual(6, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        self.assertEqual("TIMED_OUT", output.getvalue().splitlines()[0])
        self.assertEqual(active, json.loads(output.getvalue().splitlines()[1]))
        request_before.assert_called_once()
        sleep.assert_called_once_with(0.1)

    def test_wait_inflight_deadline_is_timeout_without_inventing_state(self) -> None:
        output = io.StringIO()
        with patch("lumi_eggcracker.cli.time.monotonic", return_value=10.0), patch(
            "lumi_eggcracker.cli.request_before", side_effect=TimeoutError
        ) as request_before, redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(6, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        self.assertEqual("TIMED_OUT\n", output.getvalue())
        request_before.assert_called_once()

    def test_wait_fails_closed_for_drift_malformed_unknown_and_nonmonotonic_results(self) -> None:
        cases = (
            ({**wait_status(), "extra": True}, "extra field"),
            ({**wait_status(), "state": "UNKNOWN"}, "unknown state"),
            ({**wait_status(), "name": "other"}, "name drift"),
        )
        for response, label in cases:
            with self.subTest(label=label):
                output = io.StringIO()
                error = io.StringIO()
                with patch("lumi_eggcracker.cli.time.monotonic", return_value=10.0), patch(
                    "lumi_eggcracker.cli.request_before", return_value=response
                ), redirect_stdout(output), redirect_stderr(error):
                    self.assertEqual(
                        4, main(["wait", "--name", "demo", "--timeout-seconds", "1"])
                    )
                self.assertEqual("", output.getvalue())
                self.assertEqual("ERROR\n", error.getvalue())

        first = wait_status()
        second = wait_status(state="TERMINATED", run_id="b" * 24)
        output = io.StringIO()
        error = io.StringIO()
        with patch(
            "lumi_eggcracker.cli.time.monotonic",
            side_effect=[10.0, 10.0, 10.0, 10.0, 10.1, 10.1],
        ), patch(
            "lumi_eggcracker.cli.request_before", side_effect=[first, second]
        ) as request_before, patch("lumi_eggcracker.cli.time.sleep"), redirect_stdout(
            output
        ), redirect_stderr(error):
            self.assertEqual(4, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        self.assertEqual(2, request_before.call_count)
        self.assertEqual("", output.getvalue())
        self.assertEqual("ERROR\n", error.getvalue())

        output = io.StringIO()
        error = io.StringIO()
        with patch(
            "lumi_eggcracker.cli.time.monotonic", side_effect=[10.0, 9.0]
        ), patch("lumi_eggcracker.cli.request_before") as request_before, redirect_stdout(
            output
        ), redirect_stderr(error):
            self.assertEqual(4, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
        request_before.assert_not_called()
        self.assertEqual("", output.getvalue())
        self.assertEqual("ERROR\n", error.getvalue())

    def test_wait_timeout_argument_is_bounded_and_does_not_request(self) -> None:
        for timeout in ("0", "301", "1.0", "true"):
            with self.subTest(timeout=timeout), patch(
                "lumi_eggcracker.cli.request_before"
            ) as request_before, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["wait", "--name", "demo", "--timeout-seconds", timeout])
                self.assertEqual(2, raised.exception.code)
                request_before.assert_not_called()
        with patch("lumi_eggcracker.cli.request_before") as request_before, redirect_stderr(
            io.StringIO()
        ):
            with self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "wait",
                        "--name",
                        "demo",
                        "--timeout-seconds",
                        "1",
                        "--timeout-seconds",
                        "2",
                    ]
                )
            self.assertEqual(2, raised.exception.code)
            request_before.assert_not_called()

    def test_wait_uses_only_status_action_and_existing_status_still_uses_request(self) -> None:
        terminal = wait_status(state="COMPLETED_ALLOWED")
        with patch("lumi_eggcracker.cli.time.monotonic", return_value=10.0), patch(
            "lumi_eggcracker.cli.request_before", return_value=terminal
        ) as request_before, patch(
            "lumi_eggcracker.cli.request", return_value={"state": "RUNNING"}
        ) as request:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["wait", "--name", "demo", "--timeout-seconds", "1"]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["status", "--name", "demo"]))
        request_before.assert_called_once()
        self.assertEqual("status", request_before.call_args.args[0])
        request.assert_called_once_with("status", name="demo")

    def test_execution_policy_create_requires_root(self) -> None:
        with patch("lumi_eggcracker.cli.os.geteuid", return_value=1001, create=True):
            self.assertEqual(4, main(["exec-policy", "create", "--name", "demo", "--", "/bin/sh"]))

    def test_duplicate_identifier_options_are_rejected_before_request(self) -> None:
        policy_a = "a" * 24
        policy_b = "b" * 24
        cases = (
            ["start", "--name", "first", "--name", "second", "--max-pids", "8", "--", "/bin/true"],
            ["start", "--name", "demo", "--exec-policy", policy_a, "--exec-policy", policy_b, "--max-pids", "8", "--", "/bin/true"],
            ["kill", "--name", "first", "--name", "second", "--receipt", "/tmp/receipt.json"],
            ["status", "--name", "first", "--name", "second"],
            ["approve", "--name", "first", "--name", "second", "--uid", "1001", "--", "/bin/true"],
            ["revoke", "--name", "first", "--name", "second"],
            ["exec-policy", "create", "--name", "first", "--name", "second", "--", "/bin/true"],
            ["exec-policy", "revoke", "--policy-id", policy_a, "--policy-id", policy_b],
        )
        for values in cases:
            with self.subTest(values=values), patch(
                "lumi_eggcracker.cli.request"
            ) as request, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(values)
                self.assertEqual(2, raised.exception.code)
                request.assert_not_called()
