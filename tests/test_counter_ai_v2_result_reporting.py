"""Pure reporting checks for the off-by-default v2 native demonstration."""

from __future__ import annotations

import contextlib
import io
import json
import unittest
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from experiments.counter_ai_v2 import native_demo


def _success_result() -> dict[str, Any]:
    canary_report = {"role": "canary", "generation": 1, "state": "RUNNING"}
    return {
        "schema": native_demo.SCHEMA,
        "status": "PASS",
        "canary": {
            "self_report_before": dict(canary_report),
            "self_report_after_target_stop": dict(canary_report),
            "self_report_after": dict(canary_report),
            "continued_during_stop": True,
            "heartbeat_bytes_before": 100,
            "heartbeat_bytes_during_target_stop": 200,
            "heartbeat_bytes_after": 225,
            "separate_uid": True,
        },
        "resource_accounting": {"canary_stopped_after_observation": True},
        "cleanup": {"complete": True, "errors": []},
    }


def _execute_args() -> list[str]:
    return [
        "--execute",
        "--run-dir",
        "synthetic-run",
        "--workload-script",
        "synthetic-workload.py",
        "--run-id",
        "synthetic-run-id",
        "--nonce",
        "1" * 32,
        "--hazard-acceptance",
        "synthetic-acceptance.json",
        "--native-script",
        "synthetic-native-demo.py",
        "--source-manifest",
        "synthetic-source.json",
        "--artifact-manifest",
        "synthetic-artifact.json",
    ]


class ResultReportingTests(unittest.TestCase):
    def test_complete_consistent_evidence_retains_pass(self) -> None:
        result = _success_result()

        reported = native_demo._aggregate_reporting_result(result)

        self.assertEqual(reported["status"], "PASS")
        self.assertEqual(result["status"], "PASS")
        self.assertIsNot(reported, result)

    def test_incomplete_or_contradictory_evidence_downgrades_pass(self) -> None:
        cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
            ("false continuation", lambda value: value["canary"].update(continued_during_stop=False)),
            ("missing continuation", lambda value: value["canary"].pop("continued_during_stop")),
            ("malformed continuation", lambda value: value["canary"].update(continued_during_stop="true")),
            (
                "counter contradicts continuation",
                lambda value: value["canary"].update(heartbeat_bytes_during_target_stop=100),
            ),
            ("negative heartbeat count", lambda value: value["canary"].update(heartbeat_bytes_before=-1)),
            ("boolean heartbeat count", lambda value: value["canary"].update(heartbeat_bytes_after=True)),
            ("missing observation report", lambda value: value["canary"].pop("self_report_after_target_stop")),
            (
                "contradictory report generation",
                lambda value: value["canary"]["self_report_after_target_stop"].update(generation=2),
            ),
            ("canary identity not separate", lambda value: value["canary"].update(separate_uid=False)),
            (
                "canary stop not observed",
                lambda value: value["resource_accounting"].update(canary_stopped_after_observation=False),
            ),
            ("incomplete cleanup", lambda value: value["cleanup"].update(complete=False)),
            ("missing cleanup", lambda value: value.pop("cleanup")),
            (
                "cleanup flag contradicts errors",
                lambda value: value["cleanup"].update(errors=["resource remains"]),
            ),
            ("malformed cleanup errors", lambda value: value["cleanup"].update(errors=None)),
        )

        for label, mutate in cases:
            with self.subTest(evidence=label):
                result = _success_result()
                mutate(result)

                reported = native_demo._aggregate_reporting_result(result)

                self.assertEqual(reported["status"], "UNKNOWN")
                self.assertEqual(result["status"], "PASS")

    def test_execute_cli_returns_nonzero_for_unverified_success(self) -> None:
        result = _success_result()
        result["canary"]["continued_during_stop"] = False
        output = io.StringIO()

        with (
            patch.object(native_demo, "_load_acceptance", return_value={}),
            patch.object(native_demo, "run_demo", return_value=result) as native_entry,
            contextlib.redirect_stdout(output),
        ):
            exit_code = native_demo.main(_execute_args())

        self.assertEqual(exit_code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")
        native_entry.assert_called_once()

    def test_execute_cli_keeps_zero_for_complete_positive_evidence(self) -> None:
        output = io.StringIO()

        with (
            patch.object(native_demo, "_load_acceptance", return_value={}),
            patch.object(native_demo, "run_demo", return_value=_success_result()) as native_entry,
            contextlib.redirect_stdout(output),
        ):
            exit_code = native_demo.main(_execute_args())

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "PASS")
        native_entry.assert_called_once()

    def test_off_by_default_cli_remains_inert_and_successful(self) -> None:
        output = io.StringIO()

        with (
            patch.object(native_demo, "run_demo", side_effect=AssertionError("native entry invoked")) as native_entry,
            contextlib.redirect_stdout(output),
        ):
            exit_code = native_demo.main([])

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "OFF_BY_DEFAULT")
        native_entry.assert_not_called()


if __name__ == "__main__":
    unittest.main()
