from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lumi_eggcracker.brokered import BrokeredOperator, linux_ipc
from lumi_eggcracker.brokered import operator as brokered_operator
from scripts import brokered_operator_demo


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class BrokeredLinuxProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=tempfile.gettempdir())
        self.addCleanup(self.temporary.cleanup)
        state_directory = Path(self.temporary.name) / "state"
        self.operator, self.grant = BrokeredOperator._open_or_bootstrap_service(state_directory)
        self.workload_uid = 24680
        if sys.platform == "linux" and self.workload_uid == os.geteuid():
            self.workload_uid += 1
        self.service_uid = 13579
        if self.service_uid == self.workload_uid:
            self.service_uid += 1
        self.service = linux_ipc.BrokeredLinuxService._for_trusted_test(
            self.operator,
            self.grant,
            workload_uid=self.workload_uid,
            workload_gid=24681,
            service_uid=self.service_uid,
        )

    def request(self, operation: str, **fields: object) -> bytes:
        return canonical(
            {"op": operation, "schema_version": linux_ipc.IPC_SCHEMA, **fields}
        )

    def response(self, raw: bytes, *, peer_uid: int | None = None) -> dict[str, object]:
        result = self.service.handle_packet(
            self.workload_uid if peer_uid is None else peer_uid,
            raw,
        )
        return linux_ipc._parse_response(result)

    def receipt(self, response: dict[str, object]) -> dict[str, object]:
        receipt = response.get("receipt")
        self.assertIsInstance(receipt, dict)
        return receipt

    def test_strict_protocol_rejects_unknown_duplicate_bool_malformed_and_oversize(self) -> None:
        valid = self.request("submit", operation_id="strict-1")
        unknown = self.request("submit", operation_id="strict-2", target="/private/file")
        duplicate = valid.replace(b'"op":"submit",', b'"op":"submit","op":"submit",')
        bool_queue = self.request("dispatch", queue_id=True)
        cases = (
            (unknown, "UNKNOWN_FIELDS"),
            (duplicate, "MALFORMED_INPUT"),
            (bool_queue, "MALFORMED_INPUT"),
            (b'{"broken":', "MALFORMED_INPUT"),
            (b" " * (linux_ipc.MAX_IPC_REQUEST_BYTES + 1), "MALFORMED_INPUT"),
            (valid.rstrip(b"\n"), "NON_CANONICAL_INPUT"),
            (
                canonical(
                    {
                        "action": "increment",
                        "capability": "caller-minted",
                        "generation": 0,
                        "op": "submit",
                        "operation_id": "strict-3",
                        "run_id": self.grant.run_id,
                        "schema_version": linux_ipc.IPC_SCHEMA,
                    }
                ),
                "UNKNOWN_FIELDS",
            ),
        )
        for raw, code in cases:
            with self.subTest(code=code, size=len(raw)):
                result = self.response(raw)
                self.assertEqual("protocol", result["phase"])
                self.assertEqual("DENIED", result["outcome"])
                self.assertEqual(code, result["code"])
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)

    def test_peer_identity_denial_precedes_parse_and_effect(self) -> None:
        result = self.response(b"not-json", peer_uid=self.workload_uid + 1)
        self.assertEqual("PEER_IDENTITY", result["code"])
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)

    def test_service_only_construction_and_fixed_result_workflow(self) -> None:
        with self.assertRaises(PermissionError):
            linux_ipc.BrokeredLinuxService(
                self.operator,
                self.grant,
                Path("/tmp/unused.sock"),
                self.workload_uid,
                24681,
                0,
            )

        self.assertFalse(hasattr(linux_ipc, "_SYNTHETIC_DATASET"))
        self.assertFalse(hasattr(linux_ipc, "_fixed_work_report"))
        admitted = self.receipt(
            self.response(self.request("submit", operation_id="research-batch-1"))
        )
        self.assertEqual(("admission", "QUEUED", "ADMITTED"), (admitted["phase"], admitted["outcome"], admitted["code"]))
        queue_id = admitted["queue_id"]
        self.assertEqual("NOT_FOUND", self.response(self.request("get_result", queue_id=queue_id))["code"])
        applied = self.receipt(self.response(self.request("dispatch", queue_id=queue_id)))
        self.assertEqual(("dispatch", "APPLIED", "EFFECT_APPLIED"), (applied["phase"], applied["outcome"], applied["code"]))
        self.assertTrue(applied["effect_applied"])

        available = self.response(self.request("get_result", queue_id=queue_id))
        self.assertEqual("AVAILABLE", available["outcome"])
        self.assertTrue(linux_ipc._valid_report(available["report"]))
        self.assertEqual(available["report"], self.operator._result_for_run(queue_id, self.grant.run_id))
        self.assertLessEqual(
            len(canonical(available["report"])),
            linux_ipc.MAX_RESULT_BYTES,
        )
        self.assertEqual(
            "REPLAY",
            self.receipt(
                self.response(self.request("submit", operation_id="research-batch-1"))
            )["code"],
        )
        self.assertEqual(
            "REPLAY",
            self.receipt(self.response(self.request("dispatch", queue_id=queue_id)))["code"],
        )
        snapshot = self.operator.world_snapshot()
        self.assertEqual(1, snapshot.protected_effects)
        self.assertEqual(73, snapshot.unrelated_canary_allocation)

        _, reopened = BrokeredOperator.open(Path(self.temporary.name) / "state")
        resumed_grant = reopened._service_run_grant()
        reopened_service = linux_ipc.BrokeredLinuxService._for_trusted_test(
            reopened,
            resumed_grant,
            workload_uid=self.workload_uid,
            workload_gid=24681,
            service_uid=self.service_uid,
        )
        after_reopen = linux_ipc._parse_response(
            reopened_service.handle_packet(
                self.workload_uid,
                self.request("get_result", queue_id=queue_id),
            )
        )
        self.assertEqual("AVAILABLE", after_reopen["outcome"])
        self.assertEqual(1, reopened.world_snapshot().protected_effects)

    def test_stop_fence_stale_queue_and_single_run_survive_reopen(self) -> None:
        completed = self.receipt(
            self.response(self.request("submit", operation_id="applied-before-stop"))
        )
        completed_queue_id = completed["queue_id"]
        self.receipt(self.response(self.request("dispatch", queue_id=completed_queue_id)))
        applied_report = self.response(self.request("get_result", queue_id=completed_queue_id))["report"]
        queued = self.receipt(
            self.response(self.request("submit", operation_id="queued-before-stop"))
        )
        queue_id = queued["queue_id"]
        stopped = self.service.request_stop()
        self.assertEqual(("REVOKED", 1, "UNSUPPORTED"), (stopped.outcome, stopped.generation, stopped.process_stop))
        stale = self.receipt(self.response(self.request("dispatch", queue_id=queue_id)))
        self.assertEqual("STALE_GENERATION", stale["code"])
        self.assertEqual(
            "CAPABILITY_REVOKED",
            self.receipt(
                self.response(self.request("submit", operation_id="post-stop"))
            )["code"],
        )
        self.assertEqual("NOT_FOUND", self.response(self.request("get_result", queue_id=queue_id))["code"])

        _, reopened = BrokeredOperator.open(Path(self.temporary.name) / "state")
        resumed_grant = reopened._service_run_grant()
        self.assertEqual(self.grant.run_id, resumed_grant.run_id)
        reopened_service = linux_ipc.BrokeredLinuxService._for_trusted_test(
            reopened,
            resumed_grant,
            workload_uid=self.workload_uid,
            workload_gid=24681,
            service_uid=self.service_uid,
        )
        self.assertEqual(
            "ALREADY_FINAL",
            self.receipt(
                linux_ipc._parse_response(
                    reopened_service.handle_packet(
                        self.workload_uid,
                        self.request("dispatch", queue_id=queue_id),
                    )
                )
            )["code"],
        )
        self.assertEqual(
            "CAPABILITY_REVOKED",
            self.receipt(
                linux_ipc._parse_response(
                    reopened_service.handle_packet(
                        self.workload_uid,
                        self.request("submit", operation_id="after-reopen"),
                    )
                )
            )["code"],
        )
        reopened_result = linux_ipc._parse_response(
            reopened_service.handle_packet(
                self.workload_uid,
                self.request("get_result", queue_id=completed_queue_id),
            )
        )
        self.assertEqual("AVAILABLE", reopened_result["outcome"])
        self.assertEqual(applied_report, reopened_result["report"])
        self.assertEqual(1, reopened.world_snapshot().protected_effects)
        self.assertEqual(73, reopened.world_snapshot().unrelated_canary_allocation)

    def test_direct_bypass_requests_are_denied_before_effect(self) -> None:
        for operation in ("get_dataset", "trusted_stop", "read_state"):
            with self.subTest(operation=operation):
                response = self.response(self.request(operation, path="/private/state"))
                self.assertEqual("DENIED", response["outcome"])
                self.assertIn(response["code"], {"MALFORMED_INPUT", "UNKNOWN_FIELDS"})
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)


class BrokeredLinuxOneShotCLITests(unittest.TestCase):
    queue_id = "a" * 32
    other_queue_id = "b" * 32

    @staticmethod
    def receipt(
        *,
        phase: str,
        outcome: str,
        code: str,
        effect_applied: bool,
        queue_id: str | None = None,
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "code": code,
            "effect_applied": effect_applied,
            "outcome": outcome,
            "phase": phase,
        }
        if queue_id is not None:
            value["queue_id"] = queue_id
        return {"receipt": value, "schema_version": linux_ipc.IPC_SCHEMA}

    @staticmethod
    def result(*, queue_id: str | None = None) -> dict[str, object]:
        value: dict[str, object] = {
            "outcome": "AVAILABLE",
            "phase": "result",
            "report": {
                "accepted": 2,
                "dataset_id": "synthetic.research-batch.v1",
                "dataset_sha256": "c" * 64,
                "records_checked": 4,
                "review": 2,
                "units_total": 32,
            },
            "schema_version": linux_ipc.IPC_SCHEMA,
        }
        if queue_id is not None:
            value["queue_id"] = queue_id
        return value

    def invoke(
        self,
        responses: dict[str, object],
    ) -> tuple[int, list[tuple[object, ...]], str, str, mock.Mock]:
        calls: list[tuple[object, ...]] = []

        class FakeClient:
            def _call(self, stage: str, *arguments: object) -> object:
                calls.append((stage, *arguments))
                response = responses[stage]
                if isinstance(response, Exception):
                    raise response
                return response

            def submit(self, operation_id: str) -> object:
                return self._call("submit", operation_id)

            def dispatch(self, queue_id: str) -> object:
                return self._call("dispatch", queue_id)

            def get_result(self, queue_id: str) -> object:
                return self._call("get_result", queue_id)

        fake_client = FakeClient()
        standard_output = io.StringIO()
        standard_error = io.StringIO()
        arguments = [
            "--linux-ipc",
            "run",
            "--socket",
            "/tmp/fake-broker.sock",
            "--service-uid",
            "1200",
            "--operation-id",
            "cli-run-1",
        ]
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(brokered_operator_demo.os, "geteuid", return_value=1201, create=True),
            mock.patch.object(linux_ipc, "BrokeredLinuxClient", return_value=fake_client) as constructor,
            contextlib.redirect_stdout(standard_output),
            contextlib.redirect_stderr(standard_error),
        ):
            status = brokered_operator_demo.main(arguments)
        return status, calls, standard_output.getvalue(), standard_error.getvalue(), constructor

    def successful_responses(self) -> dict[str, object]:
        return {
            "submit": self.receipt(
                phase="admission",
                outcome="QUEUED",
                code="ADMITTED",
                effect_applied=False,
                queue_id=self.queue_id,
            ),
            "dispatch": self.receipt(
                phase="dispatch",
                outcome="APPLIED",
                code="EFFECT_APPLIED",
                effect_applied=True,
                queue_id=self.queue_id,
            ),
            "get_result": self.result(queue_id=self.queue_id),
        }

    def test_run_calls_each_primitive_once_and_emits_one_combined_outcome(self) -> None:
        responses = self.successful_responses()
        status, calls, standard_output, standard_error, constructor = self.invoke(responses)

        self.assertEqual(0, status)
        self.assertEqual(
            [
                ("submit", "cli-run-1"),
                ("dispatch", self.queue_id),
                ("get_result", self.queue_id),
            ],
            calls,
        )
        constructor.assert_called_once_with("/tmp/fake-broker.sock", service_uid=1200)
        self.assertEqual("", standard_error)
        self.assertEqual(1, len(standard_output.splitlines()))
        self.assertEqual(
            {"run": {
                "admission": responses["submit"],
                "dispatch": responses["dispatch"],
                "result": responses["get_result"],
            }},
            json.loads(standard_output),
        )

    def test_run_stops_after_invalid_admission_or_dispatch(self) -> None:
        denied_admission = self.receipt(
            phase="admission",
            outcome="DENIED",
            code="CAPABILITY_REVOKED",
            effect_applied=False,
            queue_id=self.queue_id,
        )
        malformed_admission = {"schema_version": linux_ipc.IPC_SCHEMA}
        missing_admission_id = self.receipt(
            phase="admission",
            outcome="QUEUED",
            code="ADMITTED",
            effect_applied=False,
        )
        mismatched_dispatch = self.receipt(
            phase="dispatch",
            outcome="APPLIED",
            code="EFFECT_APPLIED",
            effect_applied=True,
            queue_id=self.other_queue_id,
        )
        missing_dispatch_id = self.receipt(
            phase="dispatch",
            outcome="APPLIED",
            code="EFFECT_APPLIED",
            effect_applied=True,
        )
        denied_dispatch = self.receipt(
            phase="dispatch",
            outcome="DENIED",
            code="STALE_GENERATION",
            effect_applied=False,
            queue_id=self.queue_id,
        )
        for admission, dispatch, expected_calls in (
            (denied_admission, self.successful_responses()["dispatch"], [("submit", "cli-run-1")]),
            (malformed_admission, self.successful_responses()["dispatch"], [("submit", "cli-run-1")]),
            (missing_admission_id, self.successful_responses()["dispatch"], [("submit", "cli-run-1")]),
            (
                self.successful_responses()["submit"],
                mismatched_dispatch,
                [("submit", "cli-run-1"), ("dispatch", self.queue_id)],
            ),
            (
                self.successful_responses()["submit"],
                missing_dispatch_id,
                [("submit", "cli-run-1"), ("dispatch", self.queue_id)],
            ),
            (
                self.successful_responses()["submit"],
                denied_dispatch,
                [("submit", "cli-run-1"), ("dispatch", self.queue_id)],
            ),
        ):
            with self.subTest(admission=admission, dispatch=dispatch):
                status, calls, standard_output, standard_error, _ = self.invoke(
                    {
                        "submit": admission,
                        "dispatch": dispatch,
                        "get_result": self.result(queue_id=self.queue_id),
                    }
                )
                self.assertEqual(1, status)
                self.assertEqual(expected_calls, calls)
                self.assertEqual("", standard_output)
                self.assertIn("failed closed", standard_error)

    def test_run_rejects_bad_result_and_stops_on_exceptions(self) -> None:
        mismatched_result = self.result(queue_id=self.other_queue_id)
        missing_result_id = self.result()
        bad_result = self.result(queue_id=self.queue_id)
        bad_result["report"] = {"unbounded": "x" * (linux_ipc.MAX_RESULT_BYTES + 1)}
        denied_result = {
            "code": "NOT_FOUND",
            "outcome": "DENIED",
            "phase": "result",
            "queue_id": self.queue_id,
            "schema_version": linux_ipc.IPC_SCHEMA,
        }
        cases = (
            (
                {**self.successful_responses(), "get_result": mismatched_result},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id), ("get_result", self.queue_id)],
            ),
            (
                {**self.successful_responses(), "get_result": missing_result_id},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id), ("get_result", self.queue_id)],
            ),
            (
                {**self.successful_responses(), "get_result": denied_result},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id), ("get_result", self.queue_id)],
            ),
            (
                {**self.successful_responses(), "get_result": bad_result},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id), ("get_result", self.queue_id)],
            ),
            (
                {**self.successful_responses(), "submit": RuntimeError("submit failed")},
                [("submit", "cli-run-1")],
            ),
            (
                {**self.successful_responses(), "dispatch": RuntimeError("dispatch failed")},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id)],
            ),
            (
                {**self.successful_responses(), "get_result": RuntimeError("result failed")},
                [("submit", "cli-run-1"), ("dispatch", self.queue_id), ("get_result", self.queue_id)],
            ),
        )
        for responses, expected_calls in cases:
            with self.subTest(expected_calls=expected_calls, responses=responses):
                status, calls, standard_output, standard_error, _ = self.invoke(responses)
                self.assertEqual(1, status)
                self.assertEqual(expected_calls, calls)
                self.assertEqual("", standard_output)
                self.assertIn("failed closed", standard_error)

    def test_run_missing_arguments_fail_before_client_construction(self) -> None:
        cases = (
            ["--linux-ipc", "run", "--socket", "/tmp/fake.sock", "--service-uid", "1200"],
            ["--linux-ipc", "run", "--service-uid", "1200", "--operation-id", "cli-run-1"],
            ["--linux-ipc", "run", "--socket", "/tmp/fake.sock", "--operation-id", "cli-run-1"],
        )
        with mock.patch.object(sys, "platform", "linux"), mock.patch.object(
            brokered_operator_demo.os, "geteuid", return_value=1201, create=True
        ):
            for arguments in cases:
                with self.subTest(arguments=arguments), mock.patch.object(
                    linux_ipc,
                    "BrokeredLinuxClient",
                    side_effect=AssertionError("client must not be constructed"),
                ) as constructor:
                    with self.assertRaises(SystemExit):
                        brokered_operator_demo.main(arguments)
                    constructor.assert_not_called()

    def test_run_client_construction_exception_returns_nonzero(self) -> None:
        arguments = [
            "--linux-ipc",
            "run",
            "--socket",
            "/tmp/fake-broker.sock",
            "--service-uid",
            "1200",
            "--operation-id",
            "cli-run-1",
        ]
        standard_output = io.StringIO()
        standard_error = io.StringIO()
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(brokered_operator_demo.os, "geteuid", return_value=1201, create=True),
            mock.patch.object(
                linux_ipc,
                "BrokeredLinuxClient",
                side_effect=RuntimeError("client setup failed"),
            ) as constructor,
            contextlib.redirect_stdout(standard_output),
            contextlib.redirect_stderr(standard_error),
        ):
            status = brokered_operator_demo.main(arguments)

        self.assertEqual(1, status)
        constructor.assert_called_once_with("/tmp/fake-broker.sock", service_uid=1200)
        self.assertEqual("", standard_output.getvalue())
        self.assertIn("failed closed", standard_error.getvalue())

    def test_run_failure_before_valid_admission_never_exposes_a_queue_id(self) -> None:
        denied_admission = self.receipt(
            phase="admission",
            outcome="DENIED",
            code="CAPABILITY_REVOKED",
            effect_applied=False,
            queue_id=self.other_queue_id,
        )
        malformed_admission = self.receipt(
            phase="admission",
            outcome="QUEUED",
            code="ADMITTED",
            effect_applied=False,
            queue_id="untrusted-queue-value",
        )
        for stage, response, untrusted_id in (
            ("submit", RuntimeError("untrusted submit detail"), None),
            ("admission_validation", denied_admission, self.other_queue_id),
            ("admission_validation", malformed_admission, "untrusted-queue-value"),
        ):
            with self.subTest(stage=stage):
                responses = self.successful_responses()
                responses["submit"] = response
                status, calls, standard_output, standard_error, _ = self.invoke(responses)
                failure = json.loads(standard_error)["run_failure"]
                self.assertEqual(1, status)
                self.assertEqual([("submit", "cli-run-1")], calls)
                self.assertEqual("", standard_output)
                self.assertEqual(stage, failure["failed_stage"])
                self.assertEqual("UNKNOWN", failure["effect_status"])
                self.assertNotIn("queue_id", failure)
                if untrusted_id is not None:
                    self.assertNotIn(untrusted_id, standard_error)
                self.assertNotIn("untrusted submit detail", standard_error)
                self.assertLessEqual(len(standard_error.encode("utf-8")), 256)

        arguments = [
            "--linux-ipc",
            "run",
            "--socket",
            "/tmp/fake-broker.sock",
            "--service-uid",
            "1200",
            "--operation-id",
            "cli-run-1",
        ]
        standard_output = io.StringIO()
        standard_error = io.StringIO()
        with (
            mock.patch.object(sys, "platform", "linux"),
            mock.patch.object(brokered_operator_demo.os, "geteuid", return_value=1201, create=True),
            mock.patch.object(
                linux_ipc,
                "BrokeredLinuxClient",
                side_effect=RuntimeError("untrusted setup detail"),
            ),
            contextlib.redirect_stdout(standard_output),
            contextlib.redirect_stderr(standard_error),
        ):
            status = brokered_operator_demo.main(arguments)
        failure = json.loads(standard_error.getvalue())["run_failure"]
        self.assertEqual(1, status)
        self.assertEqual("client_setup", failure["failed_stage"])
        self.assertEqual("UNKNOWN", failure["effect_status"])
        self.assertNotIn("queue_id", failure)
        self.assertNotIn("untrusted setup detail", standard_error.getvalue())
        self.assertLessEqual(len(standard_error.getvalue().encode("utf-8")), 256)
        self.assertEqual("", standard_output.getvalue())

    def test_run_failure_before_valid_dispatch_reports_validated_id_and_unknown_effect(self) -> None:
        mismatched_dispatch = self.receipt(
            phase="dispatch",
            outcome="APPLIED",
            code="EFFECT_APPLIED",
            effect_applied=True,
            queue_id=self.other_queue_id,
        )
        denied_dispatch = self.receipt(
            phase="dispatch",
            outcome="DENIED",
            code="STALE_GENERATION",
            effect_applied=False,
            queue_id=self.queue_id,
        )
        cases = (
            ("dispatch", RuntimeError("untrusted dispatch detail")),
            ("dispatch_validation", mismatched_dispatch),
            ("dispatch_validation", denied_dispatch),
        )
        for expected_stage, dispatch_response in cases:
            with self.subTest(expected_stage=expected_stage):
                responses = self.successful_responses()
                responses["dispatch"] = dispatch_response
                status, calls, standard_output, standard_error, _ = self.invoke(responses)
                failure = json.loads(standard_error)["run_failure"]
                self.assertEqual(1, status)
                self.assertEqual(
                    [("submit", "cli-run-1"), ("dispatch", self.queue_id)],
                    calls,
                )
                self.assertEqual("", standard_output)
                self.assertEqual(expected_stage, failure["failed_stage"])
                self.assertEqual("admission", failure["last_validated_stage"])
                self.assertEqual(self.queue_id, failure["queue_id"])
                self.assertEqual("UNKNOWN", failure["effect_status"])
                self.assertNotIn(self.other_queue_id, standard_error)
                self.assertNotIn("untrusted dispatch detail", standard_error)
                self.assertLessEqual(len(standard_error.encode("utf-8")), 256)

    def test_run_failure_after_validated_applied_dispatch_confirms_effect(self) -> None:
        responses = self.successful_responses()
        responses["get_result"] = RuntimeError("untrusted result detail")

        status, calls, standard_output, standard_error, _ = self.invoke(responses)
        failure = json.loads(standard_error)["run_failure"]

        self.assertEqual(1, status)
        self.assertEqual(
            [
                ("submit", "cli-run-1"),
                ("dispatch", self.queue_id),
                ("get_result", self.queue_id),
            ],
            calls,
        )
        self.assertEqual("", standard_output)
        self.assertEqual("result", failure["failed_stage"])
        self.assertEqual("dispatch", failure["last_validated_stage"])
        self.assertEqual(self.queue_id, failure["queue_id"])
        self.assertEqual("CONFIRMED_APPLIED", failure["effect_status"])
        self.assertNotIn("untrusted result detail", standard_error)
        self.assertLessEqual(len(standard_error.encode("utf-8")), 256)


class LinuxIdentityAndPathGuardTests(unittest.TestCase):
    def test_service_and_workload_root_identity_configurations_are_refused(self) -> None:
        valid = {"service_gid": 13579, "service_groups": (13579,)}
        cases = (
            (0, 24680, 24681, valid),
            (13579, 0, 24681, valid),
            (13579, 24680, 0, valid),
            (13579, 24680, 24681, {"service_gid": 0, "service_groups": ()}),
            (13579, 24680, 24681, {"service_gid": 13579, "service_groups": (0,)}),
            (13579, 13579, 24681, valid),
        )
        for service_uid, workload_uid, workload_gid, keyword_args in cases:
            with (
                self.subTest(service_uid=service_uid, workload_uid=workload_uid, workload_gid=workload_gid),
                self.assertRaises(linux_ipc.BrokeredIPCError),
            ):
                linux_ipc._validate_identity_config(
                    service_uid,
                    workload_uid,
                    workload_gid,
                    **keyword_args,
                )

    def test_exact_private_state_modes_reject_workload_owner_and_special_bits(self) -> None:
        directory_mode = stat.S_IFDIR | 0o700
        file_mode = stat.S_IFREG | 0o600
        directory = SimpleNamespace(st_uid=13579, st_mode=directory_mode, st_nlink=2)
        file = SimpleNamespace(st_uid=13579, st_mode=file_mode, st_nlink=1)
        self.assertTrue(brokered_operator._private_state_metadata_valid(directory, 13579, directory=True))
        self.assertTrue(brokered_operator._private_state_metadata_valid(file, 13579, directory=False))
        self.assertFalse(brokered_operator._private_state_metadata_valid(directory, 24680, directory=True))
        self.assertFalse(brokered_operator._private_state_metadata_valid(file, 24680, directory=False))
        special_directory = SimpleNamespace(st_uid=13579, st_mode=stat.S_IFDIR | 0o4700, st_nlink=2)
        loose_file = SimpleNamespace(st_uid=13579, st_mode=stat.S_IFREG | 0o700, st_nlink=1)
        self.assertFalse(brokered_operator._private_state_metadata_valid(special_directory, 13579, directory=True))
        self.assertFalse(brokered_operator._private_state_metadata_valid(loose_file, 13579, directory=False))

        private_operator = object.__new__(BrokeredOperator)
        private_operator._directory = Path("/private")

        def private_metadata(path: Path) -> SimpleNamespace:
            return directory if path == private_operator._directory else file

        with mock.patch.object(Path, "lstat", autospec=True, side_effect=private_metadata):
            private_operator._assert_service_state_owner(13579)
            with self.assertRaises(brokered_operator.BrokeredStoreError):
                private_operator._assert_service_state_owner(24680)

    def test_pinned_directory_and_socket_identity_replacements_fail_closed(self) -> None:
        service = object.__new__(linux_ipc.BrokeredLinuxService)
        service._socket_path = Path("/test-only/broker.sock")
        service._service_uid = 13579
        service._workload_gid = 24681
        service._socket_directory_fd = 42
        service._socket_directory_identity = (1, 2)
        service._socket_identity = (3, 4)
        parent = service._socket_path.parent
        directory_meta = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=stat.S_IFDIR | 0o710,
            st_uid=13579,
            st_gid=24681,
        )
        replacement_directory = SimpleNamespace(
            st_dev=1,
            st_ino=9,
            st_mode=stat.S_IFDIR | 0o710,
            st_uid=13579,
            st_gid=24681,
        )
        with (
            mock.patch.object(linux_ipc.os, "fstat", return_value=replacement_directory),
            mock.patch.object(Path, "lstat", return_value=directory_meta),
            mock.patch.object(Path, "resolve", return_value=parent),
            self.assertRaises(linux_ipc.BrokeredIPCError),
        ):
            service._assert_pinned_socket_directory()

        socket_path_replacement = SimpleNamespace(
            st_dev=3,
            st_ino=5,
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=13579,
            st_gid=24681,
        )

        def replaced_lstat(path: Path) -> SimpleNamespace:
            return directory_meta if path == parent else socket_path_replacement

        with (
            mock.patch.object(linux_ipc.os, "fstat", return_value=directory_meta),
            mock.patch.object(Path, "lstat", autospec=True, side_effect=replaced_lstat),
            mock.patch.object(Path, "resolve", return_value=parent),
            mock.patch.object(
                linux_ipc.os,
                "stat",
                return_value=SimpleNamespace(
                    st_dev=3,
                    st_ino=4,
                    st_mode=stat.S_IFSOCK | 0o660,
                    st_uid=13579,
                    st_gid=24681,
                ),
            ),
            self.assertRaises(linux_ipc.BrokeredIPCError),
        ):
            service._assert_bound_socket_identity()

    def test_client_identity_guard_rejects_root_and_root_group(self) -> None:
        for service_uid, workload_uid, workload_gid, groups in (
            (0, 24680, 24681, {24681}),
            (13579, 0, 24681, {24681}),
            (13579, 24680, 0, {0}),
            (13579, 24680, 24681, {0, 24681}),
            (13579, 13579, 24681, {24681}),
        ):
            with (
                self.subTest(service_uid=service_uid, workload_uid=workload_uid, groups=groups),
                self.assertRaises(linux_ipc.BrokeredIPCError),
            ):
                linux_ipc._validate_client_identity(service_uid, workload_uid, workload_gid, groups)


@unittest.skipUnless(sys.platform == "linux", "SO_PEERCRED socket checks are Linux-specific")
class LinuxPeerCredentialTests(unittest.TestCase):
    def test_linux_transport_is_explicitly_separate_from_portable_core(self) -> None:
        self.assertTrue(hasattr(socket, "SO_PEERCRED"))
        self.assertTrue(hasattr(socket, "SOCK_SEQPACKET"))
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        credentials = client.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _, peer_uid, _ = struct.unpack("3i", credentials)
        self.assertEqual(os.geteuid(), peer_uid)


if __name__ == "__main__":
    unittest.main()
