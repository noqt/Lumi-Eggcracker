from __future__ import annotations

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
