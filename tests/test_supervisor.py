from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.artifacts import ArtifactEvidence
from lumi_eggcracker.containment import EmptyProof
from lumi_eggcracker.discovery import ProcessIdentity, ProcessSnapshot
from lumi_eggcracker.elfmarkers import RuntimeEvidence
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.records import RUN_SCHEMA, command_summary
from lumi_eggcracker.supervisor import Supervisor, _EvidenceCandidate


def record() -> dict[str, object]:
    run_id = "a" * 24
    return {**command_summary(["/bin/true"]), "boot_id": "b" * 36, "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "cpu_quota_percent": 400, "created_monotonic_ns": 3, "max_memory_mib": 2048, "max_pids": 8, "name": "demo", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-eggcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


class SupervisorTests(unittest.TestCase):
    def _instance(self) -> Supervisor:
        value = object.__new__(Supervisor)
        value.policy = {"source_commit": "c" * 40, "workload_uid": 2001}
        value.runs = Path(".")
        value.names = Path(".")
        value.receipts = Path(".")
        value.locks = {}
        value.lock_guard = threading.Lock()
        value.start_lock = threading.Lock()
        value.completed = {}
        value.operations = []
        value.discovery_active = set()
        value.discovery_done = {}
        value.discovery_lock = threading.Lock()
        value.content_scan_tick = 0
        return value

    def test_recently_contained_identity_is_not_reenforced(self) -> None:
        supervisor = self._instance()
        identity = object()
        with supervisor.discovery_lock:
            supervisor.discovery_done[identity] = 1
            self.assertIn(identity, supervisor.discovery_done)

    def test_managed_processes_use_reconciled_in_memory_cgroups(self) -> None:
        supervisor = self._instance()
        cgroup = "/system.slice/lumi-eggcracker-workload-" + "a" * 24 + ".service"
        supervisor.active_cgroups = {cgroup}
        snapshot = ProcessSnapshot(
            ProcessIdentity(10, 100),
            2001,
            "/usr/bin/python3",
            "python3",
            ("python3",),
            ("0::" + cgroup,),
            (),
            (),
        )
        self.assertTrue(supervisor._managed(snapshot))

    def test_heartbeat_stops_when_no_scan_completed_within_health_bound(self) -> None:
        supervisor = self._instance()
        supervisor.discovery_thread = type(
            "LiveThread", (), {"is_alive": lambda _self: True}
        )()
        supervisor.last_heartbeat_sent = 0.0
        supervisor.last_scan_completed_ns = time.monotonic_ns() - 2_000_000_000
        supervisor.discovery_failures = 0
        with patch("lumi_eggcracker.supervisor.socket.socket") as socket_factory:
            supervisor._heartbeat()
        socket_factory.assert_not_called()

    def test_containment_orders_direct_kill_before_receipt_state_and_cleanup(self) -> None:
        supervisor = self._instance()
        response = {"result": "TERMINATED", "cleanup": {"attempted": False}}
        with patch("lumi_eggcracker.supervisor.validate_identity", return_value=Path("/owned")), patch("lumi_eggcracker.supervisor.kill_path", return_value=(11, 12)), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(13, EmptyProof(True, 1, 0, []))), patch.object(supervisor, "_cleanup", side_effect=lambda _: supervisor.operations.append("cleanup") or {}), patch("lumi_eggcracker.supervisor.make_receipt", return_value=response), patch("lumi_eggcracker.supervisor.write_atomic"), patch.object(supervisor, "_store", side_effect=lambda *_: supervisor.operations.append("durable-state")):
            result = supervisor._contain(record(), "OPERATOR", 10)
        self.assertEqual("TERMINATED", result["result"])
        self.assertEqual("cgroup.kill", supervisor.operations[0])
        self.assertLess(supervisor.operations.index("cgroup.kill"), supervisor.operations.index("durable-receipt"))
        self.assertLess(supervisor.operations.index("durable-receipt"), supervisor.operations.index("cleanup"))

    def test_exact_empty_cgroup_allows_normal_completion_without_systemctl(self) -> None:
        supervisor = self._instance()
        saved: list[dict[str, object]] = []
        with patch("lumi_eggcracker.supervisor.events_from_fd", return_value={"populated": 0}), patch.object(supervisor, "_store", side_effect=lambda value: saved.append(value.copy())):
            self.assertTrue(supervisor._complete_allowed(record(), 42))
        self.assertEqual("COMPLETED_ALLOWED", saved[0]["state"])

    def test_collected_empty_cgroup_allows_normal_completion_with_exact_proof(self) -> None:
        supervisor = self._instance()
        item = record()
        with patch.object(supervisor, "_watch_once", side_effect=JsonInputError("owned cgroup is unavailable")), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(1, EmptyProof(True, 0, 0, []))), patch.object(supervisor, "_store") as stored:
            supervisor._watch(item)
        stored.assert_called_once()
        self.assertEqual("COMPLETED_ALLOWED", item["state"])

    def test_recovery_accepts_only_an_exact_empty_collected_cgroup(self) -> None:
        supervisor = self._instance()
        item = record()
        with tempfile.TemporaryDirectory() as raw:
            supervisor.runs = Path(raw)
            (supervisor.runs / ("a" * 24 + ".json")).write_text(__import__("json").dumps(item), encoding="utf-8")
            with patch.object(supervisor, "_contain", side_effect=JsonInputError("containment failed: owned cgroup is unavailable")), patch("lumi_eggcracker.supervisor.verify_empty", return_value=(1, EmptyProof(True, 0, 0, []))), patch.object(supervisor, "_mark_completed") as completed:
                supervisor._recover()
        completed.assert_called_once_with(item)

    def test_recovery_promotes_collected_failure_after_exact_empty_proof(self) -> None:
        supervisor = self._instance()
        item = record()

        def fail_containment(value: dict[str, object], _trigger: str) -> None:
            value["state"] = "CONTAINMENT_FAILED"
            raise JsonInputError("containment failed: owned cgroup is unavailable")

        with tempfile.TemporaryDirectory() as raw:
            supervisor.runs = Path(raw)
            (supervisor.runs / ("a" * 24 + ".json")).write_text(
                __import__("json").dumps(item), encoding="utf-8"
            )
            with patch.object(supervisor, "_contain", side_effect=fail_containment), patch(
                "lumi_eggcracker.supervisor.verify_empty",
                return_value=(1, EmptyProof(True, 0, 0, [])),
            ), patch.object(supervisor, "_mark_completed") as completed:
                supervisor._recover()
        self.assertEqual("RUNNING", item["state"])
        completed.assert_called_once_with(item)

    def test_status_is_read_only(self) -> None:
        supervisor = self._instance()
        item = record()
        with patch.object(supervisor, "_load", return_value=item), patch.object(supervisor, "_store") as stored:
            value = supervisor.handle({"action": "status", "args": {"name": "demo"}})
        self.assertEqual("RUNNING", value["state"])
        stored.assert_not_called()

    def test_status_resolves_the_latest_terminal_run_after_name_reuse_is_enabled(self) -> None:
        supervisor = self._instance()
        item = record(); item["state"] = "COMPLETED_ALLOWED"
        with patch.object(supervisor, "_load", side_effect=JsonInputError("gone")), patch.object(supervisor, "_latest_by_name", return_value=item), patch.object(supervisor, "_store") as stored:
            value = supervisor.handle({"action": "status", "args": {"name": "demo"}})
        self.assertEqual("COMPLETED_ALLOWED", value["state"])
        stored.assert_not_called()

    def test_run_records_are_keyed_by_run_id_and_name_pointer_is_removed_when_terminal(self) -> None:
        supervisor = self._instance()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            supervisor.runs = root / "runs"; supervisor.names = root / "names"
            item = record()
            supervisor._store(item)
            self.assertTrue((supervisor.runs / ("a" * 24 + ".json")).is_file())
            self.assertTrue((supervisor.names / "demo.json").is_file())
            item["state"] = "TERMINATED"
            supervisor._store(item)
            self.assertFalse((supervisor.names / "demo.json").exists())

    def test_correlation_requires_live_same_uid_parent_or_sibling_relation(self) -> None:
        supervisor = self._instance()
        root = ProcessIdentity(10, 100)
        left_identity = ProcessIdentity(11, 101)
        right_identity = ProcessIdentity(12, 102)
        left = ProcessSnapshot(left_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=root)
        right = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=root)
        root_snapshot = ProcessSnapshot(root, 2001, "/usr/bin/worker", "worker", ("worker",), (), (), ())
        content = ArtifactEvidence("safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64)
        runtime = RuntimeEvidence("pytorch-aten-pinned-cpu", "PyTorch/ATen", "BUILD_ID_PAIR", ())
        left_candidate = _EvidenceCandidate(left, (content,), (), 1)
        right_candidate = _EvidenceCandidate(right, (), (runtime,), 2)
        related, boundary = supervisor._related(left_candidate, right_candidate, {root: root_snapshot, left_identity: left, right_identity: right})
        self.assertTrue(related)
        self.assertEqual("sibling", boundary)
        unrelated_root = ProcessIdentity(1, 1)
        right_unrelated = ProcessSnapshot(right_identity, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=unrelated_root)
        root_snapshot = ProcessSnapshot(unrelated_root, 0, "/sbin/init", "init", ("init",), (), (), ())
        related, _boundary = supervisor._related(left_candidate, _EvidenceCandidate(right_unrelated, (), (runtime,), 2), {unrelated_root: root_snapshot, left_identity: left, right_identity: right_unrelated})
        self.assertFalse(related)

    def test_unrelated_same_uid_partial_candidates_do_not_join_by_common_root(self) -> None:
        supervisor = self._instance()
        common = ProcessIdentity(1, 1)
        left_id = ProcessIdentity(21, 201)
        right_id = ProcessIdentity(22, 202)
        left = ProcessSnapshot(left_id, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        right = ProcessSnapshot(right_id, 2001, "/usr/bin/python3", "python3", ("python3",), (), (), (), parent=common)
        root = ProcessSnapshot(common, 0, "/sbin/init", "init", ("init",), (), (), ())
        content = ArtifactEvidence("safetensors-v1", "SAFETENSORS", 1, 2, 4096, "a" * 64)
        runtime = RuntimeEvidence("pytorch-aten-pinned-cpu", "PyTorch/ATen", "BUILD_ID_PAIR", ())
        with patch.object(supervisor, "_owned_cgroup", return_value=None):
            groups = supervisor._correlate(
                [_EvidenceCandidate(left, (content,), (), 1), _EvidenceCandidate(right, (), (runtime,), 2)],
                {common: root, left_id: left, right_id: right},
            )
        self.assertEqual(2, len(groups))
        self.assertTrue(all(len(value[0]) == 1 for value in groups))
