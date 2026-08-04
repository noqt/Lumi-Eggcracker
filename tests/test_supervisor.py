from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.containment import EmptyProof
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.records import RUN_SCHEMA, command_summary
from lumi_eggcracker.supervisor import Supervisor


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
