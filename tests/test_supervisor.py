from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_nutcracker.containment import EmptyProof
from lumi_nutcracker.records import RUN_SCHEMA
from lumi_nutcracker.supervisor import Supervisor


def record() -> dict[str, object]:
    run_id = "a" * 24
    return {"argv": ["/bin/true"], "boot_id": "b" * 36, "cgroup": f"/system.slice/lumi-nutcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "created_monotonic_ns": 3, "max_pids": 8, "name": "demo", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-nutcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


class SupervisorTests(unittest.TestCase):
    def _instance(self) -> Supervisor:
        value = object.__new__(Supervisor)
        value.policy = {"source_commit": "c" * 40}
        value.runs = Path(".")
        value.receipts = Path(".")
        value.locks = {}
        value.completed = {}
        value.operations = []
        return value

    def test_containment_orders_direct_kill_before_durable_writes(self) -> None:
        supervisor = self._instance()
        saved: list[str] = []
        response = {"result": "TERMINATED"}
        with patch("lumi_nutcracker.supervisor.validate_identity", return_value=Path("/owned")), patch("lumi_nutcracker.supervisor.kill_path", return_value=(11, 12)), patch("lumi_nutcracker.supervisor.verify_empty", return_value=(13, EmptyProof(True, 1, 0, []))), patch.object(supervisor, "_cleanup", return_value={}), patch("lumi_nutcracker.supervisor.make_receipt", return_value=response), patch("lumi_nutcracker.supervisor.write_atomic", side_effect=lambda *_: saved.append("write")), patch.object(supervisor, "_store", side_effect=lambda *_: supervisor.operations.append("durable-state")):
            result = supervisor._contain(record(), "OPERATOR", 10)
        self.assertEqual("TERMINATED", result["result"])
        self.assertEqual("cgroup.kill", supervisor.operations[0])
        self.assertLess(supervisor.operations.index("cgroup.kill"), supervisor.operations.index("durable-receipt"))
        self.assertLess(supervisor.operations.index("cgroup.kill"), supervisor.operations.index("durable-state"))
        self.assertEqual(["write"], saved)

    def test_normal_completion_is_reconciled_when_cgroup_is_collected(self) -> None:
        supervisor = self._instance()
        saved: list[dict[str, object]] = []
        with patch.object(supervisor, "_show", return_value={"ActiveState": "inactive"}), patch.object(supervisor, "_store", side_effect=lambda value: saved.append(value.copy())):
            self.assertTrue(supervisor._complete_allowed(record()))
        self.assertEqual("COMPLETED_ALLOWED", saved[0]["state"])
