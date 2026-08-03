from __future__ import annotations

import unittest

from lumi_nutcracker.containment import EmptyProof
from lumi_nutcracker.records import RUN_SCHEMA, make_receipt, validate_run


def record() -> dict[str, object]:
    run_id = "a" * 24
    return {"argv": ["/bin/true"], "boot_id": "b" * 36, "cgroup": f"/system.slice/lumi-nutcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "created_monotonic_ns": 3, "max_pids": 8, "name": "demo", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-nutcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


class RecordTests(unittest.TestCase):
    def test_receipt_requires_exact_empty_proof(self) -> None:
        value = record()
        receipt = make_receipt(record=value, trigger="OPERATOR", trigger_ns=10, kill_started_ns=11, kill_complete_ns=12, empty_ns=13, proof=EmptyProof(True, 1, 0, []), version="0.1.0", source_commit="c" * 40, cleanup={}, event_id="d" * 24)
        self.assertEqual("TERMINATED", receipt["result"])
        self.assertEqual("cgroup.kill", receipt["containment"]["primitive"])

    def test_schema_rejects_unknown_field(self) -> None:
        value = record()
        value["extra"] = True
        with self.assertRaises(Exception):
            validate_run(value)
