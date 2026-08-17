from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.containment import EmptyProof
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.records import (
    RUN_SCHEMA,
    command_summary,
    make_receipt,
    validate_run,
    write_atomic,
)


def record() -> dict[str, object]:
    run_id = "a" * 24
    return {**command_summary(["/bin/true", "--safe"]), "boot_id": "b" * 36, "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "cpu_quota_percent": 400, "created_monotonic_ns": 3, "max_memory_mib": 2048, "max_pids": 8, "name": "demo", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-eggcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


class RecordTests(unittest.TestCase):
    def test_receipt_requires_exact_empty_proof(self) -> None:
        value = record()
        receipt = make_receipt(record=value, trigger="OPERATOR", trigger_ns=10, kill_started_ns=11, kill_complete_ns=12, empty_ns=13, proof=EmptyProof(True, 1, 0, []), version="0.1.1", source_commit="c" * 40, event_id="d" * 24)
        self.assertEqual("TERMINATED", receipt["result"])
        self.assertEqual("cgroup.kill", receipt["containment"]["primitive"])

        for proof in (
            EmptyProof(False, 1, 0, []),
            EmptyProof(True, 1, 1, []),
            EmptyProof(True, 1, 0, [42]),
        ):
            with self.assertRaises(JsonInputError):
                make_receipt(record=value, trigger="OPERATOR", trigger_ns=10, kill_started_ns=11, kill_complete_ns=12, empty_ns=13, proof=proof, version="0.5.0", source_commit="c" * 40, event_id="d" * 24)

    def test_atomic_record_faults_never_publish_a_partial_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "receipt.json"
            with patch(
                "lumi_eggcracker.records.os.write", return_value=0
            ), self.assertRaises(OSError):
                write_atomic(target, {"result": "TERMINATED"})
            self.assertFalse(target.exists())
            self.assertEqual([], list(root.iterdir()))

            with patch(
                "lumi_eggcracker.records.os.replace", side_effect=OSError("read only")
            ), self.assertRaises(OSError):
                write_atomic(target, {"result": "TERMINATED"})
            self.assertFalse(target.exists())
            self.assertEqual([], list(root.iterdir()))

    def test_durable_record_redacts_command_arguments(self) -> None:
        value = record()
        self.assertNotIn("argv", value)
        self.assertNotIn("--safe", str(value))

    def test_schema_rejects_unknown_field(self) -> None:
        value = record(); value["extra"] = True
        with self.assertRaises(JsonInputError):
            validate_run(value)
