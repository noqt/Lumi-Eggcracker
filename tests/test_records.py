from __future__ import annotations

import os
import stat
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
    return {**command_summary(["/bin/true", "--safe"]), "boot_id": "b" * 36, "boundary": None, "cgroup": f"/system.slice/lumi-eggcracker-workload-{run_id}.service", "cgroup_device": 1, "cgroup_inode": 2, "cpu_quota_percent": 400, "created_monotonic_ns": 3, "max_memory_mib": 2048, "max_pids": 8, "name": "demo", "network_mode": "none", "operator_uid": 1001, "run_id": run_id, "schema_version": RUN_SCHEMA, "state": "RUNNING", "unit": f"lumi-eggcracker-workload-{run_id}.service", "workload_gid": 2001, "workload_uid": 2001}


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
                make_receipt(record=value, trigger="OPERATOR", trigger_ns=10, kill_started_ns=11, kill_complete_ns=12, empty_ns=13, proof=proof, version="0.6.0", source_commit="c" * 40, event_id="d" * 24)

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

    def test_directory_durability_faults_do_not_publish_a_success_receipt(self) -> None:
        real_open = os.open
        real_fsync = os.fsync

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "receipt.json"

            def fail_directory_open(path: object, flags: int, *args: object) -> int:
                if Path(path) == root:
                    raise OSError("directory unavailable")
                return real_open(path, flags, *args)

            with patch(
                "lumi_eggcracker.records.os.open", side_effect=fail_directory_open
            ), self.assertRaises(OSError):
                write_atomic(target, {"result": "TERMINATED"})
            self.assertFalse(target.exists())
            self.assertEqual([], list(root.iterdir()))

            def fail_directory_fsync(descriptor: int) -> None:
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    raise OSError("directory fsync failed")
                real_fsync(descriptor)

            with patch(
                "lumi_eggcracker.records.os.fsync", side_effect=fail_directory_fsync
            ), self.assertRaises(OSError):
                write_atomic(target, {"result": "TERMINATED"})
            self.assertFalse(target.exists())
            self.assertEqual([], list(root.iterdir()))

    def test_durable_record_redacts_command_arguments(self) -> None:
        value = record()
        self.assertNotIn("argv", value)
        self.assertNotIn("--safe", str(value))

    def test_schema_rejects_unknown_field(self) -> None:
        value = record()
        value["extra"] = True
        with self.assertRaises(JsonInputError):
            validate_run(value)

    def test_network_boundary_receipt_requires_bounded_metadata(self) -> None:
        value = record()
        receipt = make_receipt(
            record=value,
            trigger="NETWORK_BOUNDARY",
            trigger_ns=10,
            kill_started_ns=11,
            kill_complete_ns=12,
            empty_ns=13,
            proof=EmptyProof(True, 1, 0, []),
            version="0.6.0",
            source_commit="c" * 40,
            event_id="d" * 24,
            boundary={
                "address_family": "INET6",
                "mode": "offline",
                "policy_sha256": "a" * 64,
                "violation": "NON_LOOPBACK_EGRESS",
            },
        )
        self.assertEqual("NETWORK_BOUNDARY", receipt["trigger"]["kind"])
        self.assertEqual("INET6", receipt["boundary"]["address_family"])
        with self.assertRaises(JsonInputError):
            make_receipt(
                record=value,
                trigger="NETWORK_BOUNDARY",
                trigger_ns=10,
                kill_started_ns=11,
                kill_complete_ns=12,
                empty_ns=13,
                proof=EmptyProof(True, 1, 0, []),
                version="0.6.0",
                source_commit="c" * 40,
                event_id="d" * 24,
                boundary={
                    "address_family": "INET",
                    "mode": "offline",
                    "policy_sha256": "a" * 64,
                    "violation": "OTHER",
                },
            )

    def test_execution_boundary_receipt_requires_policy_metadata(self) -> None:
        value = record()
        receipt = make_receipt(
            record=value,
            trigger="EXECUTION_BOUNDARY",
            trigger_ns=10,
            kill_started_ns=11,
            kill_complete_ns=12,
            empty_ns=13,
            proof=EmptyProof(True, 1, 0, []),
            version="0.8.0",
            source_commit="c" * 40,
            event_id="d" * 24,
            execution_boundary={"policy_id": "a" * 24, "policy_sha256": "b" * 64},
        )
        self.assertEqual("EXECUTION_BOUNDARY", receipt["trigger"]["kind"])
        self.assertEqual("a" * 24, receipt["execution_boundary"]["policy_id"])
        with self.assertRaises(JsonInputError):
            make_receipt(
                record=value,
                trigger="EXECUTION_BOUNDARY",
                trigger_ns=10,
                kill_started_ns=11,
                kill_complete_ns=12,
                empty_ns=13,
                proof=EmptyProof(True, 1, 0, []),
                version="0.8.0",
                source_commit="c" * 40,
                event_id="d" * 24,
            )
