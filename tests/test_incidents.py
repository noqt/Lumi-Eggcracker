from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker import incidents
from lumi_eggcracker.jsonio import JsonInputError


def _receipt() -> dict[str, object]:
    return {
        "event_id": "a" * 24,
        "observed": {"argv_sha256": "b" * 64, "uid": 2001},
        "executable": {"sha256": "c" * 64},
        "detector": {"profile": "content.gguf-llama", "matched_evidence": ["gguf-v3"]},
        "workload": {
            "boot_id": "d" * 36,
            "cgroup": "/system.slice/lumi-eggcracker-workload-" + "a" * 24 + ".service",
            "cgroup_device": 1,
            "cgroup_inode": 2,
            "run_id": "a" * 24,
            "unit": "lumi-eggcracker-workload-" + "a" * 24 + ".service",
            "uid": 2001,
        },
    }


class IncidentTests(unittest.TestCase):
    def test_round_trip_and_exact_start_match(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            value = incidents.create(
                root,
                receipt=_receipt(),
                policy={"version": "1.0.0"},
                catalogue_sha256="e" * 64,
                source_commit="f" * 40,
                version="1.0.0",
                trigger="UNAPPROVED_AI_MATCH",
                profile="content.gguf-llama",
                evidence=["gguf-v3"],
                match={
                    "argv_sha256": "b" * 64,
                    "executable_sha256": "c" * 64,
                    "profile": "content.gguf-llama",
                    "uid": 2001,
                },
                workload=_receipt()["workload"],
                approval=None,
            )
            loaded = incidents.load_all(root)
            self.assertEqual(value, loaded[0])
            self.assertIsNotNone(
                incidents.find_match(loaded, argv_sha256="b" * 64, uid=2001)
            )
            self.assertIsNone(
                incidents.find_match(loaded, argv_sha256="0" * 64, uid=2001)
            )

    def test_integrity_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            value = incidents.create(
                root,
                receipt=_receipt(),
                policy={"version": "1.0.0"},
                catalogue_sha256="e" * 64,
                source_commit="f" * 40,
                version="1.0.0",
                trigger="UNAPPROVED_AI_MATCH",
                profile="content.gguf-llama",
                evidence=["gguf-v3"],
                match={
                    "argv_sha256": "b" * 64,
                    "executable_sha256": "c" * 64,
                    "profile": "content.gguf-llama",
                    "uid": 2001,
                },
                workload=_receipt()["workload"],
                approval=None,
            )
            path = root / f"{value['incident_id']}.json"
            tampered = json.loads(path.read_text(encoding="utf-8"))
            tampered["state"] = "CLEARED"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(JsonInputError):
                incidents.load_all(root)

    def test_recurrence_keeps_counting_after_receipt_sample_is_full(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            value = incidents.create(
                root,
                receipt=_receipt(),
                policy={"version": "1.0.0"},
                catalogue_sha256="e" * 64,
                source_commit="f" * 40,
                version="1.0.0",
                trigger="UNAPPROVED_AI_MATCH",
                profile="content.gguf-llama",
                evidence=["gguf-v3"],
                match={
                    "argv_sha256": "b" * 64,
                    "executable_sha256": "c" * 64,
                    "profile": "content.gguf-llama",
                    "uid": 2001,
                },
                workload=_receipt()["workload"],
                approval=None,
            )
            for index in range(incidents.MAX_LINKED_RECEIPTS + 3):
                receipt = dict(_receipt())
                receipt["event_id"] = f"{index:024x}"
                value = incidents.link(root, value, receipt)
            self.assertEqual(len(value["linked_receipts"]), incidents.MAX_LINKED_RECEIPTS)
            self.assertEqual(
                value["recurrence"]["complete_matches"],
                incidents.MAX_LINKED_RECEIPTS + 3,
            )
            self.assertEqual(incidents.load_all(root)[0], value)

    def test_compact_prunes_only_oldest_cleared_records(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            values = []
            for index in range(incidents.MAX_INCIDENTS + 1):
                receipt = dict(_receipt())
                receipt["event_id"] = f"{index:024x}"
                value = incidents.create(
                    root,
                    receipt=receipt,
                    policy={"version": "1.0.0"},
                    catalogue_sha256="e" * 64,
                    source_commit="f" * 40,
                    version="1.0.0",
                    trigger="UNAPPROVED_AI_MATCH",
                    profile="content.gguf-llama",
                    evidence=["gguf-v3"],
                    match={
                        "argv_sha256": "b" * 64,
                        "executable_sha256": "c" * 64,
                        "profile": "content.gguf-llama",
                        "uid": 2001,
                    },
                    workload=_receipt()["workload"],
                    approval=None,
                )
                value = incidents.update(
                    root,
                    value,
                    clearance={"monotonic_ns": index + 1, "uid": 0},
                    state="CLEARED",
                )
                values.append(value)
            compacted = incidents.compact(root)
            self.assertEqual(len(compacted), incidents.MAX_INCIDENTS)
            self.assertNotIn("0" * 24, {item["incident_id"] for item in compacted})
            self.assertEqual(
                len([item for item in compacted if item["state"] == "CLEARED"]),
                incidents.MAX_INCIDENTS,
            )

    def test_summary_is_bounded_query_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            value = incidents.create(
                root,
                receipt=_receipt(),
                policy={"version": "1.0.0"},
                catalogue_sha256="e" * 64,
                source_commit="f" * 40,
                version="1.0.0",
                trigger="UNAPPROVED_AI_MATCH",
                profile="content.gguf-llama",
                evidence=["gguf-v3"],
                match={
                    "argv_sha256": "b" * 64,
                    "executable_sha256": "c" * 64,
                    "profile": "content.gguf-llama",
                    "uid": 2001,
                },
                workload=_receipt()["workload"],
                approval=None,
            )
            self.assertEqual(
                incidents.summary(value),
                {
                    "incident_id": "a" * 24,
                    "state": "ACTIVE",
                    "trigger": "UNAPPROVED_AI_MATCH",
                },
            )


if __name__ == "__main__":
    unittest.main()
