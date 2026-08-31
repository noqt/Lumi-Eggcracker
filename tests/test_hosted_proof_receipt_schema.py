from __future__ import annotations

import json
import unittest
from pathlib import Path

from lumi_eggcracker import containment_probe as probe

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "hosted-proof-receipt-v1.schema.json"


class HostedProofReceiptSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.success = cls.schema["oneOf"][0]
        cls.refusal = cls.schema["oneOf"][1]

    def test_schema_identity_is_public_and_versioned(self) -> None:
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", self.schema["$schema"])
        self.assertEqual(
            "https://raw.githubusercontent.com/noqt/Lumi-Eggcracker/main/"
            "schemas/hosted-proof-receipt-v1.schema.json",
            self.schema["$id"],
        )

    def test_success_contract_matches_runtime_keys(self) -> None:
        required = set(self.success["required"])
        properties = set(self.success["properties"])
        self.assertEqual(probe.SUCCESS_KEYS, required)
        self.assertEqual(probe.SUCCESS_KEYS, properties)
        self.assertFalse(self.success["additionalProperties"])

    def test_success_constants_match_current_probe(self) -> None:
        constants = {
            name: value["const"]
            for name, value in self.success["properties"].items()
            if "const" in value
        }
        self.assertEqual(
            {
                "canary_survived": True,
                "changes_made": True,
                "cleanup_complete": True,
                "installation_performed": False,
                "journal_history_may_persist": True,
                "mode": "containment-primitive-probe",
                "network_requests_made": False,
                "primitive": "pidfd-stop+cgroup.kill",
                "result": "TERMINATED",
                "root_populated": 0,
                "target_processes": 2,
                "target_survivors": 0,
                "workload_detection_performed": False,
            },
            constants,
        )

    def test_refusal_contract_matches_redacted_runtime_receipt(self) -> None:
        receipt = probe.failure_receipt("ROOT_REQUIRED")
        self.assertEqual(set(receipt), set(self.refusal["required"]))
        self.assertEqual(set(receipt), set(self.refusal["properties"]))
        self.assertFalse(self.refusal["additionalProperties"])
        self.assertEqual(receipt["mode"], self.refusal["properties"]["mode"]["const"])
        self.assertEqual(receipt["result"], self.refusal["properties"]["result"]["const"])
        self.assertEqual("^[A-Z][A-Z0-9_]{2,63}$", self.refusal["properties"]["reason_code"]["pattern"])


if __name__ == "__main__":
    unittest.main()
