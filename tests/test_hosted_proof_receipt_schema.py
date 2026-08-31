from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

from jsonschema import ValidationError
from jsonschema.validators import validator_for

from lumi_eggcracker import containment_probe as probe

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "hosted-proof-receipt-v1.schema.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "containment-probe.yml"


def workflow_failure_codes() -> set[str]:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    match = re.search(r"allowed_failures = (\{.*?^\s*\})", workflow, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError("hosted workflow failure allowlist is missing")
    values = ast.literal_eval(match.group(1))
    if not isinstance(values, set) or not all(isinstance(value, str) for value in values):
        raise AssertionError("hosted workflow failure allowlist is invalid")
    return values


def workflow_latency_maximum_ms() -> int:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    match = re.search(r"or latency > ([0-9_]+)", workflow)
    if match is None:
        raise AssertionError("hosted workflow latency bound is missing")
    return int(match.group(1).replace("_", ""))


def success_receipt() -> dict[str, object]:
    return {
        "canary_survived": True,
        "changes_made": True,
        "cleanup_complete": True,
        "descendant_cgroups_checked": 1,
        "installation_performed": False,
        "journal_history_may_persist": True,
        "mode": "containment-primitive-probe",
        "network_requests_made": False,
        "primitive": "pidfd-stop+cgroup.kill",
        "result": "TERMINATED",
        "root_populated": 0,
        "source_commit": "a" * 40,
        "source_tree_sha256": "b" * 64,
        "target_processes": 2,
        "target_survivors": 0,
        "trigger_to_empty_ms": 1.25,
        "workload_detection_performed": False,
    }


class HostedProofReceiptSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator_class = validator_for(cls.schema)
        validator_class.check_schema(cls.schema)
        cls.validator = validator_class(cls.schema)
        cls.success = cls.schema["oneOf"][0]
        cls.failure = cls.schema["oneOf"][1]

    def test_schema_identity_is_public_and_versioned(self) -> None:
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", self.schema["$schema"])
        self.assertEqual(
            "https://raw.githubusercontent.com/noqt/Lumi-Eggcracker/main/"
            "schemas/hosted-proof-receipt-v1.schema.json",
            self.schema["$id"],
        )

    def test_success_contract_matches_runtime_keys_and_validates_current_shape(self) -> None:
        required = set(self.success["required"])
        properties = set(self.success["properties"])
        self.assertEqual(probe.SUCCESS_KEYS, required)
        self.assertEqual(probe.SUCCESS_KEYS, properties)
        self.assertFalse(self.success["additionalProperties"])
        self.validator.validate(success_receipt())

    def test_success_latency_bound_matches_probe_and_hosted_workflow(self) -> None:
        maximum = self.success["properties"]["trigger_to_empty_ms"]["maximum"]
        self.assertEqual(probe.TOTAL_TIMEOUT_SECONDS * 1000, maximum)
        self.assertEqual(workflow_latency_maximum_ms(), maximum)

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

    def test_failure_contract_matches_every_workflow_accepted_code(self) -> None:
        codes = workflow_failure_codes()
        self.assertEqual(codes, set(self.failure["properties"]["reason_code"]["enum"]))
        self.assertEqual(set(probe.failure_receipt("ROOT_REQUIRED")), set(self.failure["required"]))
        self.assertEqual(set(self.failure["required"]), set(self.failure["properties"]))
        self.assertFalse(self.failure["additionalProperties"])
        for code in codes:
            with self.subTest(code=code):
                self.validator.validate(probe.failure_receipt(code))

    def test_unknown_failure_code_and_extra_properties_are_rejected(self) -> None:
        invalid_receipts = [
            probe.failure_receipt("UNRECOGNIZED_SAFE_REFUSAL"),
            {**probe.failure_receipt("ROOT_REQUIRED"), "detail": "/private/path"},
            {**success_receipt(), "detail": "unexpected"},
        ]
        for receipt in invalid_receipts:
            with self.subTest(receipt=receipt), self.assertRaises(ValidationError):
                self.validator.validate(receipt)

    def test_wrong_constants_and_types_are_rejected(self) -> None:
        wrong_result = {**success_receipt(), "result": "FAILED"}
        wrong_latency = {**success_receipt(), "trigger_to_empty_ms": "1.25"}
        excessive_latency = {**success_receipt(), "trigger_to_empty_ms": 20_000.001}
        wrong_failure_result = {**probe.failure_receipt("ROOT_REQUIRED"), "result": "TERMINATED"}
        for receipt in (wrong_result, wrong_latency, excessive_latency, wrong_failure_result):
            with self.subTest(receipt=receipt), self.assertRaises(ValidationError):
                self.validator.validate(receipt)


if __name__ == "__main__":
    unittest.main()
