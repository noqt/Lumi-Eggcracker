from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "actions" / "validate-hosted-proof-receipt" / "action.yml"


class HostedProofReceiptActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = yaml.safe_load(ACTION.read_text(encoding="utf-8"))

    def test_action_exposes_only_one_required_local_receipt_input(self) -> None:
        self.assertEqual(
            {
                "receipt": {
                    "description": "Path to one local hosted-proof receipt JSON object",
                    "required": True,
                }
            },
            self.metadata["inputs"],
        )
        self.assertNotIn("outputs", self.metadata)

    def test_action_passes_the_path_by_environment_to_the_local_validator(self) -> None:
        self.assertEqual("composite", self.metadata["runs"]["using"])
        self.assertEqual(1, len(self.metadata["runs"]["steps"]))
        step = self.metadata["runs"]["steps"][0]
        self.assertEqual("bash --noprofile --norc -euo pipefail {0}", step["shell"])
        self.assertEqual({"RECEIPT_PATH": "${{ inputs.receipt }}"}, step["env"])
        self.assertEqual(
            'python3 "$GITHUB_ACTION_PATH/../../scripts/validate_hosted_proof_receipt.py" '
            '"$RECEIPT_PATH"\n',
            step["run"],
        )
        self.assertNotIn("inputs.receipt", step["run"])


if __name__ == "__main__":
    unittest.main()
