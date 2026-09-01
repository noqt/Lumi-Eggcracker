from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "validate-hosted-proof-receipt.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class ReusableReceiptWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_workflow_exposes_only_one_required_string_input(self) -> None:
        self.assertEqual(
            {
                "workflow_call": {
                    "inputs": {
                        "receipt": {
                            "description": (
                                "Path to one local hosted-proof receipt JSON object"
                            ),
                            "required": True,
                            "type": "string",
                        }
                    }
                }
            },
            self.workflow[True],
        )
        self.assertNotIn("outputs", self.workflow[True]["workflow_call"])
        self.assertNotIn("secrets", self.workflow[True]["workflow_call"])

    def test_workflow_is_read_only_and_uses_pinned_actions(self) -> None:
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        self.assertEqual(
            {
                "runs-on": "ubuntu-24.04",
                "timeout-minutes": 5,
                "steps": [
                    {
                        "uses": (
                            "actions/checkout@"
                            "d23441a48e516b6c34aea4fa41551a30e30af803"
                        ),
                        "with": {"persist-credentials": False},
                    },
                    {
                        "name": "Validate the local v1 receipt structure",
                        "uses": (
                            "noqt/Lumi-Eggcracker/actions/"
                            "validate-hosted-proof-receipt@"
                            "7cbd20d936e37531eb020d11ec3d4ddc9f1d8245"
                        ),
                        "with": {"receipt": "${{ inputs.receipt }}"},
                    },
                ],
            },
            self.workflow["jobs"]["validate"],
        )

    def test_ci_replays_the_reusable_caller_path(self) -> None:
        ci = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "name": "receipt-action-consumer",
                "uses": "./.github/workflows/validate-hosted-proof-receipt.yml",
                "with": {
                    "receipt": (
                        "schemas/examples/hosted-proof-receipt-v1-success.json"
                    )
                },
            },
            ci["jobs"]["receipt-action-consumer"],
        )

    def test_workflow_does_not_upload_or_interpolate_the_receipt_in_a_shell(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("run:", text)
        self.assertNotIn("secrets: inherit", text)


if __name__ == "__main__":
    unittest.main()
