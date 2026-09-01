from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FORM = ROOT / ".github" / "ISSUE_TEMPLATE" / "hosted_probe_result.yml"


class HostedProbeResultFormTests(unittest.TestCase):
    def test_current_run_follow_up_is_explicit_and_required(self) -> None:
        form = yaml.safe_load(FORM.read_text(encoding="utf-8"))
        fields = [item for item in form["body"] if "id" in item]
        self.assertEqual(
            ["outcome", "workflow_run", "friction", "follow_up", "safety"],
            [item["id"] for item in fields],
        )
        follow_up = next(item for item in fields if item["id"] == "follow_up")
        self.assertEqual("dropdown", follow_up["type"])
        self.assertEqual(
            {
                "label": "Do you want one public next step?",
                "description": (
                    "Choose whether NOQT should reply publicly with one exact "
                    "supported next step for this current run. This is current-product "
                    "support, not a request for product direction or a promise of "
                    "private support."
                ),
                "options": [
                    "Yes - reply publicly with one exact supported next step",
                    "No - record this current-use result without follow-up",
                ],
            },
            follow_up["attributes"],
        )
        self.assertEqual({"required": True}, follow_up["validations"])


if __name__ == "__main__":
    unittest.main()
