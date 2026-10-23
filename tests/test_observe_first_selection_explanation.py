from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker import observe_first

ROOT = Path(__file__).resolve().parents[1]


def _input(
    *,
    content: list[str],
    runtime: list[str],
    topology: list[str],
) -> dict[str, object]:
    return {
        "schema_version": observe_first.SCHEMA,
        "synthetic": True,
        "quiescent": True,
        "offline": True,
        "snapshot": {
            "exe_basename": "synthetic-runtime",
            "argv": ["synthetic-runtime"],
            "fd_paths": [],
            "map_basenames": [],
        },
        "evidence": {
            "MODEL_CONTENT": content,
            "MODEL_RUNTIME": runtime,
            "MODEL_TOPOLOGY": topology,
        },
    }


def _vllm_input(*, include_vllm_topology: bool = True) -> dict[str, object]:
    return _input(
        content=["safetensors-v1"],
        runtime=["pytorch-bridge-aten-pair-pinned-cpu"],
        topology=(
            ["vllm-python-extension-pair-pinned-cpu"]
            if include_vllm_topology
            else []
        ),
    )


class SelectionExplanationTests(unittest.TestCase):
    def test_default_api_output_is_unchanged_without_opt_in(self) -> None:
        observation = observe_first.parse_input(_vllm_input())
        default = observe_first.evaluate(observation)
        explicit_false = observe_first.evaluate(observation, explain_selection=False)

        self.assertEqual(default, explicit_false)
        self.assertNotIn("selection_explanation", default)

    def test_full_vllm_evidence_reports_overlapping_profiles_and_first_match(self) -> None:
        result = observe_first.evaluate(
            observe_first.parse_input(_vllm_input()), explain_selection=True
        )

        self.assertEqual("WOULD_ACT", result["result"])
        self.assertEqual(
            "content.safetensors-vllm", result["match"]["profile"]  # type: ignore[index]
        )
        self.assertEqual(
            ["content.safetensors-vllm", "content.safetensors-pytorch"],
            result["selection_explanation"]["complete_content_profile_ids"],  # type: ignore[index]
        )
        self.assertEqual(
            "content.safetensors-vllm",
            result["selection_explanation"]["selected_profile"],  # type: ignore[index]
        )
        self.assertEqual(
            "The detector selects the first complete CONTENT requirement profile in maintained "
            "catalogue order.",
            result["selection_explanation"]["selection_rule"],  # type: ignore[index]
        )

    def test_removing_only_vllm_topology_selects_pytorch(self) -> None:
        result = observe_first.evaluate(
            observe_first.parse_input(_vllm_input(include_vllm_topology=False)),
            explain_selection=True,
        )

        self.assertEqual("WOULD_ACT", result["result"])
        self.assertEqual(
            "content.safetensors-pytorch", result["match"]["profile"]  # type: ignore[index]
        )
        self.assertEqual(
            ["content.safetensors-pytorch"],
            result["selection_explanation"]["complete_content_profile_ids"],  # type: ignore[index]
        )
        self.assertEqual(
            "content.safetensors-pytorch",
            result["selection_explanation"]["selected_profile"],  # type: ignore[index]
        )

    def test_no_complete_match_explains_empty_without_changing_verdict(self) -> None:
        value = _input(content=[], runtime=[], topology=[])
        result = observe_first.evaluate(
            observe_first.parse_input(value), explain_selection=True
        )

        self.assertEqual("NO_COMPLETE_MATCH", result["result"])
        self.assertIsNone(result["match"])
        self.assertEqual([], result["selection_explanation"]["complete_content_profile_ids"])  # type: ignore[index]
        self.assertIsNone(result["selection_explanation"]["selected_profile"])  # type: ignore[index]

    def test_explanation_is_inert_and_keeps_validation_limits(self) -> None:
        result = observe_first.evaluate(
            observe_first.parse_input(_vllm_input()), explain_selection=True
        )
        self.assertFalse(result["actuation_performed"])
        self.assertTrue(result["simulation_only"])
        self.assertTrue(result["offline_only"])
        self.assertIn(
            "true workload or framework identity",
            result["selection_explanation"]["limitations"][0],  # type: ignore[index]
        )

        invalid = _vllm_input()
        invalid["evidence"] = {
            "MODEL_CONTENT": ["unknown-evidence"],
            "MODEL_RUNTIME": ["pytorch-bridge-aten-pair-pinned-cpu"],
            "MODEL_TOPOLOGY": [],
        }
        with self.assertRaises(observe_first.ObserveFirstInputError):
            observe_first.evaluate(
                observe_first.parse_input(invalid), explain_selection=True
            )

    def test_cli_opt_in_emits_selection_explanation(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "vllm.json"
            fixture.write_text(json.dumps(_vllm_input()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lumi_eggcracker.observe_first",
                    "--explain-selection",
                    str(fixture),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual("WOULD_ACT", payload["result"])
        self.assertEqual(
            ["content.safetensors-vllm", "content.safetensors-pytorch"],
            payload["selection_explanation"]["complete_content_profile_ids"],
        )
        self.assertEqual(
            "content.safetensors-vllm",
            payload["selection_explanation"]["selected_profile"],
        )

    def test_cli_without_opt_in_has_no_new_field(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        fixture = ROOT / "examples" / "observe-first" / "complete-match.json"
        completed = subprocess.run(
            [sys.executable, "-m", "lumi_eggcracker.observe_first", str(fixture)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertNotIn("selection_explanation", json.loads(completed.stdout))


if __name__ == "__main__":
    unittest.main()
