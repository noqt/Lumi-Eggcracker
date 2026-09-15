"""Offline checks for the small, direct-Linux v2 reproduction slice."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1].resolve()
PORTABLE = ROOT / "experiments" / "counter_ai_v2_portable"
CORE_PINS = {
    "experiments/counter_ai_v2/__init__.py": "f575ebebdd9d763e40f78c4036ab68e73cc13814277db6d95dc8c85037933769",
    "experiments/counter_ai_v2/native_demo.py": "cb836ab6fcc4c0f0bd9108725810d1f3e89c9f9b84e4f15d526d2836e36d84a2",
    "experiments/counter_ai_v2/workload.py": "fbbf8739ef69890c3c7ab49696768d4d2ea643ce4dd364952909589bf5765ad1",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PortableReproductionTests(unittest.TestCase):
    def test_frozen_core_is_exact_and_portable_does_not_copy_runner(self) -> None:
        for relative, expected in CORE_PINS.items():
            self.assertEqual(_sha256(ROOT / relative), expected, relative)
        self.assertFalse((PORTABLE / "vm_runner.py").exists())

    def test_protocol_is_source_only_with_exact_boundary_and_limits(self) -> None:
        protocol = json.loads((PORTABLE / "portable-protocol.v1.json").read_text(encoding="utf-8"))
        self.assertEqual(protocol["status"], "SOURCE_ONLY_OFF_BY_DEFAULT")
        self.assertEqual(protocol["boundary"]["network"], {"mode": "none", "host_shares": [], "passthrough": []})
        self.assertEqual(protocol["limits"]["selected_cpu_seconds"], 5)
        self.assertEqual(protocol["limits"]["selected_memory_bytes"], 268435456)
        self.assertEqual(protocol["limits"]["selected_max_processes"], 32)
        self.assertEqual(protocol["limits"]["fake_sink_bytes"], 16777216)
        self.assertEqual(protocol["limits"]["qemu_tcg_tb_cache_mib"], 128)
        self.assertEqual(protocol["limits"]["qemu_wall_seconds"], 600)
        self.assertIn("independent Risk acceptance", protocol["execution_gate"]["required"])
        self.assertEqual(protocol["command"]["shell"], False)

    def test_examples_are_parameterized_and_never_acceptance(self) -> None:
        artifact = json.loads((PORTABLE / "portable-artifact-manifest.example.json").read_text(encoding="utf-8"))
        source = json.loads((PORTABLE / "portable-source-manifest.example.json").read_text(encoding="utf-8"))
        self.assertEqual(artifact["status"], "EXAMPLE_NOT_AUTHORIZATION")
        self.assertEqual(artifact["source"]["experiments/counter_ai_v2/native_demo.py"], CORE_PINS["experiments/counter_ai_v2/native_demo.py"])
        self.assertEqual(artifact["source"]["experiments/counter_ai_v2/workload.py"], CORE_PINS["experiments/counter_ai_v2/workload.py"])
        self.assertNotIn("artifact_manifest_sha256", artifact["materialization"])
        self.assertIn("bind that digest only", artifact["materialization"]["rule"])
        self.assertIn("REPLACE_WITH_", source["artifact_manifest_sha256"])
        self.assertIn("REPLACE_WITH_", source["run_id"])
        self.assertIn("REPLACE_WITH_", source["run_nonce"])
        self.assertNotEqual(artifact.get("status"), "ACCEPTED")

    def test_default_frozen_native_entry_point_is_inert(self) -> None:
        from experiments.counter_ai_v2 import native_demo

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(native_demo.main([]), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["status"], "OFF_BY_DEFAULT")
        self.assertIn("--execute", plan["native_execution"])

    def test_docs_have_no_machine_specific_paths_or_private_runner_copy(self) -> None:
        for path in (PORTABLE / "README.md", PORTABLE / "portable-protocol.v1.json", PORTABLE / "portable-artifact-manifest.example.json", PORTABLE / "portable-source-manifest.example.json"):
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for drive in ("f", "g"):
                self.assertNotIn(drive + ":" + chr(92), lowered)
                self.assertNotIn(drive + ":/", lowered)
            self.assertNotIn("/root/", lowered)


if __name__ == "__main__":
    unittest.main()
