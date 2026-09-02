from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = load_script("smoke_local_ai")
content_smoke = load_script("smoke_content_ai")
prepare = load_script("prepare_ai_smoke")
sys.path.insert(0, str(ROOT / "scripts"))
try:
    autonomous_matrix = load_script("run_autonomous_matrix")
    content_adversarial = load_script("run_content_adversarial_matrix")
finally:
    sys.path.pop(0)


class AiSmokeTests(unittest.TestCase):
    def test_autonomous_approved_outcomes_exclude_termination(self) -> None:
        self.assertTrue(autonomous_matrix.approved_outcome("RUNNING"))
        self.assertTrue(autonomous_matrix.approved_outcome("COMPLETED_ALLOWED"))
        self.assertFalse(autonomous_matrix.approved_outcome("TERMINATED"))
        self.assertFalse(autonomous_matrix.approved_outcome("CONTAINMENT_FAILED"))

    def test_autonomous_cleanup_accepts_one_exact_benign_completion(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            runs = Path(raw)
            (runs / "a.json").write_text(
                json.dumps({"name": "approved-test", "state": "COMPLETED_ALLOWED"}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(autonomous_matrix, "RUNS", runs),
                mock.patch.object(
                    autonomous_matrix,
                    "call",
                    side_effect=RuntimeError("workload name is unavailable"),
                ),
            ):
                autonomous_matrix.stop_selected("operator", "approved-test")

    def test_autonomous_cleanup_does_not_mask_termination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            runs = Path(raw)
            (runs / "a.json").write_text(
                json.dumps({"name": "approved-test", "state": "TERMINATED"}),
                encoding="utf-8",
            )
            with (
                mock.patch.object(autonomous_matrix, "RUNS", runs),
                mock.patch.object(
                    autonomous_matrix,
                    "call",
                    side_effect=RuntimeError("workload name is unavailable"),
                ),
                self.assertRaisesRegex(RuntimeError, "workload name is unavailable"),
            ):
                autonomous_matrix.stop_selected("operator", "approved-test")

    def test_autonomous_incident_cleanup_waits_for_post_receipt_response(self) -> None:
        empty = {"incidents": []}
        active = {
            "incidents": [
                {"incident_id": "event-late", "state": "ACTIVE"},
            ]
        }
        cleared = {
            "incidents": [
                {"incident_id": "event-late", "state": "CLEARED"},
            ]
        }
        with (
            mock.patch.object(
                autonomous_matrix,
                "root_call",
                side_effect=[empty, active, {}, cleared],
            ) as control,
            mock.patch.object(autonomous_matrix.time, "sleep"),
        ):
            count = autonomous_matrix.clear_new_incidents(
                set(),
                expected_event_id="event-late",
                timeout=10,
                settle_seconds=0,
            )
        self.assertEqual(1, count)
        control.assert_any_call(["incident", "clear", "event-late"])

    def test_manifest_assets_must_match_their_recorded_digests(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner, model = root / "llama-cli", root / "model.gguf"
            runner.write_bytes(b"runner")
            runner.chmod(0o755)
            model.write_bytes(b"model")
            manifest = root / "assets.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": smoke.ASSET_SCHEMA,
                        "platform": {},
                        "llama": {
                            "path": str(runner),
                            "sha256": hashlib.sha256(b"runner").hexdigest(),
                        },
                        "model": {
                            "path": str(model),
                            "sha256": hashlib.sha256(b"model").hexdigest(),
                        },
                    }
                ),
                encoding="utf-8",
            )
            loaded_runner, loaded_model, _ = smoke.assets_from_manifest(manifest)
            self.assertEqual(runner, loaded_runner)
            self.assertEqual(model, loaded_model)
            runner.write_bytes(b"altered")
            with self.assertRaisesRegex(RuntimeError, "digest"):
                smoke.assets_from_manifest(manifest)

    def test_generated_output_requires_visible_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "generated.txt"
            prompt = "test prompt"
            output.write_bytes(b"startup output\n> test prompt\n" + b"x" * 31)
            self.assertFalse(smoke.generated(output, prompt))
            output.write_bytes(b"startup output\n> test prompt\n" + b"x" * 32)
            self.assertTrue(smoke.generated(output, prompt))
            self.assertFalse(smoke.generated(output, "other prompt"))

    def test_prepare_script_keeps_external_asset_inputs_pinned(self) -> None:
        self.assertEqual("b10240", prepare.LLAMA_TAG)
        self.assertEqual(40, len(prepare.LLAMA_COMMIT))
        self.assertEqual(64, len(prepare.MODEL_SHA256))
        self.assertIn("/resolve/", prepare.MODEL_URL)

    def test_prepare_build_parallelism_matches_small_host(self) -> None:
        with mock.patch.object(prepare.os, "cpu_count", return_value=2):
            command = prepare.build_command(Path("/tmp/build"))
        self.assertEqual("--parallel", command[-2])
        self.assertEqual("2", command[-1])

    def test_prepare_build_parallelism_has_a_ceiling(self) -> None:
        with mock.patch.object(prepare.os, "cpu_count", return_value=128):
            command = prepare.build_command(Path("/tmp/build"))
        self.assertEqual(str(prepare.MAX_BUILD_JOBS), command[-1])

    def test_prepare_build_parallelism_defaults_to_one(self) -> None:
        with mock.patch.object(prepare.os, "cpu_count", return_value=None):
            command = prepare.build_command(Path("/tmp/build"))
        self.assertEqual("1", command[-1])

    def test_smoke_path_does_not_use_a_shell_wrapper(self) -> None:
        source = (ROOT / "scripts" / "smoke_local_ai.py").read_text(encoding="utf-8")
        worker = (ROOT / "scripts" / "ai_smoke_worker.py").read_text(encoding="utf-8")
        self.assertNotIn("/bin/sh", source)
        self.assertIn("ai_smoke_worker.py", source)
        self.assertIn("raise SystemExit(main())", worker)

    def test_content_smoke_keeps_real_model_alive_until_containment(self) -> None:
        command = content_smoke.command(Path("/runner"), Path("/model"))
        self.assertIn("--ignore-eos", command)

    def test_adversarial_descendant_marker_binds_pid_and_start_time(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / "children"
            marker.write_text("41:101 42:102\n", encoding="ascii")
            self.assertEqual([(41, 101), (42, 102)], content_adversarial.child_identities(marker))

    def test_adversarial_zombie_is_not_an_executing_survivor(self) -> None:
        with mock.patch.object(content_adversarial, "process_identity", return_value=("Z", 101)):
            self.assertFalse(content_adversarial.identity_alive((41, 101)))

    def test_adversarial_pid_reuse_is_not_the_original_survivor(self) -> None:
        with mock.patch.object(content_adversarial, "process_identity", return_value=("S", 202)):
            self.assertFalse(content_adversarial.identity_alive((41, 101)))

    def test_adversarial_live_original_identity_blocks_empty_proof(self) -> None:
        with mock.patch.object(content_adversarial, "process_identity", return_value=("S", 101)):
            self.assertTrue(content_adversarial.identity_alive((41, 101)))
