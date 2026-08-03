from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = load_script("smoke_local_ai")
prepare = load_script("prepare_ai_smoke")


class AiSmokeTests(unittest.TestCase):
    def test_manifest_assets_must_match_their_recorded_digests(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner, model = root / "llama-cli", root / "model.gguf"
            runner.write_bytes(b"runner")
            runner.chmod(0o755)
            model.write_bytes(b"model")
            manifest = root / "assets.json"
            manifest.write_text(json.dumps({
                "schema_version": smoke.ASSET_SCHEMA,
                "platform": {},
                "llama": {"path": str(runner), "sha256": hashlib.sha256(b"runner").hexdigest()},
                "model": {"path": str(model), "sha256": hashlib.sha256(b"model").hexdigest()},
            }), encoding="utf-8")
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

    def test_smoke_path_does_not_use_a_shell_wrapper(self) -> None:
        source = (ROOT / "scripts" / "smoke_local_ai.py").read_text(encoding="utf-8")
        self.assertNotIn("/bin/sh", source)
        self.assertIn("ai_smoke_worker.py", source)
