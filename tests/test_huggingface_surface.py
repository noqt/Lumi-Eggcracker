from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_huggingface_surface import (
    SurfaceBuildError,
    _policy_root_file,
    _require_unique_paths,
    _tree_path,
    build_surface,
)


class HuggingFaceSurfaceTest(unittest.TestCase):
    def test_rejects_nonportable_or_noncanonical_git_paths(self) -> None:
        for raw_path in (
            b"../escape",
            b"folder\\escape",
            b"folder//escape",
            b"./escape",
            b"C:escape",
            b"C:/escape",
            b"file:stream",
            b"CON",
            b"folder/aux.txt",
            b"folder/LPT1.log",
            b"trailing.",
            b"trailing ",
        ):
            with (
                self.subTest(raw_path=raw_path),
                self.assertRaisesRegex(SurfaceBuildError, "unsafe or non-portable"),
            ):
                _tree_path(raw_path)

        with self.assertRaisesRegex(SurfaceBuildError, "portable path collision"):
            _require_unique_paths(
                [PurePosixPath("README.md"), PurePosixPath("readme.md")],
                "test paths",
            )

    def test_policy_outputs_are_distinct_portable_root_files(self) -> None:
        for value in ("../marker.json", "nested/marker.json", "C:marker.json", "marker.json:stream", "NUL"):
            with self.subTest(value=value), self.assertRaises(SurfaceBuildError):
                _policy_root_file(value, "source_marker")

        marker = _policy_root_file("HUGGINGFACE_SYNC.json", "source_marker")
        manifest = _policy_root_file("HUGGINGFACE_MANIFEST.json", "manifest")
        _require_unique_paths([marker, manifest], "sync policy outputs")

    def test_builds_exact_tracked_surface_with_reviewed_overlays(self) -> None:
        revision = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "surface"
            summary = build_surface(ROOT, output, revision)

            marker = json.loads((output / "HUGGINGFACE_SYNC.json").read_text(encoding="utf-8"))
            manifest_path = output / "HUGGINGFACE_MANIFEST.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            readme = (output / "README.md").read_text(encoding="utf-8")
            index = (output / "index.html").read_text(encoding="utf-8")

            self.assertEqual(revision, marker["source_revision"])
            self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), marker["manifest_sha256"])
            self.assertEqual(revision, manifest["source_revision"])
            self.assertEqual(len(manifest["files"]), marker["mirrored_files"])
            self.assertEqual(len(manifest["files"]) + 2, summary["mirrored_files"])

            self.assertTrue(readme.startswith("---\ntitle: Lumi Eggcracker\n"))
            self.assertIn(revision, readme)
            self.assertIn("git clone https://huggingface.co/spaces/noqt/eggcracker", readme)
            self.assertNotIn("git clone https://github.com/noqt/Lumi-Eggcracker.git", readme)
            retired_reference = "scadastrangelove/" + "awesome-ai-security-tools"
            self.assertNotIn(retired_reference, readme)
            self.assertIn(revision, index)
            self.assertIn(f"SOURCE COMMIT · {revision[:12]}", index)
            stale_revision = "bf6910dbd83d30a50a486f84" + "ac0fa96a0244e23e"
            self.assertNotIn(stale_revision, index)

            current_vllm = ROOT / "scripts" / "check_vllm_compatibility.py"
            mirrored_vllm = output / "scripts" / "check_vllm_compatibility.py"
            self.assertEqual(current_vllm.read_bytes(), mirrored_vllm.read_bytes())
            self.assertFalse((output / ".github").exists())
            self.assertFalse((output / "docs" / "huggingface").exists())
            for path in output.rglob("*"):
                if path.is_file():
                    self.assertNotIn(retired_reference.encode(), path.read_bytes())

            workflow = (ROOT / ".github" / "workflows" / "sync-huggingface.yml").read_text(encoding="utf-8")
            self.assertIn("if: github.ref == 'refs/heads/main'", workflow)
            self.assertIn("persist-credentials: false", workflow)

    def test_rejects_non_exact_revision_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaisesRegex(SurfaceBuildError, "40-character Git SHA"):
                build_surface(ROOT, root / "bad-revision", "main")

            with self.assertRaisesRegex(SurfaceBuildError, "requested Git source commit"):
                build_surface(ROOT, root / "missing-commit", "a" * 40)

            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(SurfaceBuildError, "already exists"):
                build_surface(ROOT, existing, "b" * 40)


if __name__ == "__main__":
    unittest.main()
