from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_huggingface_surface import (
    BOUND_RELEASE,
    SurfaceBuildError,
    _policy_root_file,
    _require_unique_paths,
    _tree_path,
    _validated_release_reference,
    build_surface,
)
from upload_huggingface_surface import UploadError, upload_surface
from verify_huggingface_surface import VerificationError, verify_surface


class HuggingFaceSurfaceTest(unittest.TestCase):
    def _minimal_surface(self, root: Path, revision: str) -> tuple[Path, Path, Path]:
        staging = root / "surface"
        staging.mkdir()
        payload = b"fixture\n"
        (staging / "README.md").write_bytes(payload)
        manifest = {
            "schema": "noqt.huggingface_manifest.v1",
            "source_repository": "https://github.com/noqt/Lumi-Eggcracker",
            "source_revision": revision,
            "source_url": f"https://github.com/noqt/Lumi-Eggcracker/commit/{revision}",
            "release_reference": {},
            "files": {"README.md": {"sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}},
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        (staging / "HUGGINGFACE_MANIFEST.json").write_bytes(manifest_bytes)
        marker = {
            "schema": "noqt.huggingface_sync.v1",
            "mode": "DERIVED_READ_ONLY_MIRROR",
            "source_repository": manifest["source_repository"],
            "source_revision": revision,
            "source_url": manifest["source_url"],
            "release_reference": {},
            "target": "https://huggingface.co/spaces/noqt/eggcracker",
            "manifest": "HUGGINGFACE_MANIFEST.json",
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "mirrored_files": 1,
        }
        (staging / "HUGGINGFACE_SYNC.json").write_text(json.dumps(marker), encoding="utf-8")
        upload_record = root / "upload.json"
        upload_record.write_text(
            json.dumps(
                {
                    "schema": "noqt.huggingface_upload.v1",
                    "repository": "noqt/eggcracker",
                    "repo_type": "space",
                    "branch": "main",
                    "source_revision": revision,
                    "parent_commit": "1" * 40,
                    "upload_commit": "2" * 40,
                    "manifest_sha256": marker["manifest_sha256"],
                }
            ),
            encoding="utf-8",
        )
        return staging, upload_record, root / "report.json"

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

    def test_policy_binds_release_boundary_and_only_authorized_triggers(self) -> None:
        policy = json.loads((ROOT / "huggingface-sync-policy.json").read_text(encoding="utf-8"))
        self.assertEqual(
            {"PUSH_TO_MAIN", "RELEASE_PUBLISHED", "WORKFLOW_DISPATCH"},
            set(policy["sync_triggers"]),
        )
        self.assertNotIn("DAILY_DRIFT_REPAIR", policy["sync_triggers"])
        self.assertEqual(BOUND_RELEASE["source_commit"], policy["release_reference"]["source_commit"])
        self.assertEqual(
            BOUND_RELEASE["release_manifest_sha256"],
            policy["release_reference"]["release_manifest"]["sha256"],
        )
        self.assertEqual(policy["release_reference"], _validated_release_reference(policy))

        workflow = (ROOT / ".github" / "workflows" / "sync-huggingface.yml").read_text(encoding="utf-8")
        self.assertNotIn("schedule:", workflow)
        self.assertIn("release:", workflow)
        self.assertIn("types: [published]", workflow)
        self.assertIn("ref: ${{ github.event_name == 'release' && 'main' || github.sha }}", workflow)
        self.assertIn("RELEASE_TAG: ${{ github.event.release.tag_name }}", workflow)
        self.assertIn("refs/tags/$RELEASE_TAG^{tag}", workflow)
        self.assertNotIn("source_ref='${{ github.event.release.tag_name }}'", workflow)
        self.assertIn("upload_huggingface_surface.py", workflow)
        self.assertIn("verify_huggingface_surface.py", workflow)
        self.assertIn("--source-root .", workflow)
        self.assertIn("parent_commit", (ROOT / "scripts" / "upload_huggingface_surface.py").read_text(encoding="utf-8"))

    def test_upload_and_readback_fail_closed_without_hub_auth(self) -> None:
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            staging, upload_record, report = self._minimal_surface(Path(temp_dir), revision)
            with patch.dict(os.environ, {"HF_TOKEN": ""}):
                with self.assertRaisesRegex(UploadError, "HF_TOKEN is missing"):
                    upload_surface(
                        repo_id="noqt/eggcracker",
                        repo_type="space",
                        folder=staging,
                        revision="main",
                        source_revision=revision,
                        output=Path(temp_dir) / "upload-result.json",
                    )
                with self.assertRaisesRegex(VerificationError, "HF_TOKEN is missing"):
                    verify_surface(
                        repo_id="noqt/eggcracker",
                        repo_type="space",
                        staging=staging,
                        upload_record=upload_record,
                        source_revision=revision,
                        readback=Path(temp_dir) / "readback",
                        report=report,
                    )

    def test_upload_rejects_stale_candidate_after_newer_remote_source(self) -> None:
        candidate = subprocess.run(
            ["git", "rev-parse", "HEAD^"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        remote_source = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as temp_dir:
            staging, _, _ = self._minimal_surface(Path(temp_dir), candidate)
            remote_marker = Path(temp_dir) / "remote-marker.json"
            remote_marker.write_text(
                json.dumps({"schema": "noqt.huggingface_sync.v1", "source_revision": remote_source}),
                encoding="utf-8",
            )
            fake_api = SimpleNamespace(
                repo_info=lambda **_: SimpleNamespace(sha="2" * 40),
                hf_hub_download=lambda **_: str(remote_marker),
                upload_folder=Mock(),
            )
            fake_hub = SimpleNamespace(HfApi=lambda **_: fake_api)
            with (
                patch.dict(os.environ, {"HF_TOKEN": "test-token"}),
                patch.dict(sys.modules, {"huggingface_hub": fake_hub}),
                self.assertRaisesRegex(UploadError, "not an ancestor"),
            ):
                upload_surface(
                    repo_id="noqt/eggcracker",
                    repo_type="space",
                    folder=staging,
                    revision="main",
                    source_revision=candidate,
                    output=Path(temp_dir) / "upload-result.json",
                    source_root=ROOT,
                )
            fake_api.upload_folder.assert_not_called()

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
            self.assertEqual(revision, marker["source_url"].rsplit("/", 1)[-1])
            self.assertEqual(policy_release := marker["release_reference"], manifest["release_reference"])
            self.assertEqual(BOUND_RELEASE["source_commit"], policy_release["source_commit"])
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
            self.assertNotIn("Official NOQT", readme)
            self.assertIn("Official noqt", readme)
            self.assertNotIn("NOQT / EGGCRACKER", index)
            self.assertIn("noqt / Lumi Eggcracker", index)

            current_vllm = ROOT / "scripts" / "check_vllm_compatibility.py"
            mirrored_vllm = output / "scripts" / "check_vllm_compatibility.py"
            self.assertEqual(current_vllm.read_bytes(), mirrored_vllm.read_bytes())
            self.assertFalse((output / ".github").exists())
            self.assertFalse((output / "docs" / "huggingface").exists())
            for path in output.rglob("*"):
                if path.is_file():
                    self.assertNotIn(retired_reference.encode(), path.read_bytes())

            workflow = (ROOT / ".github" / "workflows" / "sync-huggingface.yml").read_text(encoding="utf-8")
            self.assertIn("github.event_name == 'release' || github.ref == 'refs/heads/main'", workflow)
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
