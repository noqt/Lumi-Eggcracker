from __future__ import annotations

import importlib.util
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_release", ROOT / "scripts" / "verify_release.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release verifier")
verify_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_release)


class ReleaseArchiveTests(unittest.TestCase):
    def test_verifier_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive_path = Path(raw) / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("release/install.py", "trusted")
                    archive.writestr("release/install.py", "hostile")
            with (
                zipfile.ZipFile(archive_path) as archive,
                self.assertRaisesRegex(SystemExit, "duplicate path"),
            ):
                verify_release.validated_members(archive)

    def test_verifier_rejects_special_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive_path = Path(raw) / "special.zip"
            member = zipfile.ZipInfo("release/install.py")
            member.create_system = 3
            member.external_attr = (stat.S_IFIFO | 0o600) << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(member, "not-a-file")
            with (
                zipfile.ZipFile(archive_path) as archive,
                self.assertRaisesRegex(SystemExit, "link or special"),
            ):
                verify_release.validated_members(archive)


if __name__ == "__main__":
    unittest.main()
