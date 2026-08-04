from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.artifacts import validate_path


def gguf(*, version: int = 3, tensors: int = 1, metadata: int = 0, padding: int = 64) -> bytes:
    return b"GGUF" + struct.pack("<IQQ", version, tensors, metadata) + b"\0" * padding


class ArtifactTests(unittest.TestCase):
    def test_valid_gguf_content_does_not_depend_on_filename(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "opaque-input"
            path.write_bytes(gguf())
            evidence = validate_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual("gguf-v3", evidence.evidence_id)
            self.assertNotIn(path.name, evidence.header_sha256)

    def test_bad_magic_version_and_impossible_counts_do_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, body in enumerate(
                (b"NOPE" + gguf()[4:], gguf(version=1), gguf(tensors=1_000_000, padding=1))
            ):
                path = root / str(index)
                path.write_bytes(body)
                self.assertIsNone(validate_path(path))

    def test_symlink_and_non_regular_files_do_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target"
            link = root / "link"
            target.write_bytes(gguf())
            try:
                os.symlink(target, link)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            self.assertIsNone(validate_path(link))
