from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.artifacts import from_process_fds, from_snapshot, validate_path
from lumi_eggcracker.discovery import ProcessIdentity


def gguf(*, version: int = 3, tensors: int = 1, metadata: int = 0, padding: int = 64) -> bytes:
    return b"GGUF" + struct.pack("<IQQ", version, tensors, metadata) + b"\0" * padding


def safetensors(*, dtype: str = "F32", shape: list[int] | None = None, offsets: tuple[int, int] = (0, 8), metadata: dict[str, str] | None = None) -> bytes:
    value: dict[str, object] = {
        "tensor": {"dtype": dtype, "shape": shape if shape is not None else [2], "data_offsets": list(offsets)}
    }
    if metadata is not None:
        value["__metadata__"] = metadata
    header = json.dumps(value, separators=(",", ":")).encode("utf-8")
    header += b" " * ((8 - len(header) % 8) % 8)
    return struct.pack("<Q", len(header)) + header + b"\0" * max(0, offsets[1])


class ArtifactTests(unittest.TestCase):
    def test_descriptor_windows_eventually_cover_late_model_fd(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            directory = proc / "42" / "fd"
            directory.mkdir(parents=True)
            for number in range(20):
                (directory / str(number)).write_bytes(b"harmless")
            (directory / "20").write_bytes(gguf())
            sample = type("Snapshot", (), {"identity": ProcessIdentity(42, 100), "fd_entries": ()})()
            self.assertEqual(
                (), from_process_fds(sample, proc=proc, start_index=0, max_probes=16)
            )
            evidence = from_process_fds(
                sample, proc=proc, start_index=16, max_probes=16
            )
            self.assertEqual({"gguf-v3"}, {item.evidence_id for item in evidence})

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

    def test_ai_looking_filename_is_not_content_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "model.gguf"
            path.write_bytes(b"not a model")
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

    def test_valid_safetensors_is_extension_and_metadata_independent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "opaque-input"
            path.write_bytes(safetensors(metadata={"format": "pt"}))
            evidence = validate_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual("safetensors-v1", evidence.evidence_id)
            self.assertEqual("SAFETENSORS", evidence.format)

    def test_safetensors_rejects_duplicate_invalid_and_partial_headers(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            duplicate = b'{"tensor":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"tensor":{}}'
            duplicate_file = root / "duplicate"
            duplicate_file.write_bytes(struct.pack("<Q", len(duplicate)) + duplicate + b"\0" * 8)
            invalid_dtype = root / "dtype"
            invalid_dtype.write_bytes(safetensors(dtype="F128"))
            invalid_range = root / "range"
            invalid_range.write_bytes(safetensors(offsets=(0, 4)))
            truncated = root / "truncated"
            truncated.write_bytes(struct.pack("<Q", 1024) + b"{}")
            for path in (duplicate_file, invalid_dtype, invalid_range, truncated):
                self.assertIsNone(validate_path(path))

    def test_safetensors_allows_scalar_and_zero_dimension_tensors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            scalar = root / "scalar"
            scalar.write_bytes(safetensors(shape=[], offsets=(0, 4))[:-4] + b"\0" * 4)
            zero = root / "zero"
            zero.write_bytes(safetensors(shape=[0], offsets=(0, 0)))
            self.assertIsNotNone(validate_path(scalar))
            self.assertIsNotNone(validate_path(zero))

    def test_safetensors_requires_complete_contiguous_data_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)

            def write(value: dict[str, object], body: bytes, name: str) -> Path:
                header = json.dumps(value, separators=(",", ":")).encode("utf-8")
                header += b" " * ((8 - len(header) % 8) % 8)
                path = root / name
                path.write_bytes(struct.pack("<Q", len(header)) + header + body)
                return path

            hole = write(
                {
                    "left": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                    "right": {"dtype": "F32", "shape": [1], "data_offsets": [8, 12]},
                },
                b"\0" * 12,
                "hole",
            )
            trailing = write(
                {"tensor": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}},
                b"\0" * 8,
                "trailing",
            )
            overlap = write(
                {
                    "left": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                    "right": {"dtype": "F32", "shape": [1], "data_offsets": [2, 6]},
                },
                b"\0" * 6,
                "overlap",
            )
            out_of_order = write(
                {
                    "right": {"dtype": "F32", "shape": [1], "data_offsets": [4, 8]},
                    "left": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                },
                b"\0" * 8,
                "out-of-order",
            )
            self.assertIsNone(validate_path(hole))
            self.assertIsNone(validate_path(trailing))
            self.assertIsNone(validate_path(overlap))
            self.assertIsNotNone(validate_path(out_of_order))

    @unittest.skipUnless(os.name == "posix", "stable absolute paths are Linux-only")
    def test_artifact_cache_reuses_stable_inode_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "model"
            path.write_bytes(gguf())
            sample = type(
                "Snapshot",
                (),
                {"identity": object(), "fd_entries": (), "map_paths": (str(path),)},
            )()
            cache: dict[tuple[int, int, int, int, int], object] = {}
            first = from_snapshot(sample, cache=cache)
            second = from_snapshot(sample, cache=cache)
            self.assertEqual(first, second)
            self.assertEqual(1, len(cache))
