from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.elfmarkers import (
    PINNED_LLAMA_BUILD_IDS,
    from_snapshot,
    inspect_path,
    inspect_pytorch_path,
)


def elf(*, markers: tuple[str, ...], append_decoys: bool = False) -> bytes:
    strings = b"\0" + b"".join(item.encode() + b"\0" for item in markers)
    names: list[int] = []
    cursor = 1
    for item in markers:
        names.append(cursor)
        cursor += len(item) + 1
    body = bytearray(512 + max(24, len(markers) * 24))
    body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body[16:64] = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 0)
    body[64 + 64 : 64 + 128] = struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, 256, len(strings), 0, 0, 1, 0)
    body[64 + 128 : 64 + 192] = struct.pack(
        "<IIQQQQIIQQ", 0, 2, 0, 0, 512, len(markers) * 24, 1, 0, 8, 24
    )
    body[256 : 256 + len(strings)] = strings
    for index, name in enumerate(names):
        body[512 + index * 24 : 512 + (index + 1) * 24] = struct.pack(
            "<IBBHQQ", name, 0, 0, 1, 0, 0
        )
    if append_decoys:
        body.extend(b"llama_decode\0llama_model_load_from_file\0")
    return bytes(body)


class ElfMarkerTests(unittest.TestCase):
    def test_two_valid_symbol_markers_qualify_regardless_of_filename(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "unrelated-name"
            path.write_bytes(elf(markers=("llama_decode", "llama_model_load_from_file")))
            evidence = inspect_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual("llama-elf", evidence.evidence_id)
            self.assertEqual("ELF_MARKERS", evidence.method)

    def test_one_marker_or_appended_marker_text_does_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, body in enumerate(
                (elf(markers=("llama_decode",)), elf(markers=(), append_decoys=True), b"not an elf")
            ):
                path = root / str(index)
                path.write_bytes(body)
                self.assertIsNone(inspect_path(path))

    def test_build_id_fallback_is_explicitly_pinned(self) -> None:
        self.assertEqual({"7c2bca7f8ea49e1c6e86adb14861e721e041f95e"}, PINNED_LLAMA_BUILD_IDS)

    def test_exact_pytorch_pair_uses_build_ids_not_names(self) -> None:
        def build(identifier: bytes) -> bytes:
            note = struct.pack("<III", 4, len(identifier), 3)
            note += b"GNU\0" + b"\0" * 0
            note += identifier
            note += b"\0" * ((4 - len(identifier) % 4) % 4)
            body = bytearray(128 + len(note))
            body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            body[16:64] = struct.pack(
                "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0
            )
            body[64:120] = struct.pack("<IIQQQQQQ", 4, 0, 128, 0, 0, len(note), 0, 4)
            body[128:] = note
            return bytes(body)

        bridge_id = bytes.fromhex("11" * 20)
        aten_id = bytes.fromhex("22" * 20)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bridge = root / "renamed-a"
            aten = root / "renamed-b"
            bridge.write_bytes(build(bridge_id))
            aten.write_bytes(build(aten_id))
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {bridge_id.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_BUILD_IDS",
                {aten_id.hex()},
            ):
                self.assertEqual("pytorch-bridge-pinned-cpu", inspect_pytorch_path(bridge).evidence_id)
                self.assertEqual("pytorch-aten-pinned-cpu", inspect_pytorch_path(aten).evidence_id)
                sample = type("Snapshot", (), {"exe_path": "/bridge", "map_paths": ("/aten",)})()
                bridge_evidence = inspect_pytorch_path(bridge)
                aten_evidence = inspect_pytorch_path(aten)
                with patch(
                    "lumi_eggcracker.elfmarkers.inspect_pytorch_path",
                    side_effect=lambda path: (
                        bridge_evidence
                        if path.name == "bridge"
                        else aten_evidence
                    ),
                ):
                    pair = from_snapshot(sample)
                self.assertIn("pytorch-aten-pinned-cpu", {item.evidence_id for item in pair})

    def test_runtime_candidate_cap_deduplicates_repeated_map_segments(self) -> None:
        bridge = type("Evidence", (), {"evidence_id": "pytorch-bridge-pinned-cpu"})()
        aten = type("Evidence", (), {"evidence_id": "pytorch-aten-pinned-cpu"})()
        sample = type(
            "Snapshot",
            (),
            {"exe_path": "/exe", "map_paths": ("/decoy",) * 200 + ("/bridge", "/aten")},
        )()
        with patch(
            "lumi_eggcracker.elfmarkers.inspect_pytorch_path",
            side_effect=lambda path: {"bridge": bridge, "aten": aten}.get(path.name),
        ):
            pair = from_snapshot(sample)
        self.assertIn("pytorch-aten-pinned-cpu", {item.evidence_id for item in pair})

    @unittest.skipUnless(os.name == "posix", "stable absolute paths are Linux-only")
    def test_runtime_cache_reuses_stable_inode_result(self) -> None:
        evidence = type("Evidence", (), {"evidence_id": "cached-runtime"})()
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "runtime"
            path.write_bytes(b"runtime")
            sample = type("Snapshot", (), {"exe_path": str(path), "map_paths": (str(path),)})()
            cache: dict[tuple[int, int, int, int, int], tuple[object, ...]] = {}
            with patch(
                "lumi_eggcracker.elfmarkers._inspect_candidate",
                return_value=(evidence,),
            ) as inspect:
                first = from_snapshot(sample, cache=cache)
                second = from_snapshot(sample, cache=cache)
            self.assertEqual(first, second)
            inspect.assert_called_once_with(path)

    def test_large_shared_object_build_id_note_stays_bounded(self) -> None:
        identifier = bytes.fromhex("33" * 20)
        note = struct.pack("<III", 4, len(identifier), 3) + b"GNU\0" + identifier
        note += b"\0" * ((4 - len(identifier) % 4) % 4)
        note_offset = 5 * 1024 * 1024
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "large-runtime"
            header = bytearray(120)
            header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            header[16:64] = struct.pack(
                "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0
            )
            header[64:120] = struct.pack(
                "<IIQQQQQQ", 4, 0, note_offset, 0, 0, len(note), 0, 4
            )
            with path.open("wb") as handle:
                handle.write(header)
                handle.seek(note_offset)
                handle.write(note)
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {identifier.hex()},
            ):
                evidence = inspect_pytorch_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual("pytorch-bridge-pinned-cpu", evidence.evidence_id)

    def test_pytorch_decoy_strings_do_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "decoy"
            path.write_bytes(b"libtorch_python.so\0pytorch-aten-pinned-cpu\0")
            self.assertIsNone(inspect_pytorch_path(path))
