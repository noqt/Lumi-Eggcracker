from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.elfmarkers import inspect_path


def elf(*, markers: tuple[str, ...], append_decoys: bool = False) -> bytes:
    strings = b"\0" + b"".join(item.encode() + b"\0" for item in markers)
    names: list[int] = []
    cursor = 1
    for item in markers:
        names.append(cursor); cursor += len(item) + 1
    body = bytearray(512 + max(24, len(markers) * 24))
    body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body[16:64] = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 0)
    body[64 + 64 : 64 + 128] = struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, 256, len(strings), 0, 0, 1, 0)
    body[64 + 128 : 64 + 192] = struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, 512, len(markers) * 24, 1, 0, 8, 24)
    body[256 : 256 + len(strings)] = strings
    for index, name in enumerate(names):
        body[512 + index * 24 : 512 + (index + 1) * 24] = struct.pack("<IBBHQQ", name, 0, 0, 1, 0, 0)
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
            for index, body in enumerate((elf(markers=("llama_decode",)), elf(markers=(), append_decoys=True), b"not an elf")):
                path = root / str(index); path.write_bytes(body)
                self.assertIsNone(inspect_path(path))
