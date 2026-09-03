from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.discovery import ProcessIdentity
from lumi_eggcracker.elfmarkers import (
    OLLAMA_LAUNCHER_EVIDENCE_ID,
    PINNED_LLAMA_BUILD_IDS,
    PYTORCH_ATEN_EVIDENCE_ID,
    PYTORCH_BRIDGE_EVIDENCE_ID,
    PYTORCH_PAIR_EVIDENCE_ID,
    VLLM_EXTENSION_EVIDENCE_ID,
    VLLM_PAIR_EVIDENCE_ID,
    VLLM_PYTHON_EVIDENCE_ID,
    RuntimeEvidence,
    _inspect_descriptor,
    _matches_mapping,
    from_snapshot,
    inspect_path,
    inspect_pytorch_path,
    scan_snapshot,
    with_pytorch_pair,
    with_vllm_pair,
)
from lumi_eggcracker.procfd import ExecutableMappingReference, StableFileMetadata


def elf(
    *,
    markers: tuple[str, ...],
    append_decoys: bool = False,
    loadable: bool = True,
) -> bytes:
    strings = b"\0" + b"".join(item.encode() + b"\0" for item in markers)
    names: list[int] = []
    cursor = 1
    for item in markers:
        names.append(cursor)
        cursor += len(item) + 1
    body = bytearray(512 + max(24, len(markers) * 24))
    body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body[16:64] = struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0,
        64 if loadable else 0,
        128,
        0,
        64,
        56 if loadable else 0,
        1 if loadable else 0,
        64,
        3,
        0,
    )
    if loadable:
        body[64:120] = struct.pack(
            "<IIQQQQQQ", 1, 5, 0, 0, 0, len(body), len(body), 0x1000
        )
    body[128 + 64 : 128 + 128] = struct.pack(
        "<IIQQQQIIQQ", 0, 3, 0, 0, 384, len(strings), 0, 0, 1, 0
    )
    body[128 + 128 : 128 + 192] = struct.pack(
        "<IIQQQQIIQQ", 0, 2, 0, 0, 512, len(markers) * 24, 1, 0, 8, 24
    )
    body[384 : 384 + len(strings)] = strings
    for index, name in enumerate(names):
        body[512 + index * 24 : 512 + (index + 1) * 24] = struct.pack(
            "<IBBHQQ", name, 0, 0, 1, 0, 0
        )
    if append_decoys:
        body.extend(b"llama_decode\0llama_model_load_from_file\0")
    return bytes(body)


def build_id_elf(identifier: bytes, *, loadable: bool = True) -> bytes:
    note = struct.pack("<III", 4, len(identifier), 3) + b"GNU\0" + identifier
    note += b"\0" * ((4 - len(identifier) % 4) % 4)
    note_offset = 192
    body = bytearray(note_offset + len(note))
    body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body[16:64] = struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2 if loadable else 1,
        0,
        0,
        0,
    )
    cursor = 64
    if loadable:
        body[cursor : cursor + 56] = struct.pack(
            "<IIQQQQQQ", 1, 5, 0, 0, 0, len(body), len(body), 0x1000
        )
        cursor += 56
    body[cursor : cursor + 56] = struct.pack(
        "<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(note), len(note), 4
    )
    body[note_offset:] = note
    return bytes(body)


class ElfMarkerTests(unittest.TestCase):
    def test_deleted_fallback_requires_exact_mapping_mount_and_inode(self) -> None:
        reference = ExecutableMappingReference("1-2", 0, 42, 12, 0, (77,))
        self.assertTrue(
            _matches_mapping(StableFileMetadata(77, 12, 128), (reference,))
        )
        self.assertFalse(
            _matches_mapping(StableFileMetadata(78, 12, 128), (reference,))
        )
        self.assertFalse(
            _matches_mapping(StableFileMetadata(77, 13, 128), (reference,))
        )

    def test_readable_deleted_drvfs_duplicate_does_not_require_fstat(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "runtime"
            body = elf(markers=("llama_decode", "llama_model_load_from_file"))
            path.write_bytes(body)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                fallback = StableFileMetadata(7, 12, path.stat().st_size)
                with patch(
                    "lumi_eggcracker.elfmarkers.os.fstat",
                    side_effect=FileNotFoundError(2, "deleted DrvFS descriptor"),
                ), patch(
                    "lumi_eggcracker.elfmarkers.PINNED_LLAMA_FILES",
                    {hashlib.sha256(body).hexdigest(): len(body)},
                ):
                    evidence = _inspect_descriptor(descriptor, fallback)
            finally:
                os.close(descriptor)
            self.assertEqual(
                ("llama-build-id",), tuple(item.evidence_id for item in evidence)
            )

    def test_proc_mapping_descriptors_are_inspected_without_pathnames(self) -> None:
        bridge_id = bytes.fromhex("44" * 20)
        aten_id = bytes.fromhex("55" * 20)
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            mappings = proc / "42" / "map_files"
            mappings.mkdir(parents=True)
            (mappings / "1000-2000").write_bytes(build_id_elf(bridge_id))
            (mappings / "3000-4000").write_bytes(build_id_elf(aten_id))
            (proc / "42" / "maps").write_text(
                "1000-2000 r-xp 00000000 00:01 11 /deleted-a\n"
                "3000-4000 r-xp 00000000 00:01 12 /deleted-b\n",
                encoding="utf-8",
            )
            sample = type(
                "Snapshot",
                (),
                {
                    "identity": ProcessIdentity(42, 100),
                    "exe_path": "/deleted-runtime",
                    "map_paths": (),
                },
            )()
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {bridge_id.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_BUILD_IDS",
                {aten_id.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_FILES",
                {
                    bridge_id.hex(): (
                        (mappings / "1000-2000").stat().st_size,
                        hashlib.sha256((mappings / "1000-2000").read_bytes()).hexdigest(),
                    )
                },
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_FILES",
                {
                    aten_id.hex(): (
                        (mappings / "3000-4000").stat().st_size,
                        hashlib.sha256((mappings / "3000-4000").read_bytes()).hexdigest(),
                    )
                },
            ):
                evidence = from_snapshot(sample, proc=proc, max_candidates=2)
            self.assertEqual(
                {
                    PYTORCH_BRIDGE_EVIDENCE_ID,
                    PYTORCH_ATEN_EVIDENCE_ID,
                    PYTORCH_PAIR_EVIDENCE_ID,
                },
                {item.evidence_id for item in evidence},
            )

    def test_two_valid_symbol_markers_qualify_regardless_of_filename(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "unrelated-name"
            body = elf(markers=("llama_decode", "llama_model_load_from_file"))
            path.write_bytes(body)
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_LLAMA_FILES",
                {hashlib.sha256(body).hexdigest(): len(body)},
            ):
                evidence = inspect_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual("llama-build-id", evidence.evidence_id)
            self.assertEqual("SHA256", evidence.method)

    def test_nonloadable_marker_elf_does_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "metadata-only"
            path.write_bytes(
                elf(
                    markers=("llama_decode", "llama_model_load_from_file"),
                    loadable=False,
                )
            )
            self.assertIsNone(inspect_path(path))

    def test_loadable_marker_elf_requires_exact_release_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "forged-loadable"
            path.write_bytes(
                elf(markers=("llama_decode", "llama_model_load_from_file"))
            )
            self.assertIsNone(inspect_path(path))

    def test_note_only_build_id_elf_does_not_qualify(self) -> None:
        identifier = bytes.fromhex("66" * 20)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "note-only"
            path.write_bytes(build_id_elf(identifier, loadable=False))
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {identifier.hex()},
            ):
                self.assertIsNone(inspect_pytorch_path(path))

    def test_loadable_forged_build_id_requires_exact_release_digest(self) -> None:
        identifier = bytes.fromhex("77" * 20)
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "forged-loadable"
            path.write_bytes(build_id_elf(identifier))
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {identifier.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_FILES",
                {identifier.hex(): (path.stat().st_size, "0" * 64)},
            ):
                self.assertIsNone(inspect_pytorch_path(path))

    def test_arbitrary_open_runtime_fd_is_not_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            directory = proc / "42" / "fd"
            directory.mkdir(parents=True)
            (directory / "7").write_bytes(
                elf(markers=("llama_decode", "llama_model_load_from_file"))
            )
            (proc / "42" / "maps").write_text("", encoding="utf-8")
            sample = type(
                "Snapshot",
                (),
                {
                    "identity": ProcessIdentity(42, 100),
                    "exe_path": "",
                    "executable_map_paths": (),
                    "fd_entries": ((7, "/runtime"),),
                },
            )()
            body = (directory / "7").read_bytes()
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_LLAMA_FILES",
                {hashlib.sha256(body).hexdigest(): len(body)},
            ):
                self.assertEqual((), from_snapshot(sample, proc=proc))

    def test_read_only_runtime_mapping_is_not_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            mappings = proc / "42" / "map_files"
            mappings.mkdir(parents=True)
            (mappings / "1000-2000").write_bytes(
                elf(markers=("llama_decode", "llama_model_load_from_file"))
            )
            (proc / "42" / "maps").write_text(
                "1000-2000 r--p 00000000 00:01 11 /data-only\n",
                encoding="utf-8",
            )
            sample = type(
                "Snapshot",
                (),
                {
                    "identity": ProcessIdentity(42, 100),
                    "exe_path": "",
                    "executable_map_paths": (),
                },
            )()
            body = (mappings / "1000-2000").read_bytes()
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_LLAMA_FILES",
                {hashlib.sha256(body).hexdigest(): len(body)},
            ):
                self.assertEqual((), from_snapshot(sample, proc=proc))

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
        bridge_id = bytes.fromhex("11" * 20)
        aten_id = bytes.fromhex("22" * 20)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            bridge = root / "renamed-a"
            aten = root / "renamed-b"
            bridge.write_bytes(build_id_elf(bridge_id))
            aten.write_bytes(build_id_elf(aten_id))
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {bridge_id.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_BUILD_IDS",
                {aten_id.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_FILES",
                {
                    bridge_id.hex(): (
                        bridge.stat().st_size,
                        hashlib.sha256(bridge.read_bytes()).hexdigest(),
                    )
                },
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_FILES",
                {
                    aten_id.hex(): (
                        aten.stat().st_size,
                        hashlib.sha256(aten.read_bytes()).hexdigest(),
                    )
                },
            ):
                self.assertEqual(PYTORCH_BRIDGE_EVIDENCE_ID, inspect_pytorch_path(bridge).evidence_id)
                self.assertEqual(PYTORCH_ATEN_EVIDENCE_ID, inspect_pytorch_path(aten).evidence_id)
                sample = type(
                    "Snapshot",
                    (),
                    {
                        "exe_path": "/bridge",
                        "executable_map_paths": ("/aten",),
                    },
                )()
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
                self.assertEqual(
                    {PYTORCH_BRIDGE_EVIDENCE_ID, PYTORCH_ATEN_EVIDENCE_ID, PYTORCH_PAIR_EVIDENCE_ID},
                    {item.evidence_id for item in pair},
                )

    def test_pytorch_pair_requires_both_raw_identities(self) -> None:
        bridge = RuntimeEvidence(PYTORCH_BRIDGE_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ())
        aten = RuntimeEvidence(PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ())
        self.assertEqual((bridge,), with_pytorch_pair((bridge,)))
        self.assertEqual((aten,), with_pytorch_pair((aten,)))
        self.assertEqual(
            {PYTORCH_BRIDGE_EVIDENCE_ID, PYTORCH_ATEN_EVIDENCE_ID, PYTORCH_PAIR_EVIDENCE_ID},
            {item.evidence_id for item in with_pytorch_pair((bridge, aten))},
        )
        pair = next(
            item
            for item in with_pytorch_pair((bridge, aten))
            if item.evidence_id == PYTORCH_PAIR_EVIDENCE_ID
        )
        self.assertEqual("SHA256_PAIR", pair.method)

    def test_vllm_pair_requires_exact_python_and_extension_identities(self) -> None:
        python = RuntimeEvidence(VLLM_PYTHON_EVIDENCE_ID, "vLLM/CPython", "SHA256", ())
        extension = RuntimeEvidence(VLLM_EXTENSION_EVIDENCE_ID, "vLLM", "SHA256", ())
        self.assertEqual((python,), with_vllm_pair((python,)))
        self.assertEqual((extension,), with_vllm_pair((extension,)))
        values = with_vllm_pair((python, extension))
        self.assertIn(VLLM_PAIR_EVIDENCE_ID, {item.evidence_id for item in values})

    def test_bounded_runtime_authentication_converges_through_cache(self) -> None:
        identifiers = [bytes.fromhex(f"{value:02x}" * 20) for value in range(1, 5)]
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            mappings = proc / "42" / "map_files"
            mappings.mkdir(parents=True)
            paths: list[Path] = []
            lines: list[str] = []
            for index, identifier in enumerate(identifiers):
                start = 0x1000 + index * 0x2000
                path = mappings / f"{start:x}-{start + 0x1000:x}"
                path.write_bytes(build_id_elf(identifier))
                paths.append(path)
                lines.append(
                    f"{start:x}-{start + 0x1000:x} r-xp 00000000 00:01 "
                    f"{index + 11} /runtime-{index}\n"
                )
            (proc / "42" / "maps").write_text("".join(lines), encoding="utf-8")
            sample = type(
                "Snapshot",
                (),
                {
                    "identity": ProcessIdentity(42, 100),
                    "exe_path": "",
                    "executable_map_paths": (),
                },
            )()
            caches: dict[tuple[int, int, int, int, int], tuple[RuntimeEvidence, ...]] = {}
            file_pins = [
                (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
                for path in paths
            ]
            with (
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                    {identifiers[0].hex()},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_BUILD_IDS",
                    {identifiers[1].hex()},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_PYTHON_BUILD_IDS",
                    {identifiers[2].hex()},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_EXTENSION_BUILD_IDS",
                    {identifiers[3].hex()},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_FILES",
                    {identifiers[0].hex(): file_pins[0]},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_ATEN_FILES",
                    {identifiers[1].hex(): file_pins[1]},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_PYTHON_FILES",
                    {identifiers[2].hex(): file_pins[2]},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_EXTENSION_FILES",
                    {identifiers[3].hex(): file_pins[3]},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.MAX_RUNTIME_AUTH_BYTES_PER_SCAN",
                    paths[0].stat().st_size * 3,
                ),
            ):
                first = scan_snapshot(sample, proc=proc, cache=caches)
                second = scan_snapshot(sample, proc=proc, cache=caches)
            first_ids = {item.evidence_id for item in first.evidence}
            second_ids = {item.evidence_id for item in second.evidence}
            self.assertTrue(first.incomplete)
            self.assertEqual(
                frozenset({VLLM_EXTENSION_EVIDENCE_ID}),
                first.deferred_evidence_ids,
            )
            self.assertIn(PYTORCH_PAIR_EVIDENCE_ID, first_ids)
            self.assertIn(VLLM_PYTHON_EVIDENCE_ID, first_ids)
            self.assertNotIn(VLLM_PAIR_EVIDENCE_ID, first_ids)
            self.assertFalse(second.incomplete)
            self.assertIn(VLLM_PAIR_EVIDENCE_ID, second_ids)

    def test_churning_wrong_hash_decoy_preserves_evidence_and_stays_incomplete(self) -> None:
        identifiers = [bytes.fromhex(f"{value:02x}" * 20) for value in range(11, 16)]
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            mappings = proc / "42" / "map_files"
            mappings.mkdir(parents=True)
            paths: list[Path] = []
            lines: list[str] = []
            for index, identifier in enumerate(identifiers[:4]):
                start = 0x1000 + index * 0x2000
                path = mappings / f"{start:x}-{start + 0x1000:x}"
                path.write_bytes(build_id_elf(identifier))
                paths.append(path)
                lines.append(
                    f"{start:x}-{start + 0x1000:x} r-xp 00000000 00:01 "
                    f"{index + 21} /cached-{index}\n"
                )
            extension = build_id_elf(identifiers[4]) + b"\0"
            decoy = mappings / "9000-a000"
            valid = mappings / "b000-c000"
            decoy.write_bytes(extension[:-1] + b"\1")
            valid.write_bytes(extension)
            lines.extend(
                (
                    "9000-a000 r-xp 00000000 00:01 31 /churning-decoy\n",
                    "b000-c000 r-xp 00000000 00:01 32 /valid-extension\n",
                )
            )
            (proc / "42" / "maps").write_text("".join(lines), encoding="utf-8")
            sample = type(
                "Snapshot",
                (),
                {
                    "identity": ProcessIdentity(42, 100),
                    "exe_path": "",
                    "executable_map_paths": (),
                },
            )()

            def key(path: Path) -> tuple[int, int, int, int, int]:
                metadata = path.stat()
                return (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )

            cache = {
                key(paths[0]): (
                    RuntimeEvidence(
                        PYTORCH_BRIDGE_EVIDENCE_ID, "PyTorch/ATen", "SHA256", ()
                    ),
                    RuntimeEvidence(
                        OLLAMA_LAUNCHER_EVIDENCE_ID, "Ollama", "SHA256", ()
                    ),
                    RuntimeEvidence(
                        PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "SHA256", ()
                    ),
                    RuntimeEvidence(
                        VLLM_PYTHON_EVIDENCE_ID, "vLLM/CPython", "SHA256", ()
                    ),
                ),
                key(paths[1]): (
                    RuntimeEvidence(
                        PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "SHA256", ()
                    ),
                ),
                key(paths[2]): (
                    RuntimeEvidence(
                        VLLM_PYTHON_EVIDENCE_ID, "vLLM/CPython", "SHA256", ()
                    ),
                ),
                key(paths[3]): (
                    RuntimeEvidence(
                        OLLAMA_LAUNCHER_EVIDENCE_ID, "Ollama", "SHA256", ()
                    ),
                ),
            }
            expected = (len(extension), hashlib.sha256(extension).hexdigest())
            with (
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_EXTENSION_BUILD_IDS",
                    {identifiers[4].hex()},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.PINNED_VLLM_EXTENSION_FILES",
                    {identifiers[4].hex(): expected},
                ),
                patch(
                    "lumi_eggcracker.elfmarkers.MAX_RUNTIME_AUTH_BYTES_PER_SCAN",
                    len(extension),
                ),
            ):
                first = scan_snapshot(sample, proc=proc, cache=cache)
                decoy.unlink()
                decoy.write_bytes(extension[:-1] + b"\2")
                second = scan_snapshot(sample, proc=proc, cache=cache)
            for result in (first, second):
                evidence_ids = {item.evidence_id for item in result.evidence}
                self.assertEqual(
                    frozenset({VLLM_EXTENSION_EVIDENCE_ID}),
                    result.deferred_evidence_ids,
                )
                self.assertIn(PYTORCH_PAIR_EVIDENCE_ID, evidence_ids)
                self.assertIn(VLLM_PYTHON_EVIDENCE_ID, evidence_ids)
                self.assertIn(OLLAMA_LAUNCHER_EVIDENCE_ID, evidence_ids)
                self.assertNotIn(VLLM_PAIR_EVIDENCE_ID, evidence_ids)

    def test_runtime_candidate_cap_deduplicates_repeated_map_segments(self) -> None:
        bridge = type("Evidence", (), {"evidence_id": PYTORCH_BRIDGE_EVIDENCE_ID})()
        aten = type("Evidence", (), {"evidence_id": PYTORCH_ATEN_EVIDENCE_ID})()
        sample = type(
            "Snapshot",
            (),
            {
                "exe_path": "/exe",
                "executable_map_paths": ("/decoy",) * 200
                + ("/bridge", "/aten"),
            },
        )()
        with patch(
            "lumi_eggcracker.elfmarkers.inspect_pytorch_path",
            side_effect=lambda path: {"bridge": bridge, "aten": aten}.get(path.name),
        ):
            pair = from_snapshot(sample)
        self.assertIn(PYTORCH_PAIR_EVIDENCE_ID, {item.evidence_id for item in pair})

    @unittest.skipUnless(os.name == "posix", "stable absolute paths are Linux-only")
    def test_runtime_cache_reuses_stable_inode_result(self) -> None:
        evidence = type("Evidence", (), {"evidence_id": "cached-runtime"})()
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "runtime"
            path.write_bytes(b"runtime")
            sample = type(
                "Snapshot",
                (),
                {"exe_path": str(path), "executable_map_paths": (str(path),)},
            )()
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
            total_size = note_offset + len(note)
            header = bytearray(176)
            header[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            header[16:64] = struct.pack(
                "<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0
            )
            header[64:120] = struct.pack(
                "<IIQQQQQQ", 1, 5, 0, 0, 0, total_size, total_size, 0x1000
            )
            header[120:176] = struct.pack(
                "<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(note), len(note), 4
            )
            with path.open("wb") as handle:
                handle.write(header)
                handle.seek(note_offset)
                handle.write(note)
            with patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                {identifier.hex()},
            ), patch(
                "lumi_eggcracker.elfmarkers.PINNED_PYTORCH_BRIDGE_FILES",
                {
                    identifier.hex(): (
                        path.stat().st_size,
                        hashlib.sha256(path.read_bytes()).hexdigest(),
                    )
                },
            ):
                evidence = inspect_pytorch_path(path)
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual(PYTORCH_BRIDGE_EVIDENCE_ID, evidence.evidence_id)

    def test_pytorch_decoy_strings_do_not_qualify(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "decoy"
            path.write_bytes(b"libtorch_python.so\0pytorch-aten-pinned-cpu\0")
            self.assertIsNone(inspect_pytorch_path(path))
