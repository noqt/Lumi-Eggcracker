"""Bounded ELF symbol-table markers for supported inference runtimes."""

from __future__ import annotations

import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from .jsonio import JsonInputError

MAX_ELF_BYTES = 4 * 1024 * 1024
MAX_SECTIONS = 1024
LLAMA_MARKERS = frozenset(
    {
        "llama_decode",
        "llama_model_load_from_file",
        "llama_model_load_from_splits",
        "ggml_build_forward_expand",
    }
)
PINNED_LLAMA_BUILD_IDS = frozenset({"7c2bca7f8ea49e1c6e86adb14861e721e041f95e"})
# Exact GNU build IDs from the pinned CPU-only PyTorch 2.5.1 wheel used by the
# real smoke environment.  Names and paths are deliberately not part of the
# qualification rule.
PINNED_PYTORCH_BRIDGE_BUILD_IDS = frozenset({"0ba50bfa63eb5fd0dd19cabca2ee1de77c4c1398"})
PINNED_PYTORCH_ATEN_BUILD_IDS = frozenset({"ad9ab6eeec3b28a0ec3f12f266627610de90813b"})
MAX_RUNTIME_CANDIDATES = 128


@dataclass(frozen=True)
class RuntimeEvidence:
    evidence_id: str
    family: str
    method: str
    markers: tuple[str, ...]

    def public(self) -> dict[str, object]:
        return {"family": self.family, "method": self.method}


def _read(descriptor: int, offset: int, count: int) -> bytes:
    if offset < 0 or count < 0 or offset + count > MAX_ELF_BYTES:
        raise JsonInputError("ELF read exceeds bounded inspection window")
    os.lseek(descriptor, offset, os.SEEK_SET)
    value = os.read(descriptor, count)
    if len(value) != count:
        raise JsonInputError("truncated ELF object")
    return value


def _symbols(descriptor: int, size: int) -> set[str]:
    header = _read(descriptor, 0, 64)
    if header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01" or header[18:20] != struct.pack("<H", 62):
        raise JsonInputError("candidate runtime is not little-endian ELF64")
    (
        _type,
        _machine,
        _version,
        _entry,
        _phoff,
        section_offset,
        _flags,
        header_size,
        _phent,
        _phnum,
        section_size,
        section_count,
        _shstr,
    ) = struct.unpack("<HHIQQQIHHHHHH", header[16:])
    if header_size != 64 or not 1 <= section_count <= MAX_SECTIONS or section_size < 64:
        raise JsonInputError("ELF section table is invalid")
    if (
        section_offset + section_size * section_count > size
        or section_offset + section_size * section_count > MAX_ELF_BYTES
    ):
        raise JsonInputError("ELF section table exceeds inspection window")
    sections = [
        _read(descriptor, section_offset + index * section_size, 64)
        for index in range(section_count)
    ]
    values: set[str] = set()
    for entry in sections:
        _name, kind, _flags, _address, offset, length, link, _info, _align, entry_size = (
            struct.unpack("<IIQQQQIIQQ", entry)
        )
        if (
            kind not in {2, 11}
            or entry_size != 24
            or not length
            or length > MAX_ELF_BYTES
            or offset + length > size
        ):
            continue
        if link >= section_count:
            raise JsonInputError("ELF symbol table references invalid string table")
        _n, string_kind, _f, _a, string_offset, string_length, _l, _i, _al, _es = struct.unpack(
            "<IIQQQQIIQQ", sections[link]
        )
        if (
            string_kind != 3
            or string_offset + string_length > size
            or string_length > MAX_ELF_BYTES
        ):
            raise JsonInputError("ELF string table is invalid")
        strings = _read(descriptor, string_offset, string_length)
        symbols = _read(descriptor, offset, length)
        for cursor in range(0, len(symbols), 24):
            name_offset = struct.unpack("<I", symbols[cursor : cursor + 4])[0]
            if name_offset >= len(strings):
                continue
            end = strings.find(b"\0", name_offset)
            if end < 0 or end - name_offset > 256:
                continue
            try:
                values.add(strings[name_offset:end].decode("ascii"))
            except UnicodeDecodeError:
                continue
    return values


def _build_id(descriptor: int, size: int) -> str | None:
    """Return a GNU build ID from a bounded ELF program-note segment."""
    header = _read(descriptor, 0, 64)
    if header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01" or header[18:20] != struct.pack("<H", 62):
        raise JsonInputError("candidate runtime is not little-endian ELF64")
    values = struct.unpack("<HHIQQQIHHHHHH", header[16:])
    program_offset, entry_size, count = values[4], values[8], values[9]
    if count == 0:
        return None
    if (
        entry_size < 56
        or not 1 <= count <= MAX_SECTIONS
        or program_offset + entry_size * count > size
    ):
        raise JsonInputError("ELF program table is invalid")
    for index in range(count):
        entry = _read(descriptor, program_offset + index * entry_size, 56)
        kind, _flags, offset, _virtual, _physical, length, _memory, _align = struct.unpack(
            "<IIQQQQQQ", entry
        )
        if kind != 4 or not length or offset + length > size or offset + length > MAX_ELF_BYTES:
            continue
        note = _read(descriptor, offset, length)
        cursor = 0
        while cursor + 12 <= len(note):
            names, descriptor_size, note_type = struct.unpack("<III", note[cursor : cursor + 12])
            cursor += 12
            name_end = cursor + names
            padded_name_end = (name_end + 3) & ~3
            desc_end = padded_name_end + descriptor_size
            cursor = (desc_end + 3) & ~3
            if desc_end > len(note):
                raise JsonInputError("ELF note is truncated")
            if note_type == 3 and note[name_end - names : name_end] == b"GNU\0":
                return note[padded_name_end:desc_end].hex()
    return None


def inspect_path(path: Path) -> RuntimeEvidence | None:
    """Recognise a llama/GGML ELF by two valid symbol-table markers, not name."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 64 or before.st_size > (1 << 40):
            return None
        build_id = _build_id(descriptor, before.st_size)
        try:
            found = tuple(sorted(LLAMA_MARKERS.intersection(_symbols(descriptor, before.st_size))))
        except JsonInputError:
            # A large object can keep its section table beyond the bounded
            # window. It may still qualify only through the exact build ID.
            found = ()
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            return None
        if len(found) >= 2:
            return RuntimeEvidence("llama-elf", "llama.cpp/GGML", "ELF_MARKERS", found)
        if build_id in PINNED_LLAMA_BUILD_IDS:
            return RuntimeEvidence("llama-build-id", "llama.cpp", "BUILD_ID", ())
        return None
    except (JsonInputError, OSError, struct.error):
        return None
    finally:
        os.close(descriptor)


def inspect_pytorch_path(path: Path) -> RuntimeEvidence | None:
    """Recognise one exact pinned PyTorch bridge/ATen ELF identity."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 64:
            return None
        build_id = _build_id(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            return None
        if build_id in PINNED_PYTORCH_BRIDGE_BUILD_IDS:
            return RuntimeEvidence(
                "pytorch-bridge-pinned-cpu", "PyTorch/ATen", "BUILD_ID", ()
            )
        if build_id in PINNED_PYTORCH_ATEN_BUILD_IDS:
            return RuntimeEvidence(
                "pytorch-aten-pinned-cpu", "PyTorch/ATen", "BUILD_ID", ()
            )
        return None
    except (JsonInputError, OSError, struct.error):
        return None
    finally:
        os.close(descriptor)


def from_snapshot(snapshot: object) -> tuple[RuntimeEvidence, ...]:
    """Inspect executable and mapped regular files; their names are ignored."""
    candidates = [getattr(snapshot, "exe_path", ""), *getattr(snapshot, "map_paths", ())]
    result: list[RuntimeEvidence] = []
    bridge = False
    aten = False
    for raw in candidates[:MAX_RUNTIME_CANDIDATES]:
        evidence = inspect_path(Path(raw)) if isinstance(raw, str) and raw.startswith("/") else None
        if evidence is not None and evidence not in result:
            result.append(evidence)
        pytorch = (
            inspect_pytorch_path(Path(raw))
            if isinstance(raw, str) and raw.startswith("/")
            else None
        )
        if pytorch is not None:
            bridge |= pytorch.evidence_id == "pytorch-bridge-pinned-cpu"
            aten |= pytorch.evidence_id == "pytorch-aten-pinned-cpu"
    if bridge and aten:
        result.append(RuntimeEvidence("pytorch-aten-pinned-cpu", "PyTorch/ATen", "BUILD_ID_PAIR", ()))
    return tuple(result)
