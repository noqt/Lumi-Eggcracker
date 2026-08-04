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
LLAMA_MARKERS = frozenset({"llama_decode", "llama_model_load_from_file", "llama_model_load_from_splits", "ggml_build_forward_expand"})


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
    if header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01":
        raise JsonInputError("candidate runtime is not little-endian ELF64")
    _type, _machine, _version, _entry, _phoff, section_offset, _flags, header_size, _phent, _phnum, section_size, section_count, _shstr = struct.unpack("<HHIQQQIHHHHHH", header[16:])
    if header_size != 64 or not 1 <= section_count <= MAX_SECTIONS or section_size < 64:
        raise JsonInputError("ELF section table is invalid")
    if section_offset + section_size * section_count > size or section_offset + section_size * section_count > MAX_ELF_BYTES:
        raise JsonInputError("ELF section table exceeds inspection window")
    sections = [_read(descriptor, section_offset + index * section_size, 64) for index in range(section_count)]
    values: set[str] = set()
    for entry in sections:
        _name, kind, _flags, _address, offset, length, link, _info, _align, entry_size = struct.unpack("<IIQQQQIIQQ", entry)
        if kind not in {2, 11} or entry_size != 24 or not length or length > MAX_ELF_BYTES or offset + length > size:
            continue
        if link >= section_count:
            raise JsonInputError("ELF symbol table references invalid string table")
        _n, string_kind, _f, _a, string_offset, string_length, _l, _i, _al, _es = struct.unpack("<IIQQQQIIQQ", sections[link])
        if string_kind != 3 or string_offset + string_length > size or string_length > MAX_ELF_BYTES:
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
        found = tuple(sorted(LLAMA_MARKERS.intersection(_symbols(descriptor, before.st_size))))
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size) or len(found) < 2:
            return None
        return RuntimeEvidence("llama-elf", "llama.cpp/GGML", "ELF_MARKERS", found)
    except (JsonInputError, OSError, struct.error):
        return None
    finally:
        os.close(descriptor)


def from_snapshot(snapshot: object) -> tuple[RuntimeEvidence, ...]:
    """Inspect executable and mapped regular files; their names are ignored."""
    candidates = [getattr(snapshot, "exe_path", ""), *getattr(snapshot, "map_paths", ())]
    result: list[RuntimeEvidence] = []
    for raw in candidates[:513]:
        evidence = inspect_path(Path(raw)) if isinstance(raw, str) and raw.startswith("/") else None
        if evidence is not None and evidence not in result:
            result.append(evidence)
    return tuple(result)
