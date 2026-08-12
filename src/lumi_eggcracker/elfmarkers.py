"""Bounded ELF symbol-table markers for supported inference runtimes."""

from __future__ import annotations

import os
import stat
import struct
from collections.abc import Iterable, MutableMapping
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
PYTORCH_BRIDGE_EVIDENCE_ID = "pytorch-bridge-build-id-pinned-cpu"
PYTORCH_ATEN_EVIDENCE_ID = "pytorch-aten-build-id-pinned-cpu"
PYTORCH_PAIR_EVIDENCE_ID = "pytorch-bridge-aten-pair-pinned-cpu"
MAX_RUNTIME_CANDIDATES = 256


@dataclass(frozen=True)
class RuntimeEvidence:
    evidence_id: str
    family: str
    method: str
    markers: tuple[str, ...]

    def public(self) -> dict[str, object]:
        return {"family": self.family, "method": self.method}


RuntimeCacheKey = tuple[int, int, int, int, int]
RuntimeCache = MutableMapping[RuntimeCacheKey, tuple[RuntimeEvidence, ...]]


def _cache_key(metadata: os.stat_result) -> RuntimeCacheKey:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read(descriptor: int, offset: int, count: int, *, allow_distant_offset: bool = False) -> bytes:
    if offset < 0 or count < 0 or count > MAX_ELF_BYTES:
        raise JsonInputError("ELF read exceeds bounded inspection window")
    # GNU build-id notes in large shared objects (for example libtorch_cpu)
    # may live far beyond the first bounded window.  The read itself remains
    # bounded; only the seek offset is allowed to be distant after the file
    # size was checked by the caller.
    if not allow_distant_offset and offset + count > MAX_ELF_BYTES:
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
        if kind != 4 or not length or length > MAX_ELF_BYTES or offset + length > size:
            continue
        note = _read(descriptor, offset, length, allow_distant_offset=True)
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


def _inspect_llama_descriptor(descriptor: int) -> RuntimeEvidence | None:
    """Recognise llama/GGML through one already-open, stable descriptor."""
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


def _inspect_pytorch_descriptor(descriptor: int) -> RuntimeEvidence | None:
    """Recognise one exact pinned PyTorch bridge/ATen descriptor identity."""
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
                PYTORCH_BRIDGE_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ()
            )
        if build_id in PINNED_PYTORCH_ATEN_BUILD_IDS:
            return RuntimeEvidence(
                PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID", ()
            )
        return None
    except (JsonInputError, OSError, struct.error):
        return None


def _inspect_descriptor(descriptor: int) -> tuple[RuntimeEvidence, ...]:
    values: list[RuntimeEvidence] = []
    llama = _inspect_llama_descriptor(descriptor)
    if llama is not None:
        values.append(llama)
    pytorch = _inspect_pytorch_descriptor(descriptor)
    if pytorch is not None and pytorch not in values:
        values.append(pytorch)
    return tuple(values)


def inspect_path(path: Path) -> RuntimeEvidence | None:
    """Recognise a llama/GGML ELF by two valid symbol-table markers, not name."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return _inspect_llama_descriptor(descriptor)
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
        return _inspect_pytorch_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _inspect_candidate(path: Path) -> tuple[RuntimeEvidence, ...]:
    values: list[RuntimeEvidence] = []
    llama = inspect_path(path)
    if llama is not None:
        values.append(llama)
    pytorch = inspect_pytorch_path(path)
    if pytorch is not None and pytorch not in values:
        values.append(pytorch)
    return tuple(values)


def with_pytorch_pair(values: Iterable[RuntimeEvidence]) -> tuple[RuntimeEvidence, ...]:
    """Add the composite identity only when both raw pinned identities exist."""
    result = list(values)
    evidence_ids = {item.evidence_id for item in result}
    if (
        PYTORCH_BRIDGE_EVIDENCE_ID in evidence_ids
        and PYTORCH_ATEN_EVIDENCE_ID in evidence_ids
        and PYTORCH_PAIR_EVIDENCE_ID not in evidence_ids
    ):
        result.append(RuntimeEvidence(PYTORCH_PAIR_EVIDENCE_ID, "PyTorch/ATen", "BUILD_ID_PAIR", ()))
    return tuple(result)


def _cached_descriptor(
    descriptor: int, cache: RuntimeCache | None
) -> tuple[RuntimeEvidence, ...]:
    try:
        metadata = os.fstat(descriptor)
        key = _cache_key(metadata)
    except OSError:
        return ()
    if cache is not None and key in cache:
        return cache[key]
    values = _inspect_descriptor(descriptor)
    if cache is not None:
        cache[key] = values
    return values


def _mapping_references(snapshot: object, proc: Path) -> tuple[str, ...]:
    try:
        pid = snapshot.identity.pid
        directory = proc / str(pid) / "map_files"
        values = [
            item.name
            for item in directory.iterdir()
            if len(item.name.split("-", 1)) == 2
            and all(
                part and all(character in "0123456789abcdefABCDEF" for character in part)
                for part in item.name.split("-", 1)
            )
        ]
    except (AttributeError, OSError):
        return ()
    return tuple(sorted(values, key=lambda value: int(value.split("-", 1)[0], 16)))


def from_snapshot(
    snapshot: object,
    *,
    cache: RuntimeCache | None = None,
    proc: Path = Path("/proc"),
    start_index: int = 0,
    max_candidates: int = MAX_RUNTIME_CANDIDATES,
) -> tuple[RuntimeEvidence, ...]:
    """Inspect one fair window of live executable/mapping descriptors.

    Native Linux inspection opens ``/proc/<pid>/map_files/<range>`` directly.
    The mapped inode therefore remains inspectable after its pathname is
    renamed or deleted.  Path reopening is only a compatibility fallback for
    fixtures or kernels where ``map_files`` is unavailable.
    """
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise JsonInputError("runtime mapping cursor is invalid")
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise JsonInputError("runtime candidate limit is invalid")

    result: list[RuntimeEvidence] = []

    def add(values: tuple[RuntimeEvidence, ...]) -> None:
        for evidence in values:
            if evidence not in result:
                result.append(evidence)

    # Bind the executable through procfs as well; a deleted executable path is
    # not an excuse to lose an otherwise exact runtime identity.
    try:
        executable = proc / str(snapshot.identity.pid) / "exe"
        descriptor = os.open(executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except (AttributeError, OSError):
        descriptor = -1
    if descriptor >= 0:
        try:
            add(_cached_descriptor(descriptor, cache))
        finally:
            os.close(descriptor)

    references = _mapping_references(snapshot, proc)
    if references:
        offset = start_index % len(references)
        count = min(max_candidates, len(references))
        selected = tuple(
            references[(offset + index) % len(references)] for index in range(count)
        )
        for reference in selected:
            try:
                descriptor = os.open(
                    proc / str(snapshot.identity.pid) / "map_files" / reference,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
            except (AttributeError, OSError):
                continue
            try:
                add(_cached_descriptor(descriptor, cache))
            finally:
                os.close(descriptor)
    else:
        candidates: list[str] = []
        seen: set[str] = set()
        for raw in (getattr(snapshot, "exe_path", ""), *getattr(snapshot, "map_paths", ())):
            if isinstance(raw, str) and raw.startswith("/") and raw not in seen:
                seen.add(raw)
                candidates.append(raw)
        if candidates:
            offset = start_index % len(candidates)
            count = min(max_candidates, len(candidates))
            for index in range(count):
                path = Path(candidates[(offset + index) % len(candidates)])
                if cache is None:
                    values = _inspect_candidate(path)
                else:
                    try:
                        key = _cache_key(path.stat())
                    except OSError:
                        continue
                    if key in cache:
                        values = cache[key]
                    else:
                        values = _inspect_candidate(path)
                        cache[key] = values
                add(values)
    return with_pytorch_pair(result)
