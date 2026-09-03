"""Bounded ELF symbol-table markers for supported inference runtimes."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .jsonio import JsonInputError
from .procfd import (
    ExecutableMappingReference,
    StableFileMetadata,
    descriptor_size,
    executable_mapping_references,
    fair_window,
    open_process_fd,
)

MAX_ELF_BYTES = 4 * 1024 * 1024
MAX_SECTIONS = 1024
MAX_RUNTIME_FD_PROBES = 32
LLAMA_MARKERS = frozenset(
    {
        "llama_decode",
        "llama_model_load_from_file",
        "llama_model_load_from_splits",
        "ggml_build_forward_expand",
    }
)
PINNED_LLAMA_BUILD_IDS = frozenset({"7c2bca7f8ea49e1c6e86adb14861e721e041f95e"})
PINNED_LLAMA_FILES = {
    "ef0b86d353638b74519079b5937b9d62b4d4c6c6cdbf68812d7898437ecc4fb5": 1_248_024
}
# Exact GNU build IDs from the qualified CPU-only PyTorch wheels used by the
# real smoke environments. Names and paths are deliberately not part of the
# qualification rule.
PINNED_PYTORCH_BRIDGE_BUILD_IDS = frozenset(
    {
        "0ba50bfa63eb5fd0dd19cabca2ee1de77c4c1398",
        "85d09b66000780cd7339d28d952751229cb33bc7",
    }
)
PINNED_PYTORCH_ATEN_BUILD_IDS = frozenset(
    {
        "ad9ab6eeec3b28a0ec3f12f266627610de90813b",
        "8ec08ec8f71de04ee2baa46c0dbe262858b1e27c",
    }
)
PINNED_PYTORCH_BRIDGE_FILES = {
    "0ba50bfa63eb5fd0dd19cabca2ee1de77c4c1398": (
        26_113_896,
        "b576248e3a0f6ff37de11baa3beac0e53ca1500208b9cf4974db2f3b67cfc8c5",
    ),
    "85d09b66000780cd7339d28d952751229cb33bc7": (
        30_616_304,
        "247efcbc423fb65aa64640b96cd51672d4863413472ed2ddded6ad57a8647c67",
    ),
}
PINNED_PYTORCH_ATEN_FILES = {
    "ad9ab6eeec3b28a0ec3f12f266627610de90813b": (
        433_155_401,
        "dacb42735f5a59a8b2abbf06fe7fdeba359849a08f418ad830a84ffadc316802",
    ),
    "8ec08ec8f71de04ee2baa46c0dbe262858b1e27c": (
        434_184_800,
        "ae0f4bc33ffe73f4eb85b2fd03b036c68cf5ab6139995f6a2345f5962c1bbb81",
    ),
}
PYTORCH_BRIDGE_EVIDENCE_ID = "pytorch-bridge-build-id-pinned-cpu"
PYTORCH_ATEN_EVIDENCE_ID = "pytorch-aten-build-id-pinned-cpu"
PYTORCH_PAIR_EVIDENCE_ID = "pytorch-bridge-aten-pair-pinned-cpu"
# Exact native identities qualified in the disposable Ubuntu CPU fixtures.
# Hashes, not names or paths, are the release trust anchors.
PINNED_OLLAMA_LAUNCHER_BUILD_IDS = frozenset({"d9eb30a551e9c61d699adfbccc961304605ca852"})
PINNED_OLLAMA_LAUNCHER_FILES = {
    "d9eb30a551e9c61d699adfbccc961304605ca852": (
        39_348_080,
        "9f595107f966433f93f20ee19043f8e0cdea88e7403672f4dba2cadcb45ee085",
    )
}
PINNED_OLLAMA_RUNNER_BUILD_IDS = frozenset({"f8d44c042216b0a5042f13bf9426f7e263ac5471"})
PINNED_OLLAMA_RUNNER_FILES = {
    "f8d44c042216b0a5042f13bf9426f7e263ac5471": (
        15_096,
        "234b05b2138264f8fb263c3205e85f4c290e8afe5067e280a4f6f90cdac5696b",
    )
}
PINNED_VLLM_PYTHON_BUILD_IDS = frozenset({"dc79f2c659038743f8f0c7ec18623284365df091"})
PINNED_VLLM_PYTHON_FILES = {
    "dc79f2c659038743f8f0c7ec18623284365df091": (
        8_025_024,
        "a92f0f95e883390c7256b2e441484aac06b1002dbe1d924141a77c8d82f96223",
    )
}
PINNED_VLLM_EXTENSION_BUILD_IDS = frozenset(
    {
        "0b81145998cd6a2a1162b3ca47c1029e55061449",
        "d86c8add9ec525f83ff66448174bf20b7d065772",
    }
)
PINNED_VLLM_EXTENSION_FILES = {
    "0b81145998cd6a2a1162b3ca47c1029e55061449": (
        17_766_528,
        "56510a6c504707d8f986a76f87225ce8026de498672aceae4fc7642bf1aa1edc",
    ),
    "d86c8add9ec525f83ff66448174bf20b7d065772": (
        82_113_712,
        "46c04a0e0b245d5438181e9e8335cf5a5445f00c1615962a4b414f844c74dd31",
    ),
}
OLLAMA_LAUNCHER_EVIDENCE_ID = "ollama-launcher-pinned"
OLLAMA_RUNNER_EVIDENCE_ID = "ollama-runner-pinned"
VLLM_PYTHON_EVIDENCE_ID = "vllm-python-pinned-cpu"
VLLM_EXTENSION_EVIDENCE_ID = "vllm-extension-pinned-cpu"
VLLM_PAIR_EVIDENCE_ID = "vllm-python-extension-pair-pinned-cpu"
MAX_RUNTIME_CANDIDATES = 256
MAX_RUNTIME_AUTH_BYTES_PER_SCAN = 512 * 1024 * 1024
PT_LOAD = 1
PT_NOTE = 4
PF_X = 1


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


class _Metadata(Protocol):
    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int
    st_mode: int


@dataclass(frozen=True)
class _ProgramHeader:
    kind: int
    flags: int
    offset: int
    virtual: int
    file_size: int
    memory_size: int
    alignment: int


@dataclass
class _AuthenticationBudget:
    remaining: int = MAX_RUNTIME_AUTH_BYTES_PER_SCAN


class _AuthenticationDeferred(Exception):
    """The current bounded scan exhausted its full-file authentication budget."""


def _cache_key(metadata: _Metadata) -> RuntimeCacheKey:
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


def _loadable_programs(descriptor: int, size: int) -> tuple[_ProgramHeader, ...]:
    """Validate a loadable ELF64 layout and return its bounded program table."""
    header = _read(descriptor, 0, 64)
    if (
        header[:4] != b"\x7fELF"
        or header[4:7] != b"\x02\x01\x01"
        or header[18:20] != struct.pack("<H", 62)
    ):
        raise JsonInputError("candidate runtime is not little-endian x86-64 ELF")
    values = struct.unpack("<HHIQQQIHHHHHH", header[16:])
    elf_type, version = values[0], values[2]
    program_offset, header_size, entry_size, count = (
        values[4],
        values[7],
        values[8],
        values[9],
    )
    if (
        elf_type not in {2, 3}
        or version != 1
        or header_size != 64
        or entry_size < 56
        or not 1 <= count <= MAX_SECTIONS
        or program_offset + entry_size * count > size
        or program_offset + entry_size * count > MAX_ELF_BYTES
    ):
        raise JsonInputError("ELF program table is not loadable")

    result: list[_ProgramHeader] = []
    loadable = False
    executable = False
    for index in range(count):
        entry = _read(descriptor, program_offset + index * entry_size, 56)
        kind, flags, offset, virtual, _physical, file_size, memory_size, alignment = (
            struct.unpack("<IIQQQQQQ", entry)
        )
        current = _ProgramHeader(
            kind, flags, offset, virtual, file_size, memory_size, alignment
        )
        result.append(current)
        if kind != PT_LOAD:
            continue
        if (
            memory_size < 1
            or file_size > memory_size
            or offset + file_size > size
            or (
                alignment not in {0, 1}
                and (
                    alignment & (alignment - 1)
                    or offset % alignment != virtual % alignment
                )
            )
        ):
            raise JsonInputError("ELF load segment is invalid")
        loadable = True
        if flags & PF_X and file_size:
            executable = True
    if not loadable or not executable:
        raise JsonInputError("ELF lacks an executable load segment")
    return tuple(result)


def _authenticated_sha256(
    descriptor: int,
    size: int,
    expected: dict[str, int] | tuple[int, str],
    budget: _AuthenticationBudget | None,
) -> bool:
    """Authenticate the complete stable runtime file against the release pin."""
    if isinstance(expected, tuple):
        expected_size, expected_digest = expected
        allowed = {expected_digest: expected_size}
    else:
        allowed = expected
    if size not in allowed.values():
        return False
    if budget is not None:
        if budget.remaining < size:
            raise _AuthenticationDeferred
        budget.remaining -= size
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            return False
        digest.update(block)
        remaining -= len(block)
    return allowed.get(digest.hexdigest()) == size


def _symbols(descriptor: int, size: int) -> set[str]:
    _loadable_programs(descriptor, size)
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
    for entry in _loadable_programs(descriptor, size):
        if (
            entry.kind != PT_NOTE
            or not entry.file_size
            or entry.file_size > MAX_ELF_BYTES
            or entry.offset + entry.file_size > size
        ):
            continue
        note = _read(
            descriptor,
            entry.offset,
            entry.file_size,
            allow_distant_offset=True,
        )
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


def _metadata(
    descriptor: int, fallback: StableFileMetadata | None = None
) -> _Metadata:
    try:
        return os.fstat(descriptor)
    except OSError:
        if fallback is None or descriptor_size(descriptor) != fallback.st_size:
            raise
        return fallback


def _same_metadata(before: _Metadata, after: _Metadata) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _inspect_llama_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    """Recognise llama/GGML through one already-open, stable descriptor."""
    try:
        before = _metadata(descriptor, fallback)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 64 or before.st_size > (1 << 40):
            return None
        build_id = _build_id(descriptor, before.st_size)
        try:
            found = tuple(sorted(LLAMA_MARKERS.intersection(_symbols(descriptor, before.st_size))))
        except JsonInputError:
            # A large object can keep its section table beyond the bounded
            # window. It may still qualify only through the exact build ID.
            found = ()
        if (
            (len(found) >= 2 or build_id in PINNED_LLAMA_BUILD_IDS)
            and _authenticated_sha256(
                descriptor, before.st_size, PINNED_LLAMA_FILES, budget
            )
            and _same_metadata(before, _metadata(descriptor, fallback))
        ):
            return RuntimeEvidence(
                "llama-build-id", "llama.cpp", "SHA256", found
            )
        return None
    except _AuthenticationDeferred:
        raise
    except (JsonInputError, OSError, struct.error):
        return None


def _inspect_pytorch_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    """Recognise one exact pinned PyTorch bridge/ATen descriptor identity."""
    try:
        before = _metadata(descriptor, fallback)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 64:
            return None
        build_id = _build_id(descriptor, before.st_size)
        if build_id in PINNED_PYTORCH_BRIDGE_BUILD_IDS and _authenticated_sha256(
            descriptor,
            before.st_size,
            PINNED_PYTORCH_BRIDGE_FILES[build_id],
            budget,
        ) and _same_metadata(before, _metadata(descriptor, fallback)):
            return RuntimeEvidence(
                PYTORCH_BRIDGE_EVIDENCE_ID, "PyTorch/ATen", "SHA256", ()
            )
        if build_id in PINNED_PYTORCH_ATEN_BUILD_IDS and _authenticated_sha256(
            descriptor,
            before.st_size,
            PINNED_PYTORCH_ATEN_FILES[build_id],
            budget,
        ) and _same_metadata(before, _metadata(descriptor, fallback)):
            return RuntimeEvidence(
                PYTORCH_ATEN_EVIDENCE_ID, "PyTorch/ATen", "SHA256", ()
            )
        return None
    except _AuthenticationDeferred:
        raise
    except (JsonInputError, OSError, KeyError, struct.error):
        return None


def _inspect_exact_descriptor(
    descriptor: int,
    *,
    build_ids: frozenset[str],
    files: dict[str, tuple[int, str]],
    evidence_id: str,
    family: str,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    """Authenticate one exact native build without trusting its filename."""
    try:
        before = _metadata(descriptor, fallback)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 64:
            return None
        build_id = _build_id(descriptor, before.st_size)
        expected = files.get(build_id) if build_id is not None else None
        if (
            build_id in build_ids
            and expected is not None
            and _authenticated_sha256(descriptor, before.st_size, expected, budget)
            and _same_metadata(before, _metadata(descriptor, fallback))
        ):
            return RuntimeEvidence(evidence_id, family, "SHA256", ())
        return None
    except _AuthenticationDeferred:
        raise
    except (JsonInputError, OSError, KeyError, struct.error):
        return None


def _inspect_ollama_launcher_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    return _inspect_exact_descriptor(
        descriptor,
        build_ids=PINNED_OLLAMA_LAUNCHER_BUILD_IDS,
        files=PINNED_OLLAMA_LAUNCHER_FILES,
        evidence_id=OLLAMA_LAUNCHER_EVIDENCE_ID,
        family="Ollama",
        fallback=fallback,
        budget=budget,
    )


def _inspect_ollama_runner_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    return _inspect_exact_descriptor(
        descriptor,
        build_ids=PINNED_OLLAMA_RUNNER_BUILD_IDS,
        files=PINNED_OLLAMA_RUNNER_FILES,
        evidence_id=OLLAMA_RUNNER_EVIDENCE_ID,
        family="Ollama",
        fallback=fallback,
        budget=budget,
    )


def _inspect_vllm_python_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    return _inspect_exact_descriptor(
        descriptor,
        build_ids=PINNED_VLLM_PYTHON_BUILD_IDS,
        files=PINNED_VLLM_PYTHON_FILES,
        evidence_id=VLLM_PYTHON_EVIDENCE_ID,
        family="vLLM/CPython",
        fallback=fallback,
        budget=budget,
    )


def _inspect_vllm_extension_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> RuntimeEvidence | None:
    return _inspect_exact_descriptor(
        descriptor,
        build_ids=PINNED_VLLM_EXTENSION_BUILD_IDS,
        files=PINNED_VLLM_EXTENSION_FILES,
        evidence_id=VLLM_EXTENSION_EVIDENCE_ID,
        family="vLLM",
        fallback=fallback,
        budget=budget,
    )


def _inspect_descriptor(
    descriptor: int,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> tuple[RuntimeEvidence, ...]:
    values: list[RuntimeEvidence] = []
    llama = _inspect_llama_descriptor(descriptor, fallback, budget)
    if llama is not None:
        values.append(llama)
    pytorch = _inspect_pytorch_descriptor(descriptor, fallback, budget)
    if pytorch is not None and pytorch not in values:
        values.append(pytorch)
    for inspector in (
        _inspect_ollama_launcher_descriptor,
        _inspect_ollama_runner_descriptor,
        _inspect_vllm_python_descriptor,
        _inspect_vllm_extension_descriptor,
    ):
        evidence = inspector(descriptor, fallback, budget)
        if evidence is not None and evidence not in values:
            values.append(evidence)
    return tuple(values)


def inspect_path(path: Path) -> RuntimeEvidence | None:
    """Recognise the exact qualified llama/GGML runtime, independent of name."""
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
    """Recognise one full-file authenticated PyTorch bridge/ATen identity."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return _inspect_pytorch_descriptor(descriptor)
    finally:
        os.close(descriptor)


def inspect_ollama_path(path: Path) -> RuntimeEvidence | None:
    """Recognise one exact pinned Ollama launcher or runner binary."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return inspect_ollama_descriptor(descriptor)
    finally:
        os.close(descriptor)


def inspect_ollama_descriptor(descriptor: int) -> RuntimeEvidence | None:
    """Recognise one exact Ollama identity from an already-open descriptor."""
    return next(
        (
            evidence
            for inspector in (
                _inspect_ollama_launcher_descriptor,
                _inspect_ollama_runner_descriptor,
            )
            if (evidence := inspector(descriptor)) is not None
        ),
        None,
    )


def inspect_vllm_path(path: Path) -> RuntimeEvidence | None:
    """Recognise one exact pinned vLLM Python or native extension binary."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return next(
            (
                evidence
                for inspector in (
                    _inspect_vllm_python_descriptor,
                    _inspect_vllm_extension_descriptor,
                )
                if (evidence := inspector(descriptor)) is not None
            ),
            None,
        )
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
    for inspector in (inspect_ollama_path, inspect_vllm_path):
        evidence = inspector(path)
        if evidence is not None and evidence not in values:
            values.append(evidence)
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
        result.append(
            RuntimeEvidence(
                PYTORCH_PAIR_EVIDENCE_ID, "PyTorch/ATen", "SHA256_PAIR", ()
            )
        )
    return tuple(result)


def with_vllm_pair(values: Iterable[RuntimeEvidence]) -> tuple[RuntimeEvidence, ...]:
    """Add the composite vLLM launcher/native-extension identity."""
    result = list(values)
    evidence_ids = {item.evidence_id for item in result}
    if (
        VLLM_PYTHON_EVIDENCE_ID in evidence_ids
        and VLLM_EXTENSION_EVIDENCE_ID in evidence_ids
        and VLLM_PAIR_EVIDENCE_ID not in evidence_ids
    ):
        result.append(
            RuntimeEvidence(VLLM_PAIR_EVIDENCE_ID, "vLLM", "SHA256_PAIR", ())
        )
    return tuple(result)


def _cached_descriptor(
    descriptor: int,
    cache: RuntimeCache | None,
    fallback: StableFileMetadata | None = None,
    budget: _AuthenticationBudget | None = None,
) -> tuple[RuntimeEvidence, ...]:
    try:
        metadata = _metadata(descriptor, fallback)
        key = _cache_key(metadata)
    except OSError:
        return ()
    cacheable = not isinstance(metadata, StableFileMetadata)
    if cache is not None and cacheable and key in cache:
        return cache[key]
    try:
        values = _inspect_descriptor(descriptor, fallback, budget)
    except _AuthenticationDeferred:
        return ()
    if cache is not None and cacheable:
        cache[key] = values
    return values


def _mapping_references(
    snapshot: object, proc: Path
) -> tuple[ExecutableMappingReference, ...]:
    identity = getattr(snapshot, "identity", None)
    pid = getattr(identity, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
        return ()
    return executable_mapping_references(pid, proc=proc)


def _matches_mapping(
    metadata: _Metadata,
    references: tuple[ExecutableMappingReference, ...] | list[ExecutableMappingReference],
) -> bool:
    """Bind a fallback process descriptor to one exact executable mapping."""
    for reference in references:
        if metadata.st_ino != reference.inode:
            continue
        # Deleted DrvFS pidfd duplicates expose mnt_id rather than a device
        # number through the stable fallback.  The kernel inode is still the
        # exact identity shared with /proc/PID/maps.  Ordinary descriptors can
        # and must match both device and inode.
        if isinstance(metadata, StableFileMetadata):
            return metadata.st_dev in reference.mount_ids
        try:
            if (
                os.major(metadata.st_dev) == reference.device_major
                and os.minor(metadata.st_dev) == reference.device_minor
            ):
                return True
        except (AttributeError, ValueError):
            continue
    return False


def from_snapshot(
    snapshot: object,
    *,
    cache: RuntimeCache | None = None,
    proc: Path = Path("/proc"),
    start_index: int = 0,
    max_candidates: int = MAX_RUNTIME_CANDIDATES,
) -> tuple[RuntimeEvidence, ...]:
    """Inspect one fair window of live executable/mapping descriptors.

    Native Linux inspection opens only executable ``map_files`` ranges.
    Runtime bytes held merely as an ordinary descriptor or read-only data
    mapping are not execution evidence.  If a deleted executable mapping
    cannot be reopened, only an exact device/inode-matched retained descriptor
    may stand in for that mapping.  Path reopening is a compatibility fallback
    for fixtures or kernels where ``map_files`` is unavailable.
    """
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise JsonInputError("runtime mapping cursor is invalid")
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise JsonInputError("runtime candidate limit is invalid")

    result: list[RuntimeEvidence] = []
    budget = _AuthenticationBudget()

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
            add(_cached_descriptor(descriptor, cache, budget=budget))
        finally:
            os.close(descriptor)

    references = _mapping_references(snapshot, proc)
    if references:
        selected = fair_window(
            references, start_index=start_index, max_probes=max_candidates
        )
        unresolved: list[ExecutableMappingReference] = []
        for reference in selected:
            try:
                descriptor = os.open(
                    proc / str(snapshot.identity.pid) / "map_files" / reference.name,
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
            except (AttributeError, OSError):
                unresolved.append(reference)
                continue
            try:
                add(_cached_descriptor(descriptor, cache, budget=budget))
            finally:
                os.close(descriptor)

        # WSL DrvFS can leave an executable mapping whose map_files magic link
        # is unreopenable.  Recover only through a retained descriptor that
        # matches the executable mapping's kernel identity.  This is not an
        # arbitrary-FD recognition path.
        if unresolved:
            try:
                numbers = sorted(
                    int(item.name)
                    for item in (proc / str(snapshot.identity.pid) / "fd").iterdir()
                    if item.name.isdigit()
                )
            except (AttributeError, OSError):
                numbers = sorted(
                    {
                        number
                        for number, _target in tuple(
                            getattr(snapshot, "fd_entries", ())
                        )
                        if isinstance(number, int)
                        and not isinstance(number, bool)
                        and number >= 0
                    }
                )
            runtime_generation = start_index // max_candidates
            for number in fair_window(
                numbers,
                start_index=runtime_generation * MAX_RUNTIME_FD_PROBES,
                max_probes=MAX_RUNTIME_FD_PROBES,
            ):
                descriptor = -1
                try:
                    descriptor, fallback = open_process_fd(
                        snapshot.identity, number, proc=proc
                    )
                    metadata = _metadata(descriptor, fallback)
                except (JsonInputError, OSError, ProcessLookupError):
                    if descriptor >= 0:
                        os.close(descriptor)
                    continue
                try:
                    if _matches_mapping(metadata, unresolved):
                        add(
                            _cached_descriptor(
                                descriptor, cache, fallback, budget=budget
                            )
                        )
                finally:
                    os.close(descriptor)
    else:
        candidates: list[str] = []
        seen: set[str] = set()
        for raw in (
            getattr(snapshot, "exe_path", ""),
            *getattr(snapshot, "executable_map_paths", ()),
        ):
            if isinstance(raw, str) and raw.startswith("/") and raw not in seen:
                seen.add(raw)
                candidates.append(raw)
        if candidates:
            for raw_path in fair_window(
                candidates, start_index=start_index, max_probes=max_candidates
            ):
                path = Path(raw_path)
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
    return with_vllm_pair(with_pytorch_pair(result))
