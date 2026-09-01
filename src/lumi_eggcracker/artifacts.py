"""Bounded, content-based local model artifact recognition."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .jsonio import JsonInputError
from .procfd import (
    StableFileMetadata,
    descriptor_size,
    fair_window,
    open_process_fd,
    unique_mapping_references,
)

MAX_ARTIFACT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACTS = 16
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_FD_PROBES_PER_SCAN = 64
MAX_MAP_PROBES_PER_SCAN = 64
MAX_ARG_ARTIFACT_PROBES = 32
MAX_ARG_ARTIFACT_PATH_BYTES = 4096
MAX_ARG_ARTIFACT_DIRECTORY_ENTRIES = 64
MAX_GGUF_ITEMS = 10_000_000
MAX_SAFETENSORS_TENSORS = 100_000
MAX_SAFETENSORS_DIMS = 64
MAX_SAFETENSORS_DIM = 1 << 31
MAX_SAFETENSORS_ELEMENTS = 1 << 60

# This is deliberately a small, pinned set for the CPU MVP.  Unknown future
# dtypes fail closed until a new release qualifies their byte semantics.
SAFETENSORS_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "I16": 2,
    "U16": 2,
    "I32": 4,
    "U32": 4,
    "I64": 8,
    "U64": 8,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "F16": 2,
    "BF16": 2,
    "F32": 4,
    "F64": 8,
    "C64": 8,
    "C128": 16,
}


@dataclass(frozen=True)
class ArtifactEvidence:
    """Redacted evidence suitable for a detection receipt."""

    evidence_id: str
    format: str
    device: int
    inode: int
    size: int
    header_sha256: str

    def public(self) -> dict[str, object]:
        return {
            "format": self.format,
            "header_sha256": self.header_sha256,
            "size_bucket": _size_bucket(self.size),
        }


ArtifactCacheKey = tuple[int, int, int, int, int]
ArtifactCache = MutableMapping[ArtifactCacheKey, ArtifactEvidence | None]


class _Metadata(Protocol):
    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int
    st_mode: int


def _cache_key(metadata: _Metadata) -> ArtifactCacheKey:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _size_bucket(size: int) -> str:
    if size < 1 << 20:
        return "<1MiB"
    if size < 1 << 30:
        return "1MiB-1GiB"
    if size < 8 << 30:
        return "1GiB-8GiB"
    return ">=8GiB"


def _regular(
    descriptor: int,
    *,
    minimum: int = 1,
    fallback: StableFileMetadata | None = None,
) -> _Metadata:
    try:
        metadata: _Metadata = os.fstat(descriptor)
    except OSError:
        if fallback is None or descriptor_size(descriptor) != fallback.st_size:
            raise
        metadata = fallback
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < minimum:
        raise JsonInputError("candidate model artifact is not a usable regular file")
    return metadata


def _read_exact(descriptor: int, amount: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    value = bytearray()
    while len(value) < amount:
        block = os.read(descriptor, amount - len(value))
        if not block:
            break
        value.extend(block)
    return bytes(value)


def validate_gguf_fd(
    descriptor: int, *, fallback: StableFileMetadata | None = None
) -> ArtifactEvidence:
    """Validate the fixed GGUF v2/v3 header without reading a model body."""
    before = _regular(descriptor, minimum=25, fallback=fallback)
    raw = _read_exact(descriptor, 24)
    if len(raw) != 24 or raw[:4] != b"GGUF":
        raise JsonInputError("candidate is not GGUF")
    version, tensors, metadata = struct.unpack("<IQQ", raw[4:])
    if version not in {2, 3} or not 1 <= tensors <= MAX_GGUF_ITEMS or metadata > MAX_GGUF_ITEMS:
        raise JsonInputError("GGUF fixed header is implausible")
    # Each declared entry needs at least a type/name prefix. This is a lower
    # bound, not a full parser, and rejects maliciously inconsistent headers.
    minimum = 24 + tensors * 12 + metadata * 8
    if minimum > before.st_size or minimum > MAX_ARTIFACT_BYTES:
        raise JsonInputError("GGUF declared header exceeds the inspection budget")
    header = _read_exact(descriptor, min(before.st_size, MAX_ARTIFACT_BYTES))
    after = _regular(descriptor, fallback=fallback)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise JsonInputError("candidate model artifact changed during validation")
    return ArtifactEvidence(
        f"gguf-v{version}",
        "GGUF",
        before.st_dev,
        before.st_ino,
        before.st_size,
        hashlib.sha256(header).hexdigest(),
    )


def _json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # The reference Safetensors loader accepts duplicate JSON names with the
    # final value taking precedence.  Mirror that interpretation before
    # validating the resulting tensor layout; otherwise a loader-accepted
    # model can evade content recognition merely by repeating a key.
    return dict(pairs)


def validate_safetensors_fd(
    descriptor: int, *, fallback: StableFileMetadata | None = None
) -> ArtifactEvidence:
    """Validate one bounded Safetensors header through an opened descriptor."""
    before = _regular(descriptor, minimum=8, fallback=fallback)
    prefix = _read_exact(descriptor, 8)
    if len(prefix) != 8:
        raise JsonInputError("Safetensors header length is truncated")
    header_length = struct.unpack("<Q", prefix)[0]
    if not 1 <= header_length <= MAX_ARTIFACT_BYTES:
        raise JsonInputError("Safetensors header length is outside the bounded budget")
    if 8 + header_length > before.st_size:
        raise JsonInputError("Safetensors header exceeds file size")
    header = _read_exact(descriptor, header_length + 8)[8:]
    if len(header) != header_length:
        raise JsonInputError("Safetensors header is truncated")
    if not header.startswith(b"{"):
        raise JsonInputError("Safetensors header must begin with an object")
    try:
        value = json.loads(header.decode("utf-8"), object_pairs_hook=_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, JsonInputError) as error:
        raise JsonInputError(f"Safetensors header JSON is invalid: {error}") from error
    if not isinstance(value, dict) or not value:
        raise JsonInputError("Safetensors header must be a non-empty JSON object")
    metadata = value.pop("__metadata__", None)
    if metadata is not None and (
        not isinstance(metadata, dict)
        or any(
            not isinstance(key, str) or not isinstance(item, str)
            for key, item in metadata.items()
        )
    ):
        raise JsonInputError("Safetensors metadata must be string-to-string")
    if not value or len(value) > MAX_SAFETENSORS_TENSORS:
        raise JsonInputError("Safetensors tensor count is invalid")
    data_start = 8 + header_length
    data_size = before.st_size - data_start
    ranges: list[tuple[int, int]] = []
    for name, tensor in value.items():
        if not isinstance(name, str) or not name or not isinstance(tensor, dict):
            raise JsonInputError("Safetensors tensor entry is invalid")
        if set(tensor) != {"dtype", "shape", "data_offsets"}:
            raise JsonInputError("Safetensors tensor fields are invalid")
        dtype = tensor["dtype"]
        if not isinstance(dtype, str) or dtype not in SAFETENSORS_DTYPE_BYTES:
            raise JsonInputError("Safetensors dtype is unsupported")
        shape = tensor["shape"]
        if (
            not isinstance(shape, list)
            or len(shape) > MAX_SAFETENSORS_DIMS
            or any(
                isinstance(item, bool)
                or not isinstance(item, int)
                or item < 0
                or item > MAX_SAFETENSORS_DIM
                for item in shape
            )
        ):
            raise JsonInputError("Safetensors shape is invalid")
        elements = 1
        for dimension in shape:
            elements *= dimension
            if elements > MAX_SAFETENSORS_ELEMENTS:
                raise JsonInputError("Safetensors shape exceeds arithmetic budget")
        required_bytes = elements * SAFETENSORS_DTYPE_BYTES[dtype]
        offsets = tensor["data_offsets"]
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or any(
                isinstance(item, bool) or not isinstance(item, int) or item < 0
                for item in offsets
            )
        ):
            raise JsonInputError("Safetensors data offsets are invalid")
        start, end = offsets
        if start > end or end > data_size or end - start != required_bytes:
            raise JsonInputError("Safetensors data offsets do not match tensor shape")
        ranges.append((start, end))
    ranges.sort()
    if not ranges or ranges[0][0] != 0:
        raise JsonInputError("Safetensors data offsets contain a leading gap")
    previous_end = 0
    for start, end in ranges:
        if start != previous_end:
            raise JsonInputError("Safetensors data offsets contain a gap or overlap")
        previous_end = end
    if previous_end != data_size:
        raise JsonInputError("Safetensors data offsets leave trailing data")
    after = _regular(descriptor, minimum=8, fallback=fallback)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise JsonInputError("candidate model artifact changed during validation")
    return ArtifactEvidence(
        "safetensors-v1",
        "SAFETENSORS",
        before.st_dev,
        before.st_ino,
        before.st_size,
        hashlib.sha256(header).hexdigest(),
    )


def validate_path(path: Path) -> ArtifactEvidence | None:
    """Return strict GGUF or Safetensors evidence for one opened file."""
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
        for validator in (validate_gguf_fd, validate_safetensors_fd):
            try:
                return validator(descriptor)
            except (JsonInputError, OSError):
                continue
        return None
    except (JsonInputError, OSError):
        return None
    finally:
        os.close(descriptor)


def _looks_like_artifact(path: Path) -> bool:
    """Use only a bounded regular-file probe before full validation."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        return stat.S_ISREG(metadata.st_mode) and metadata.st_size >= 8
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _argv_artifact_paths(snapshot: object) -> tuple[Path, ...]:
    """Return a bounded set of absolute argv path candidates.

    Content-addressed model stores (including Ollama blobs) commonly have no
    model-file extension and may no longer be open after loading.  The argv is
    only a locator here: a candidate becomes evidence only after opening the
    exact path with ``O_NOFOLLOW`` and passing the bounded format validator.
    No token is retained in evidence or receipts.
    """
    values: list[Path] = []
    seen: set[str] = set()
    argv = tuple(getattr(snapshot, "argv", ()))
    for raw in argv:
        if len(values) >= MAX_ARG_ARTIFACT_PROBES:
            break
        if not isinstance(raw, str) or not raw or len(raw.encode("utf-8", "ignore")) > MAX_ARG_ARTIFACT_PATH_BYTES:
            continue
        candidates = (raw, raw.partition("=")[2]) if raw.startswith("--") and "=" in raw else (raw,)
        for candidate in candidates:
            if len(values) >= MAX_ARG_ARTIFACT_PROBES:
                break
            if not candidate.startswith("/") or "\x00" in candidate or candidate in seen:
                continue
            seen.add(candidate)
            values.append(Path(candidate))
    return tuple(values)


def from_argv_paths(
    snapshot: object,
    *,
    cache: ArtifactCache | None = None,
    max_probes: int = MAX_ARG_ARTIFACT_PROBES,
) -> tuple[ArtifactEvidence, ...]:
    """Inspect bounded absolute argv paths for extensionless model content."""
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or max_probes < 1:
        raise JsonInputError("artifact argv probe limit is invalid")
    result: list[ArtifactEvidence] = []
    candidates: list[Path] = []
    for path in _argv_artifact_paths(snapshot)[:max_probes]:
        candidates.append(path)
        # vLLM commonly receives a model directory and closes the checkpoint
        # after loading.  Inspect only its bounded immediate children; this is
        # not a recursive filesystem walk and names are never trusted.
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            descriptor = os.open(path, flags)
        except OSError:
            continue
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                continue
            try:
                children = sorted(path.iterdir(), key=lambda item: item.name)
            except OSError:
                children = []
            for child in children[:MAX_ARG_ARTIFACT_DIRECTORY_ENTRIES]:
                if child.is_symlink():
                    continue
                candidates.append(child)
        finally:
            os.close(descriptor)
        if len(candidates) >= max_probes * (MAX_ARG_ARTIFACT_DIRECTORY_ENTRIES + 1):
            break
    for path in candidates:
        try:
            metadata = path.stat()
            key = _cache_key(metadata)
        except OSError:
            continue
        if cache is not None and key in cache:
            evidence = cache[key]
        else:
            evidence = validate_path(path) if _looks_like_artifact(path) else None
            if cache is not None:
                cache[key] = evidence
        if evidence is not None and evidence not in result:
            result.append(evidence)
            if len(result) >= MAX_ARTIFACTS:
                break
    return tuple(result)


def _evidence_from_descriptor(
    descriptor: int,
    cache: ArtifactCache | None,
    fallback: StableFileMetadata | None = None,
) -> ArtifactEvidence | None:
    metadata = _regular(descriptor, fallback=fallback)
    key = _cache_key(metadata)
    if cache is not None and key in cache:
        return cache[key]
    evidence = None
    for validator in (validate_gguf_fd, validate_safetensors_fd):
        try:
            evidence = validator(descriptor, fallback=fallback)
            break
        except (JsonInputError, OSError):
            continue
    if cache is not None:
        cache[key] = evidence
    return evidence


def from_process_fds(
    snapshot: object,
    *,
    proc: Path = Path("/proc"),
    cache: ArtifactCache | None = None,
    start_index: int = 0,
    max_probes: int = MAX_FD_PROBES_PER_SCAN,
) -> tuple[ArtifactEvidence, ...]:
    """Inspect one fair bounded window of currently open target descriptors.

    The descriptor is opened through ``/proc/<pid>/fd/<n>``.  The link name is
    used only to find a descriptor number; it is never accepted as evidence.
    Callers advance ``start_index`` between scans so a held-open artifact
    cannot be hidden permanently behind harmless lower-numbered descriptors.
    """
    identity = getattr(snapshot, "identity", None)
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise JsonInputError("artifact descriptor cursor is invalid")
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or max_probes < 1:
        raise JsonInputError("artifact descriptor probe limit is invalid")
    pid = getattr(identity, "pid", None)
    if isinstance(pid, int) and not isinstance(pid, bool) and pid >= 1:
        directory = proc / str(pid) / "fd"
        try:
            numbers = sorted(
                int(item.name) for item in directory.iterdir() if item.name.isdigit()
            )
        except OSError:
            numbers = sorted(
                {
                    number
                    for number, _target in tuple(getattr(snapshot, "fd_entries", ()))
                    if isinstance(number, int)
                    and not isinstance(number, bool)
                    and number >= 0
                }
            )
    else:
        # Synthetic snapshots and partially collected /proc records can still
        # contribute stable pathname evidence through ``from_snapshot``.  A
        # missing process identity must not prevent that fallback path.
        numbers = []
    selected = fair_window(numbers, start_index=start_index, max_probes=max_probes)
    result: list[ArtifactEvidence] = []
    consumed = 0
    for number in selected:
        # /proc/<pid>/fd/<n> is necessarily a procfs symlink.  We open that
        # exact descriptor target, then validate the opened inode; O_NOFOLLOW
        # would reject every legitimate procfs descriptor.
        try:
            descriptor, fallback = open_process_fd(identity, number, proc=proc)
        except (JsonInputError, OSError, ProcessLookupError):
            continue
        try:
            evidence = _evidence_from_descriptor(descriptor, cache, fallback)
            if evidence is None:
                continue
            header_bytes = min(
                _regular(descriptor, fallback=fallback).st_size,
                MAX_ARTIFACT_BYTES,
            )
            if consumed + header_bytes > MAX_TOTAL_BYTES:
                break
            consumed += header_bytes
            if evidence not in result:
                result.append(evidence)
        except (JsonInputError, OSError):
            pass
        finally:
            os.close(descriptor)
    return tuple(result)


def _mapping_references(snapshot: object, proc: Path) -> tuple[str, ...]:
    identity = getattr(snapshot, "identity", None)
    pid = getattr(identity, "pid", None)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
        return ()
    return unique_mapping_references(pid, proc=proc)


def from_mapped_files(
    snapshot: object,
    *,
    proc: Path = Path("/proc"),
    cache: ArtifactCache | None = None,
    start_index: int = 0,
    max_probes: int = MAX_MAP_PROBES_PER_SCAN,
) -> tuple[ArtifactEvidence, ...]:
    """Inspect a rotating bounded window of live mapped-file descriptors."""
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise JsonInputError("artifact mapping cursor is invalid")
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or max_probes < 1:
        raise JsonInputError("artifact mapping probe limit is invalid")
    references = _mapping_references(snapshot, proc)
    if not references:
        return ()
    selected = fair_window(references, start_index=start_index, max_probes=max_probes)
    result: list[ArtifactEvidence] = []
    for reference in selected:
        try:
            descriptor = os.open(
                proc / str(snapshot.identity.pid) / "map_files" / reference,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
        except (AttributeError, OSError):
            continue
        try:
            evidence = _evidence_from_descriptor(descriptor, cache)
            if evidence is not None and evidence not in result:
                result.append(evidence)
                if len(result) >= MAX_ARTIFACTS:
                    break
        except (JsonInputError, OSError):
            pass
        finally:
            os.close(descriptor)
    return tuple(result)


def from_snapshot(
    snapshot: object,
    *,
    proc: Path = Path("/proc"),
    cache: ArtifactCache | None = None,
    fd_start_index: int = 0,
    fd_max_probes: int = MAX_FD_PROBES_PER_SCAN,
    map_start_index: int = 0,
    map_max_probes: int = MAX_MAP_PROBES_PER_SCAN,
) -> tuple[ArtifactEvidence, ...]:
    """Collect bounded content evidence from descriptors, mappings and argv locators."""
    result = list(
        from_process_fds(
            snapshot,
            proc=proc,
            cache=cache,
            start_index=fd_start_index,
            max_probes=fd_max_probes,
        )
    )
    for evidence in from_mapped_files(
        snapshot,
        proc=proc,
        cache=cache,
        start_index=map_start_index,
        max_probes=map_max_probes,
    ):
        if evidence not in result:
            result.append(evidence)
    for evidence in from_argv_paths(snapshot, cache=cache):
        if evidence not in result:
            result.append(evidence)
            if len(result) >= MAX_ARTIFACTS:
                return tuple(result[:MAX_ARTIFACTS])
    for raw in tuple(getattr(snapshot, "map_paths", ())):
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        path = Path(raw)
        try:
            metadata = path.stat()
            key = _cache_key(metadata)
        except OSError:
            continue
        if cache is not None and key in cache:
            evidence = cache[key]
        else:
            evidence = validate_path(path) if _looks_like_artifact(path) else None
            if cache is not None:
                cache[key] = evidence
        if evidence is not None and evidence not in result:
            result.append(evidence)
            if len(result) >= MAX_ARTIFACTS:
                break
    return tuple(result[:MAX_ARTIFACTS])
