"""Bounded, content-based local model artifact recognition."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

from .jsonio import JsonInputError

MAX_ARTIFACT_BYTES = 1 * 1024 * 1024
MAX_ARTIFACTS = 16
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_GGUF_ITEMS = 10_000_000


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


def _size_bucket(size: int) -> str:
    if size < 1 << 20:
        return "<1MiB"
    if size < 1 << 30:
        return "1MiB-1GiB"
    if size < 8 << 30:
        return "1GiB-8GiB"
    return ">=8GiB"


def _regular(descriptor: int) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 25:
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


def validate_gguf_fd(descriptor: int) -> ArtifactEvidence:
    """Validate the fixed GGUF v2/v3 header without reading a model body."""
    before = _regular(descriptor)
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
    after = _regular(descriptor)
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


def validate_path(path: Path) -> ArtifactEvidence | None:
    """Return strict GGUF evidence for one locally opened regular file."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        return validate_gguf_fd(descriptor)
    except (JsonInputError, OSError):
        return None
    finally:
        os.close(descriptor)


def from_process_fds(
    snapshot: object, *, proc: Path = Path("/proc")
) -> tuple[ArtifactEvidence, ...]:
    """Inspect a bounded set of currently open target descriptors.

    The descriptor is opened through ``/proc/<pid>/fd/<n>``.  The link name is
    used only to find a descriptor number; it is never accepted as evidence.
    """
    identity = snapshot.identity
    entries = tuple(getattr(snapshot, "fd_entries", ()))[:MAX_ARTIFACTS]
    result: list[ArtifactEvidence] = []
    consumed = 0
    for number, _target in entries:
        if not isinstance(number, int) or number < 0:
            continue
        # /proc/<pid>/fd/<n> is necessarily a procfs symlink.  We open that
        # exact descriptor target, then validate the opened inode; O_NOFOLLOW
        # would reject every legitimate procfs descriptor.
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(proc / str(identity.pid) / "fd" / str(number), flags)
        except OSError:
            continue
        try:
            evidence = validate_gguf_fd(descriptor)
            header_bytes = min(os.fstat(descriptor).st_size, MAX_ARTIFACT_BYTES)
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


def from_snapshot(snapshot: object, *, proc: Path = Path("/proc")) -> tuple[ArtifactEvidence, ...]:
    """Collect bounded GGUF evidence from open descriptors and mapped files."""
    result = list(from_process_fds(snapshot, proc=proc))
    for raw in tuple(getattr(snapshot, "map_paths", ()))[:MAX_ARTIFACTS]:
        if not isinstance(raw, str) or not raw.startswith("/"):
            continue
        evidence = validate_path(Path(raw))
        if evidence is not None and evidence not in result:
            result.append(evidence)
    return tuple(result[:MAX_ARTIFACTS])
