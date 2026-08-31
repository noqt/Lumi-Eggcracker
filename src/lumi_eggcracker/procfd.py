"""Stable access to another process's open descriptors on supported Linux."""

from __future__ import annotations

import ctypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from .discovery import PROC, ProcessIdentity, identity
from .jsonio import JsonInputError

SYS_PIDFD_GETFD = 438
MAX_FDINFO_BYTES = 16 * 1024
MAX_REGULAR_FILE_SIZE = 1 << 40
MAX_PROC_MAP_BYTES = 8 * 1024 * 1024
T = TypeVar("T")


def fair_window(
    values: tuple[T, ...] | list[T], *, start_index: int, max_probes: int
) -> tuple[T, ...]:
    """Return one bounded stripe that eventually covers every current item.

    Contiguous prefix windows let an adversary concentrate useful evidence at
    one end of a large descriptor table. Stripes distribute each bounded read
    across the complete table. ``start_index`` remains expressed in
    probe-sized windows so callers can keep advancing by ``max_probes``.
    """
    if isinstance(start_index, bool) or not isinstance(start_index, int) or start_index < 0:
        raise JsonInputError("descriptor window cursor is invalid")
    if isinstance(max_probes, bool) or not isinstance(max_probes, int) or max_probes < 1:
        raise JsonInputError("descriptor window probe limit is invalid")
    count = len(values)
    if count <= max_probes:
        return tuple(values)
    generation = start_index // max_probes
    if max_probes < 4:
        stripes = (count + max_probes - 1) // max_probes
        return tuple(values[generation % stripes :: stripes])
    # Always retain both descriptor-table edges.  High-FD placement is a
    # common bounded-pressure tactic; the rotating interior still guarantees
    # eventual coverage for every non-edge entry.
    interior = values[1:-1]
    interior_limit = max_probes - 2
    stripes = (len(interior) + interior_limit - 1) // interior_limit
    return (
        values[0],
        *interior[generation % stripes :: stripes],
        values[-1],
    )


def unique_mapping_references(pid: int, *, proc: Path = PROC) -> tuple[str, ...]:
    """Return one map-files range per stable mapped inode when available.

    Shared objects normally occupy several adjacent mapping ranges. Counting
    every segment against the deep-inspection limit makes the limit depend on
    loader segmentation rather than unique runtime files. If a mapping cannot
    be stat-bound (for example a deleted DrvFS entry), retain every range so no
    evidence is discarded on the strength of a pathname.
    """
    directory = proc / str(pid) / "map_files"
    try:
        candidates = sorted(
            (
                item
                for item in directory.iterdir()
                if len(item.name.split("-", 1)) == 2
                and all(
                    part
                    and all(character in "0123456789abcdefABCDEF" for character in part)
                    for part in item.name.split("-", 1)
                )
            ),
            key=lambda item: int(item.name.split("-", 1)[0], 16),
        )
    except (AttributeError, OSError):
        return ()
    result: list[str] = []
    seen: set[tuple[int, int]] = set()
    for item in candidates:
        try:
            metadata = item.stat()
        except OSError:
            result.append(item.name)
            continue
        key = (metadata.st_dev, metadata.st_ino)
        if key in seen:
            continue
        seen.add(key)
        result.append(item.name)
    return tuple(result)


@dataclass(frozen=True)
class ExecutableMappingReference:
    """One executable file mapping, bound to its kernel mapping identity."""

    name: str
    device_major: int
    device_minor: int
    inode: int
    file_offset: int
    mount_ids: tuple[int, ...] = ()


def _mount_devices(pid: int, proc: Path) -> dict[tuple[int, int], tuple[int, ...]]:
    """Map kernel device numbers to target mount IDs from bounded mountinfo."""
    path = proc / str(pid) / "mountinfo"
    try:
        raw = path.read_bytes()
    except OSError:
        return {}
    if len(raw) > MAX_PROC_MAP_BYTES:
        raise JsonInputError("process mount table exceeds bounded inspection limit")
    result: dict[tuple[int, int], list[int]] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3 or ":" not in fields[2]:
            continue
        try:
            mount_id = int(fields[0], 10)
            major, minor = (int(item, 10) for item in fields[2].split(":", 1))
        except ValueError:
            continue
        if mount_id < 1 or major < 0 or minor < 0:
            continue
        result.setdefault((major, minor), []).append(mount_id)
    return {key: tuple(values) for key, values in result.items()}


def executable_mapping_references(
    pid: int, *, proc: Path = PROC
) -> tuple[ExecutableMappingReference, ...]:
    """Return bounded, unique executable file mappings from ``/proc/PID/maps``.

    Runtime identity is intentionally narrower than general mapped-file
    discovery: read-only/data mappings do not prove that an inference runtime
    was loaded.  The device/inode identity is retained so a deleted mapping
    whose ``map_files`` link cannot be reopened can be matched to the exact
    retained process descriptor instead of scanning arbitrary open files.
    """
    path = proc / str(pid) / "maps"
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        return ()
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= MAX_PROC_MAP_BYTES:
            block = os.read(descriptor, min(64 * 1024, MAX_PROC_MAP_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
    finally:
        os.close(descriptor)
    if total > MAX_PROC_MAP_BYTES:
        raise JsonInputError("process maps exceeds bounded inspection limit")
    try:
        lines = b"".join(chunks).decode("utf-8", errors="replace").splitlines()
    except UnicodeError:
        return ()

    mount_devices = _mount_devices(pid, proc)
    result: list[ExecutableMappingReference] = []
    seen: set[tuple[int, int, int]] = set()
    for line in lines:
        fields = line.split(maxsplit=5)
        if len(fields) < 5 or "x" not in fields[1]:
            continue
        name, permissions, raw_offset, raw_device, raw_inode = fields[:5]
        if len(permissions) != 4 or permissions[0] not in "r-":
            continue
        limits = name.split("-", 1)
        devices = raw_device.split(":", 1)
        if (
            len(limits) != 2
            or len(devices) != 2
            or any(not item for item in (*limits, *devices))
        ):
            continue
        try:
            start, end = (int(item, 16) for item in limits)
            major, minor = (int(item, 16) for item in devices)
            file_offset = int(raw_offset, 16)
            inode = int(raw_inode, 10)
        except ValueError:
            continue
        if start >= end or inode < 1 or file_offset < 0:
            continue
        key = (major, minor, inode)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            ExecutableMappingReference(
                name,
                major,
                minor,
                inode,
                file_offset,
                mount_devices.get((major, minor), ()),
            )
        )
    return tuple(result)


@dataclass(frozen=True)
class StableFileMetadata:
    """Minimal stat-compatible identity for a duplicated DrvFS descriptor.

    WSL can duplicate a deleted DrvFS descriptor with ``pidfd_getfd`` while
    ``fstat`` on the duplicate returns ``ENOENT``.  The descriptor remains
    readable and seekable.  Its target fdinfo supplies the stable mount/inode
    identity and ``SEEK_END`` supplies the bounded size used by validators.
    """

    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int = 0
    st_ctime_ns: int = 0
    st_mode: int = stat.S_IFREG | 0o400


def descriptor_size(descriptor: int) -> int:
    """Return a seekable descriptor's size without relying on ``fstat``."""
    try:
        current = os.lseek(descriptor, 0, os.SEEK_CUR)
        size = os.lseek(descriptor, 0, os.SEEK_END)
        os.lseek(descriptor, current, os.SEEK_SET)
    except OSError as error:
        raise JsonInputError("candidate descriptor is not a seekable regular file") from error
    if not 0 <= size <= MAX_REGULAR_FILE_SIZE:
        raise JsonInputError("candidate descriptor size is outside the supported bound")
    return size


def _fdinfo(value: ProcessIdentity, number: int, proc: Path) -> StableFileMetadata:
    path = proc / str(value.pid) / "fdinfo" / str(number)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise JsonInputError("cannot read target descriptor identity") from error
    if len(raw) > MAX_FDINFO_BYTES:
        raise JsonInputError("target descriptor identity exceeds the bounded input")
    fields: dict[str, str] = {}
    try:
        lines = raw.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise JsonInputError("target descriptor identity is not ASCII") from error
    for line in lines:
        key, separator, item = line.partition(":")
        if separator and key not in fields:
            fields[key] = item.strip()
    try:
        mount_id = int(fields["mnt_id"], 10)
        inode = int(fields["ino"], 10)
    except (KeyError, ValueError) as error:
        raise JsonInputError("target descriptor identity is incomplete") from error
    if mount_id < 1 or inode < 1:
        raise JsonInputError("target descriptor identity is invalid")
    return StableFileMetadata(mount_id, inode, 0)


def _same(value: ProcessIdentity, proc: Path) -> bool:
    return identity(value.pid, proc=proc) == value


def _pidfd_getfd(pidfd: int, number: int) -> int:
    if os.uname().machine not in {"x86_64", "aarch64", "riscv64"}:
        raise JsonInputError("pidfd_getfd syscall number is unavailable on this architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(
        ctypes.c_long(SYS_PIDFD_GETFD),
        ctypes.c_int(pidfd),
        ctypes.c_int(number),
        ctypes.c_uint(0),
    )
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def open_process_fd(
    value: ProcessIdentity,
    number: int,
    *,
    proc: Path = PROC,
) -> tuple[int, StableFileMetadata | None]:
    """Open one target FD, falling back to a stable pidfd duplicate on WSL.

    The ordinary procfs magic-link route remains first.  ``pidfd_getfd`` is
    used only when that route fails and only for the real procfs, with the
    exact PID/start-time revalidated before and after duplication.
    """
    if isinstance(number, bool) or not isinstance(number, int) or number < 0:
        raise JsonInputError("target descriptor number is invalid")
    # A target can deliberately expose a FIFO, device, or another descriptor
    # whose open would wait for external activity.  Discovery must never let
    # an untrusted workload block the supervisor before the descriptor has
    # been validated as a regular file.  O_NONBLOCK is inert for ordinary
    # files and lets the caller reject non-regular descriptors after fstat.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    path = proc / str(value.pid) / "fd" / str(number)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if proc != PROC or not hasattr(os, "pidfd_open") or not _same(value, proc):
            raise
    else:
        if proc == PROC and not _same(value, proc):
            os.close(descriptor)
            raise ProcessLookupError("process identity changed while opening descriptor")
        return descriptor, None

    pidfd = os.pidfd_open(value.pid, 0)
    descriptor = -1
    try:
        if not _same(value, proc):
            raise ProcessLookupError("process identity changed before descriptor duplication")
        descriptor = _pidfd_getfd(pidfd, number)
        if not _same(value, proc):
            raise ProcessLookupError("process identity changed after descriptor duplication")
        try:
            os.fstat(descriptor)
            return descriptor, None
        except OSError:
            fallback = _fdinfo(value, number, proc)
            fallback = StableFileMetadata(
                fallback.st_dev,
                fallback.st_ino,
                descriptor_size(descriptor),
            )
            return descriptor, fallback
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    finally:
        os.close(pidfd)
