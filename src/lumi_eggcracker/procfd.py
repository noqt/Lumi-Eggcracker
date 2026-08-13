"""Stable access to another process's open descriptors on supported Linux."""

from __future__ import annotations

import ctypes
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .discovery import PROC, ProcessIdentity, identity
from .jsonio import JsonInputError

SYS_PIDFD_GETFD = 438
MAX_FDINFO_BYTES = 16 * 1024
MAX_REGULAR_FILE_SIZE = 1 << 40


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
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
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
