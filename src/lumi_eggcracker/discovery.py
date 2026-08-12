"""Bounded `/proc` process identities and snapshots for autonomous discovery."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .jsonio import JsonInputError

PROC = Path("/proc")
MAX_READ = 64 * 1024
MAX_CMDLINE_BYTES = 8 * 1024 * 1024
MAX_MAP_BYTES = 8 * 1024 * 1024
MAX_FDS = 256
MAX_MAPS = 512


@dataclass(frozen=True, order=True)
class ProcessIdentity:
    pid: int
    start_time: int


@dataclass(frozen=True)
class ProcessSnapshot:
    identity: ProcessIdentity
    uid: int
    exe_path: str
    exe_basename: str
    argv: tuple[str, ...]
    cgroups: tuple[str, ...]
    fd_paths: tuple[str, ...]
    map_basenames: tuple[str, ...]
    fd_entries: tuple[tuple[int, str], ...] = ()
    map_paths: tuple[str, ...] = ()
    parent: ProcessIdentity | None = None
    argv_complete: bool = True


def _read(path: Path, limit: int = MAX_READ) -> bytes:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= limit:
            value = os.read(descriptor, min(64 * 1024, limit + 1 - total))
            if not value:
                break
            chunks.append(value)
            total += len(value)
    finally:
        os.close(descriptor)
    if total > limit:
        raise JsonInputError(f"bounded proc read exceeded for {path.name}")
    return b"".join(chunks)


def parse_stat(raw: str) -> tuple[int, int]:
    """Return (parent PID, process start time) from a Linux stat record."""
    end = raw.rfind(")")
    fields = raw[end + 2 :].split()
    if end < 1 or len(fields) < 20 or not fields[1].isdigit() or not fields[19].isdigit():
        raise JsonInputError("process stat is invalid")
    return int(fields[1]), int(fields[19])


def identity(pid: int, *, proc: Path = PROC) -> ProcessIdentity | None:
    if pid < 1:
        return None
    try:
        _parent, start = parse_stat(_read(proc / str(pid) / "stat", 4096).decode("utf-8"))
    except (OSError, UnicodeDecodeError, JsonInputError):
        return None
    return ProcessIdentity(pid, start)


def argv_digest(argv: tuple[str, ...] | list[str]) -> str:
    return hashlib.sha256(
        "\0".join(argv).encode("utf-8", errors="surrogateescape")
    ).hexdigest()


def executable_digest(path: Path) -> str:
    """Hash a regular executable through one stable file descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise JsonInputError("detected executable is not a regular file")
        value = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        for block in iter(lambda: os.read(descriptor, 64 * 1024), b""):
            value.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise JsonInputError("executable changed during hashing")
        return value.hexdigest()
    finally:
        os.close(descriptor)


def executable_digest_for_identity(
    value: ProcessIdentity, *, proc: Path = PROC
) -> tuple[str, os.stat_result]:
    """Hash the executable actually running for one PID/start-time identity.

    ``/proc/<pid>/exe`` is opened directly so a renamed or replaced pathname
    cannot make the supervisor hash a different file from the executing inode.
    The identity and descriptor metadata are checked before and after hashing.
    """
    if identity(value.pid, proc=proc) != value:
        raise JsonInputError("process identity changed before executable hashing")
    descriptor = os.open(
        proc / str(value.pid) / "exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise JsonInputError("running executable is not a regular file")
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        for block in iter(lambda: os.read(descriptor, 64 * 1024), b""):
            digest.update(block)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise JsonInputError("running executable changed during hashing")
        if identity(value.pid, proc=proc) != value:
            raise JsonInputError("process identity changed during executable hashing")
        return digest.hexdigest(), before
    finally:
        os.close(descriptor)


def executable_metadata_for_identity(
    value: ProcessIdentity, *, proc: Path = PROC
) -> os.stat_result:
    """Return stable metadata for the live executable without hashing it."""
    if identity(value.pid, proc=proc) != value:
        raise JsonInputError("process identity changed before executable inspection")
    descriptor = os.open(
        proc / str(value.pid) / "exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise JsonInputError("running executable is not a regular file")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or identity(value.pid, proc=proc) != value:
            raise JsonInputError("running executable changed during inspection")
        return before
    finally:
        os.close(descriptor)


def _uid(raw: str) -> int:
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            fields = line.split()
            if len(fields) >= 2 and fields[1].isdigit():
                return int(fields[1])
    raise JsonInputError("process status lacks UID")


def _links(directory: Path, *, limit: int) -> tuple[str, ...]:
    values: list[str] = []
    for item in sorted(directory.iterdir(), key=lambda value: value.name)[:limit]:
        try:
            target = os.readlink(item)
        except OSError:
            continue
        if len(target) <= 4096:
            values.append(target.removesuffix(" (deleted)"))
    return tuple(values)


def _fd_entries(directory: Path, *, limit: int) -> tuple[tuple[int, str], ...]:
    values: list[tuple[int, str]] = []
    entries = sorted(
        (item for item in directory.iterdir() if item.name.isdigit()),
        key=lambda value: int(value.name),
    )
    for item in entries[:limit]:
        try:
            target = os.readlink(item)
        except OSError:
            continue
        if len(target) <= 4096:
            values.append((int(item.name), target.removesuffix(" (deleted)")))
    return tuple(values)


def _maps(path: Path) -> tuple[str, ...]:
    try:
        raw = _read(path, MAX_MAP_BYTES).decode("utf-8", errors="replace")
    except (OSError, JsonInputError):
        return ()
    values: list[str] = []
    for line in raw.splitlines()[:MAX_MAPS]:
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith("/"):
            values.append(Path(parts[5].removesuffix(" (deleted)")).name)
    return tuple(values)


def _map_paths(path: Path) -> tuple[str, ...]:
    try:
        raw = _read(path, MAX_MAP_BYTES).decode("utf-8", errors="replace")
    except (OSError, JsonInputError):
        return ()
    values: list[str] = []
    for line in raw.splitlines()[:MAX_MAPS]:
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith("/"):
            values.append(parts[5].removesuffix(" (deleted)"))
    return tuple(values)


def snapshot(
    value: ProcessIdentity,
    *,
    proc: Path = PROC,
    include_evidence: bool = True,
) -> ProcessSnapshot | None:
    current = identity(value.pid, proc=proc)
    if current != value:
        return None
    root = proc / str(value.pid)
    try:
        parent_pid, _start = parse_stat(_read(root / "stat", 4096).decode("utf-8"))
        exe = os.readlink(root / "exe")
        cgroups = tuple(
            line for line in _read(root / "cgroup", 8192).decode("utf-8").splitlines() if line
        )
        uid = _uid(_read(root / "status", 8192).decode("utf-8"))
    except (OSError, UnicodeDecodeError, JsonInputError):
        return None
    if not exe or len(exe) > 4096:
        return None

    # Linux argv is a byte sequence.  Invalid UTF-8 must not erase the whole
    # process from discovery, and a bounded-read failure must make approval
    # unavailable rather than making the process invisible.
    try:
        command = tuple(
            item
            for item in _read(root / "cmdline", MAX_CMDLINE_BYTES)
            .decode("utf-8", errors="surrogateescape")
            .split("\0")
            if item
        )
        argv_complete = True
    except (OSError, JsonInputError):
        command = ()
        argv_complete = False

    fd_entries: tuple[tuple[int, str], ...] = ()
    maps: tuple[str, ...] = ()
    if include_evidence:
        try:
            fd_entries = _fd_entries(root / "fd", limit=MAX_FDS)
        except OSError:
            fd_entries = ()
        # Native runtime discovery uses stable /proc/<pid>/map_files handles.
        # This fallback is retained for kernels/test fixtures without it and
        # is deliberately isolated so one oversized maps file cannot abort a
        # global discovery pass.
        if not (root / "map_files").is_dir():
            maps = _map_paths(root / "maps")
    fd_paths = tuple(item[1] for item in fd_entries)
    parent = identity(parent_pid, proc=proc) if parent_pid > 0 else None
    return ProcessSnapshot(
        value,
        uid,
        exe,
        Path(exe.removesuffix(" (deleted)")).name,
        command,
        cgroups,
        fd_paths,
        tuple(Path(item).name for item in maps),
        fd_entries,
        maps,
        parent,
        argv_complete,
    )


def scan(
    *,
    proc: Path = PROC,
    exclude: Callable[[ProcessSnapshot], bool] | None = None,
    include_evidence: bool = True,
) -> list[ProcessSnapshot]:
    result: list[ProcessSnapshot] = []
    try:
        candidates = sorted(int(item.name) for item in proc.iterdir() if item.name.isdigit())
    except OSError as error:
        raise JsonInputError(f"cannot enumerate proc: {error}") from error
    for pid in candidates:
        item = identity(pid, proc=proc)
        if item is None:
            continue
        current = snapshot(item, proc=proc, include_evidence=include_evidence)
        if current is not None and not (exclude and exclude(current)):
            result.append(current)
    return result
