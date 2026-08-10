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
MAX_MAP_BYTES = 256 * 1024
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


def _read(path: Path, limit: int = MAX_READ) -> bytes:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        value = os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
    if len(value) > limit:
        raise JsonInputError(f"bounded proc read exceeded for {path.name}")
    return value


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
    return hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest()


def executable_digest(path: Path) -> str:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode):
        raise JsonInputError("detected executable is not a regular file")
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


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
    for item in sorted(directory.iterdir(), key=lambda value: value.name)[:limit]:
        if not item.name.isdigit():
            continue
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
    except OSError:
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
    except OSError:
        return ()
    values: list[str] = []
    for line in raw.splitlines()[:MAX_MAPS]:
        parts = line.split(maxsplit=5)
        if len(parts) == 6 and parts[5].startswith("/"):
            values.append(parts[5].removesuffix(" (deleted)"))
    return tuple(values)


def snapshot(value: ProcessIdentity, *, proc: Path = PROC) -> ProcessSnapshot | None:
    current = identity(value.pid, proc=proc)
    if current != value:
        return None
    root = proc / str(value.pid)
    try:
        exe = os.readlink(root / "exe")
        command = tuple(
            item for item in _read(root / "cmdline").decode("utf-8").split("\0") if item
        )
        cgroups = tuple(
            line for line in _read(root / "cgroup", 8192).decode("utf-8").splitlines() if line
        )
        uid = _uid(_read(root / "status", 8192).decode("utf-8"))
        fd_entries = _fd_entries(root / "fd", limit=MAX_FDS)
        fd_paths = tuple(item[1] for item in fd_entries)
    except (OSError, UnicodeDecodeError, JsonInputError):
        return None
    if not command or not exe or len(exe) > 4096:
        return None
    maps = _map_paths(root / "maps")
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
    )


def scan(
    *, proc: Path = PROC, exclude: Callable[[ProcessSnapshot], bool] | None = None
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
        current = snapshot(item, proc=proc)
        if current is not None and not (exclude and exclude(current)):
            result.append(current)
    return result
