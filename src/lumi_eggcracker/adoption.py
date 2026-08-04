"""Stop, capture and cgroup-kill a discovered host process tree."""

from __future__ import annotations

import errno
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path

from .containment import EmptyProof, events_from_fd, kill_path
from .discovery import PROC, ProcessIdentity, identity
from .jsonio import JsonInputError

MAX_CAPTURED = 4096
MAX_CAPTURE_SECONDS = 0.5


@dataclass(frozen=True)
class QuarantineIdentity:
    path: Path
    device: int
    inode: int
    event_id: str


@dataclass(frozen=True)
class AdoptionResult:
    identity: QuarantineIdentity
    captured: tuple[ProcessIdentity, ...]
    fixed_point_scans: int
    first_stop_ns: int
    kill_started_ns: int
    kill_complete_ns: int
    empty_ns: int
    proof: EmptyProof


def pidfd_available() -> bool:
    return hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")


def _same(value: ProcessIdentity, *, proc: Path = PROC) -> bool:
    return identity(value.pid, proc=proc) == value


def stop(value: ProcessIdentity, *, proc: Path = PROC) -> int:
    """Stop one revalidated identity through a pidfd; return completion time."""
    if not pidfd_available():
        raise JsonInputError("pidfd_send_signal is unavailable")
    if not _same(value, proc=proc):
        raise ProcessLookupError(errno.ESRCH, "process identity vanished")
    descriptor = os.pidfd_open(value.pid, 0)
    try:
        if not _same(value, proc=proc):
            raise ProcessLookupError(errno.ESRCH, "process identity changed")
        signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
        return time.monotonic_ns()
    finally:
        os.close(descriptor)


def _kill(value: ProcessIdentity, *, proc: Path = PROC) -> None:
    if not pidfd_available() or not _same(value, proc=proc):
        return
    try:
        descriptor = os.pidfd_open(value.pid, 0)
    except OSError:
        return
    try:
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except OSError:
        return
    finally:
        os.close(descriptor)


def children(value: ProcessIdentity, *, proc: Path = PROC) -> set[ProcessIdentity]:
    result: set[ProcessIdentity] = set()
    tasks = proc / str(value.pid) / "task"
    try:
        entries = list(tasks.iterdir())
    except OSError:
        return result
    for task in entries:
        try:
            raw = (task / "children").read_text(encoding="ascii", errors="strict")
        except OSError:
            continue
        for field in raw.split():
            if not field.isdigit():
                raise JsonInputError("process children file is invalid")
            item = identity(int(field), proc=proc)
            if item is not None:
                result.add(item)
    return result


def descendants(roots: set[ProcessIdentity], *, proc: Path = PROC, maximum: int = MAX_CAPTURED) -> set[ProcessIdentity]:
    result = set(roots)
    pending = list(roots)
    while pending:
        current = pending.pop()
        for child in children(current, proc=proc):
            if child not in result:
                if len(result) >= maximum:
                    raise JsonInputError("discovered process tree exceeds capture limit")
                result.add(child)
                pending.append(child)
    return result


def _events(path: Path) -> dict[str, int]:
    with (path / "cgroup.events").open("rb", buffering=0) as handle:
        return events_from_fd(handle.fileno())


def _validate(identity_value: QuarantineIdentity, root: Path) -> Path:
    path = identity_value.path
    if path.parent != root or path.name != identity_value.event_id or path.is_symlink() or not path.is_dir():
        raise JsonInputError("quarantine cgroup is invalid")
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_dev != identity_value.device or metadata.st_ino != identity_value.inode:
        raise JsonInputError("quarantine cgroup identity drifted")
    if not all((path / item).is_file() for item in ("cgroup.events", "cgroup.kill", "cgroup.procs")):
        raise JsonInputError("quarantine cgroup lacks required controls")
    return path


def create_quarantine(root: Path, event_id: str) -> QuarantineIdentity:
    if not root.is_dir() or root.is_symlink() or len(event_id) != 24 or any(character not in "0123456789abcdef" for character in event_id):
        raise JsonInputError("quarantine root or event identity is invalid")
    path = root / event_id
    try:
        path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise JsonInputError("quarantine cgroup already exists") from error
    metadata = path.stat(follow_symlinks=False)
    value = QuarantineIdentity(path, metadata.st_dev, metadata.st_ino, event_id)
    _validate(value, root)
    return value


def _move(value: ProcessIdentity, destination: Path, *, proc: Path = PROC) -> bool:
    if not _same(value, proc=proc):
        return False
    descriptor = os.open(destination / "cgroup.procs", os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.write(descriptor, f"{value.pid}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    return True


def _survivors(path: Path) -> tuple[list[int], int]:
    directories = [path, *(item for item in path.rglob("*") if item.is_dir() and not item.is_symlink())]
    values: list[int] = []
    for directory in directories:
        for raw in (directory / "cgroup.procs").read_text(encoding="ascii").splitlines():
            if not raw.isdigit():
                raise JsonInputError("quarantine cgroup contains invalid PID")
            values.append(int(raw))
    return sorted(set(values)), len(directories)


def verify_empty(value: QuarantineIdentity, root: Path, *, deadline_seconds: float = 0.9) -> tuple[int, EmptyProof]:
    deadline = time.monotonic() + deadline_seconds
    last = EmptyProof(False, 0, -1, [])
    while time.monotonic() <= deadline:
        path = _validate(value, root)
        state = _events(path)
        survivors, count = _survivors(path)
        populated = state.get("populated", -1)
        last = EmptyProof(populated == 0 and not survivors, count, populated, survivors)
        if last.complete:
            return time.monotonic_ns(), last
        kill_path(path)
        time.sleep(0.002)
    return time.monotonic_ns(), last


def _remove(value: QuarantineIdentity, root: Path) -> None:
    path = _validate(value, root)
    if _events(path).get("populated") != 0 or (path / "cgroup.procs").read_text(encoding="ascii").strip():
        raise JsonInputError("cannot remove populated quarantine cgroup")
    path.rmdir()


def contain(target: ProcessIdentity, root: Path, event_id: str, *, proc: Path = PROC) -> AdoptionResult:
    """The first durable operation happens only after pidfd stop and cgroup kill."""
    trigger_deadline = time.monotonic() + MAX_CAPTURE_SECONDS
    first_stop = stop(target, proc=proc)
    captured: set[ProcessIdentity] = {target}
    fixed = 0
    quarantine: QuarantineIdentity | None = None
    try:
        quarantine = create_quarantine(root, event_id)
        while True:
            captured = descendants(captured, proc=proc)
            if len(captured) > MAX_CAPTURED:
                raise JsonInputError("discovered process tree exceeds capture limit")
            for current in sorted(captured):
                try:
                    stop(current, proc=proc)
                except ProcessLookupError:
                    continue
            for current in sorted(captured):
                _move(current, quarantine.path, proc=proc)
            current_tree = descendants(captured, proc=proc)
            if current_tree == captured:
                fixed += 1
                if fixed >= 2:
                    break
            else:
                captured = current_tree
                fixed = 0
            if time.monotonic() > trigger_deadline:
                raise JsonInputError("discovered process tree did not reach capture fixed point")
            time.sleep(0.002)
        path = _validate(quarantine, root)
        kill_started, kill_complete = kill_path(path)
        empty_ns, proof = verify_empty(quarantine, root)
        if not proof.complete:
            raise JsonInputError("quarantine cgroup did not become empty")
        result = AdoptionResult(quarantine, tuple(sorted(captured)), fixed, first_stop, kill_started, kill_complete, empty_ns, proof)
        _remove(quarantine, root)
        return result
    except Exception:
        for current in captured:
            _kill(current, proc=proc)
        try:
            if quarantine is not None:
                path = _validate(quarantine, root)
                kill_path(path)
                _remove(quarantine, root)
        except (JsonInputError, OSError):
            pass
        raise
