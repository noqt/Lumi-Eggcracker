"""Exact cgroup-v2 identity, direct kill, and hierarchy-emptiness proof."""

from __future__ import annotations

import errno
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .jsonio import JsonInputError


CGROUP_ROOT = Path("/sys/fs/cgroup")
UNIT_RE = re.compile(r"^/system\.slice/lumi-nutcracker-workload-([0-9a-f]{24})\.service$")


@dataclass(frozen=True)
class CgroupIdentity:
    boot_id: str
    cgroup: str
    device: int
    inode: int
    run_id: str
    unit: str

    def as_dict(self) -> dict[str, object]:
        return {
            "boot_id": self.boot_id,
            "cgroup": self.cgroup,
            "cgroup_device": self.device,
            "cgroup_inode": self.inode,
            "run_id": self.run_id,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class EmptyProof:
    complete: bool
    descendant_cgroups_checked: int
    root_populated: int
    surviving_pids: list[int]


def boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise JsonInputError("Linux boot identity is invalid")
    return value


def _path(cgroup: str, *, root: Path = CGROUP_ROOT) -> Path:
    if not UNIT_RE.fullmatch(cgroup):
        raise JsonInputError("cgroup is outside the Nutcracker unit namespace")
    candidate = root.joinpath(*cgroup.lstrip("/").split("/"))
    if candidate.is_symlink() or not candidate.is_dir():
        raise JsonInputError("owned cgroup is unavailable")
    return candidate


def _events(path: Path) -> dict[str, int]:
    try:
        pairs = [line.split(" ", 1) for line in path.read_text(encoding="ascii").splitlines()]
    except OSError as error:
        raise JsonInputError(f"cannot read {path.name}: {error}") from error
    value = {key: raw for key, raw in pairs if key and raw}
    if any(not raw.isdigit() for raw in value.values()):
        raise JsonInputError(f"{path.name} has invalid values")
    return {key: int(raw) for key, raw in value.items()}


def capture_identity(cgroup: str, run_id: str, unit: str, *, root: Path = CGROUP_ROOT) -> CgroupIdentity:
    if unit != f"lumi-nutcracker-workload-{run_id}.service":
        raise JsonInputError("unit and run identity disagree")
    path = _path(cgroup, root=root)
    required = ("cgroup.kill", "cgroup.events", "cgroup.procs", "pids.events", "pids.max")
    if not all((path / name).is_file() for name in required):
        raise JsonInputError("owned cgroup lacks required v2 control files")
    if "populated" not in _events(path / "cgroup.events"):
        raise JsonInputError("owned cgroup does not expose populated state")
    if "max" not in _events(path / "pids.events"):
        raise JsonInputError("owned cgroup does not expose PID events")
    metadata = path.stat(follow_symlinks=False)
    return CgroupIdentity(boot_id(), cgroup, metadata.st_dev, metadata.st_ino, run_id, unit)


def validate_identity(identity: CgroupIdentity, *, root: Path = CGROUP_ROOT) -> Path:
    if identity.boot_id != boot_id():
        raise JsonInputError("workload boot identity changed")
    path = _path(identity.cgroup, root=root)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise JsonInputError("owned cgroup is unavailable") from error
    if metadata.st_dev != identity.device or metadata.st_ino != identity.inode:
        raise JsonInputError("owned cgroup identity drifted")
    return path


def pids_max_event(identity: CgroupIdentity, *, root: Path = CGROUP_ROOT) -> int:
    return _events(validate_identity(identity, root=root) / "pids.events")["max"]


def kill_path(path: Path) -> tuple[int, int]:
    """Write a previously validated exact cgroup.kill file directly."""
    control = path / "cgroup.kill"
    started = time.monotonic_ns()
    descriptor = os.open(control, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        if os.write(descriptor, b"1\n") != 2:
            raise JsonInputError("short write to cgroup.kill")
    finally:
        os.close(descriptor)
    return started, time.monotonic_ns()


def kill(identity: CgroupIdentity, *, root: Path = CGROUP_ROOT) -> tuple[int, int]:
    """Validate then write cgroup.kill; use kill_path when trigger order matters."""
    return kill_path(validate_identity(identity, root=root))


def _survivors(path: Path) -> tuple[list[int], int]:
    directories = [path]
    directories.extend(item for item in path.rglob("*") if item.is_dir() and not item.is_symlink())
    values: list[int] = []
    for directory in directories:
        control = directory / "cgroup.procs"
        if control.is_file():
            for line in control.read_text(encoding="ascii").splitlines():
                if not line.isdigit():
                    raise JsonInputError("cgroup.procs contains invalid PID")
                values.append(int(line))
    return sorted(set(values)), len(directories)


def _collected(error: Exception) -> bool:
    return isinstance(error, OSError) and error.errno in {errno.ENOENT, errno.ENODEV}


def verify_empty(identity: CgroupIdentity, *, deadline_seconds: float = 0.9, root: Path = CGROUP_ROOT) -> tuple[int, EmptyProof]:
    """Prove an empty hierarchy after direct kill, re-applying it across fork races."""
    deadline = time.monotonic() + deadline_seconds
    last = EmptyProof(False, 0, -1, [])
    while time.monotonic() <= deadline:
        try:
            path = validate_identity(identity, root=root)
        except JsonInputError as error:
            if "unavailable" in str(error):
                return time.monotonic_ns(), EmptyProof(True, 0, 0, [])
            raise
        try:
            events = _events(path / "cgroup.events")
            survivors, descendants = _survivors(path)
        except (JsonInputError, OSError) as error:
            # A transient service may be collected immediately after cgroup.kill.
            # ENODEV/ENOENT from cgroupfs is proof that no live hierarchy remains.
            if _collected(error) or "No such device" in str(error) or "No such file" in str(error):
                return time.monotonic_ns(), EmptyProof(True, 0, 0, [])
            raise
        populated = events.get("populated", -1)
        last = EmptyProof(populated == 0 and not survivors, descendants, populated, survivors)
        if last.complete:
            return time.monotonic_ns(), last
        # A process can fork while the kernel is walking a busy hierarchy for a
        # prior cgroup.kill.  Re-applying the same direct primitive closes that
        # narrow race; nothing is persisted or explained before enforcement.
        try:
            kill_path(path)
        except OSError as error:
            if _collected(error):
                return time.monotonic_ns(), EmptyProof(True, 0, 0, [])
            raise
        time.sleep(0.002)
    return time.monotonic_ns(), last
