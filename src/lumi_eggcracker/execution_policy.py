"""Root-owned immutable executable identities for the sealed-exec boundary.

The policy is deliberately small.  It is not a general application sandbox:
it answers one question for the native listener, namely whether a newly
requested executable image is the exact root-controlled object that an
operator selected before launch.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from .jsonio import JsonInputError, canonical_bytes, load_regular_json
from .records import write_atomic

SCHEMA = "lumi-eggcracker.exec-policy.v1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
POLICY_ID = re.compile(r"[0-9a-f]{24}\Z")
MAX_EXECUTABLES = 32
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
STATE_DIR = Path("/var/lib/lumi-eggcracker/exec-policies")


def _root_controlled(path: Path) -> bool:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        return False
    for item in (path, *path.parents):
        try:
            metadata = item.lstat()
        except OSError:
            return False
        if metadata.st_uid != 0:
            return False
        if not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022:
            return False
    return True


def _hash_descriptor(descriptor: int, metadata: os.stat_result) -> str:
    if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= MAX_EXECUTABLE_BYTES:
        raise JsonInputError("execution policy executable is outside the supported size bound")
    before = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = metadata.st_size
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            raise JsonInputError("execution policy executable changed during hashing")
        digest.update(block)
        remaining -= len(block)
    after_metadata = os.fstat(descriptor)
    after = (
        after_metadata.st_dev,
        after_metadata.st_ino,
        after_metadata.st_size,
        after_metadata.st_mtime_ns,
        after_metadata.st_ctime_ns,
    )
    if after != before:
        raise JsonInputError("execution policy executable changed during hashing")
    return digest.hexdigest()


def inspect_executable(path_text: str) -> dict[str, Any]:
    """Capture one immutable root-controlled executable identity."""
    if not isinstance(path_text, str) or not path_text or len(path_text) > 4096:
        raise JsonInputError("execution policy executable path is invalid")
    supplied = Path(path_text)
    if not _root_controlled(supplied):
        raise JsonInputError("execution policy executable path must be root-controlled")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise JsonInputError("execution policy executable cannot be resolved") from error
    if not _root_controlled(resolved):
        raise JsonInputError("resolved execution policy executable is not root-controlled")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise JsonInputError("execution policy executable cannot be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or not (metadata.st_mode & 0o111)
        ):
            raise JsonInputError("execution policy target must be a root-owned executable")
        digest = _hash_descriptor(descriptor, metadata)
        return {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "path": str(resolved),
            "sha256": digest,
            "size": metadata.st_size,
            "uid": metadata.st_uid,
        }
    finally:
        os.close(descriptor)


def _validate_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "device", "inode", "mode", "path", "sha256", "size", "uid"
    }:
        raise JsonInputError("execution policy executable identity is invalid")
    if (
        not isinstance(value["path"], str)
        or not value["path"].startswith("/")
        or not isinstance(value["sha256"], str)
        or HEX.fullmatch(value["sha256"]) is None
    ):
        raise JsonInputError("execution policy executable identity is invalid")
    for key in ("device", "inode", "mode", "size", "uid"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise JsonInputError("execution policy executable integer is invalid")
    if value["uid"] != 0 or value["size"] < 1 or value["size"] > MAX_EXECUTABLE_BYTES:
        raise JsonInputError("execution policy executable owner or size is invalid")
    return value


def _digest(value: dict[str, Any]) -> str:
    body = {key: value[key] for key in value if key != "digest"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def validate(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "created_monotonic_ns", "creator_uid", "digest", "executables", "generation",
        "name", "policy_id", "revoked", "schema_version",
    }
    if set(value) != expected or value.get("schema_version") != SCHEMA:
        raise JsonInputError("execution policy schema is invalid")
    if not isinstance(value["name"], str) or NAME.fullmatch(value["name"]) is None:
        raise JsonInputError("execution policy name is invalid")
    if not isinstance(value["policy_id"], str) or POLICY_ID.fullmatch(value["policy_id"]) is None:
        raise JsonInputError("execution policy identity is invalid")
    if not isinstance(value["digest"], str) or HEX.fullmatch(value["digest"]) is None:
        raise JsonInputError("execution policy digest is invalid")
    for key in ("created_monotonic_ns", "creator_uid", "generation"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise JsonInputError("execution policy integer is invalid")
    if value["creator_uid"] != 0 or value["generation"] < 1 or not isinstance(value["revoked"], bool):
        raise JsonInputError("execution policy authority or state is invalid")
    entries = value["executables"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_EXECUTABLES:
        raise JsonInputError("execution policy executable count is invalid")
    checked = [_validate_entry(entry) for entry in entries]
    identities = {(item["device"], item["inode"], item["size"], item["sha256"]) for item in checked}
    if len(identities) != len(checked):
        raise JsonInputError("execution policy executable identity is duplicated")
    if _digest(value) != value["digest"]:
        raise JsonInputError("execution policy digest does not match contents")
    return value


def _path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise JsonInputError("execution policy name is invalid")
    return root / f"{name}.json"


def create(root: Path, *, name: str, paths: list[str], creator_uid: int = 0) -> dict[str, Any]:
    if creator_uid != 0 or not isinstance(paths, list) or not 1 <= len(paths) <= MAX_EXECUTABLES:
        raise JsonInputError("execution policy arguments are invalid")
    destination = _path(root, name)
    if destination.exists() or destination.is_symlink():
        raise JsonInputError("execution policy name is unavailable")
    entries = [inspect_executable(item) for item in paths]
    value = {
        "created_monotonic_ns": time.monotonic_ns(),
        "creator_uid": 0,
        "digest": "0" * 64,
        "executables": entries,
        "generation": 1,
        "name": name,
        "policy_id": os.urandom(12).hex(),
        "revoked": False,
        "schema_version": SCHEMA,
    }
    value["digest"] = _digest(value)
    value = validate(value)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(root, 0, 0)
    os.chmod(root, 0o700)
    write_atomic(destination, value)
    os.chown(destination, 0, 0)
    os.chmod(destination, 0o600)
    return value


def load_all(root: Path = STATE_DIR) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise JsonInputError("execution policy root is invalid")
    values: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        value = validate(load_regular_json(path))
        if value["name"] != path.stem:
            raise JsonInputError("execution policy name/path mismatch")
        values.append(value)
    return values


def load(root: Path, policy_id: str) -> dict[str, Any]:
    for value in load_all(root):
        if value["policy_id"] == policy_id:
            if value["revoked"]:
                raise JsonInputError("execution policy is revoked")
            return value
    raise JsonInputError("execution policy is unavailable")


def revoke(root: Path, policy_id: str) -> dict[str, Any]:
    values = load_all(root)
    for value in values:
        if value["policy_id"] == policy_id:
            path = _path(root, value["name"])
            replacement = dict(value)
            replacement["revoked"] = True
            replacement["generation"] = value["generation"] + 1
            replacement["digest"] = _digest(replacement)
            write_atomic(path, validate(replacement))
            return {"policy_id": policy_id, "result": "REVOKED"}
    raise JsonInputError("execution policy is unavailable")


def public(value: dict[str, Any]) -> dict[str, Any]:
    checked = validate(value)
    return {
        "digest": checked["digest"],
        "executable_count": len(checked["executables"]),
        "generation": checked["generation"],
        "name": checked["name"],
        "policy_id": checked["policy_id"],
        "revoked": checked["revoked"],
    }


def ephemeral(path: str, run_id: str) -> dict[str, Any]:
    """Build a non-persistent policy for the default initial executable."""
    entry = inspect_executable(path)
    value = {
        "created_monotonic_ns": time.monotonic_ns(),
        "creator_uid": 0,
        "digest": "0" * 64,
        "executables": [entry],
        "generation": 1,
        "name": f"sealed-{run_id}",
        "policy_id": run_id,
        "revoked": False,
        "schema_version": SCHEMA,
    }
    value["digest"] = _digest(value)
    return validate(value)


def match_identity(policy: dict[str, Any], identity: dict[str, Any]) -> bool:
    validate(policy)
    return any(
        all(identity.get(key) == entry.get(key) for key in ("device", "inode", "size", "sha256"))
        for entry in policy["executables"]
    )
