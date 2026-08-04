"""Exact root-owned approval records for known AI invocations."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from .discovery import argv_digest, executable_digest
from .jsonio import JsonInputError, load_regular_json
from .records import write_atomic

SCHEMA = "lumi-eggcracker.approval.v1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise JsonInputError("approval name is invalid")
    return root / f"{name}.json"


def validate(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"argv_count", "argv_sha256", "created_monotonic_ns", "executable", "executable_device", "executable_inode", "executable_sha256", "name", "operator_uid", "schema_version", "uid"}
    if set(value) != expected or value.get("schema_version") != SCHEMA:
        raise JsonInputError("approval schema is invalid")
    if not isinstance(value["name"], str) or not NAME.fullmatch(value["name"]):
        raise JsonInputError("approval name is invalid")
    for key in ("argv_sha256", "executable_sha256"):
        if not isinstance(value[key], str) or not HEX.fullmatch(value[key]):
            raise JsonInputError("approval digest is invalid")
    if not isinstance(value["executable"], str) or not Path(value["executable"]).is_absolute():
        raise JsonInputError("approval executable path is invalid")
    for key in ("argv_count", "created_monotonic_ns", "executable_device", "executable_inode", "operator_uid", "uid"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise JsonInputError("approval integer field is invalid")
    return value


def create(root: Path, *, name: str, uid: int, argv: list[str], operator_uid: int) -> dict[str, Any]:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1 or not argv or not all(isinstance(item, str) and item for item in argv):
        raise JsonInputError("approval arguments are invalid")
    supplied = Path(argv[0])
    if not supplied.is_absolute():
        raise JsonInputError("approval executable must be an absolute regular file")
    try:
        executable = supplied.resolve(strict=True)
    except OSError as error:
        raise JsonInputError("approval executable cannot be resolved") from error
    metadata = executable.stat(follow_symlinks=False)
    if executable.is_symlink() or not executable.is_file():
        raise JsonInputError("approval executable must be regular")
    destination = _path(root, name)
    if destination.exists() or destination.is_symlink():
        raise JsonInputError("approval name is unavailable")
    value = validate({"argv_count": len(argv), "argv_sha256": argv_digest(argv), "created_monotonic_ns": time.monotonic_ns(), "executable": str(executable), "executable_device": metadata.st_dev, "executable_inode": metadata.st_ino, "executable_sha256": executable_digest(executable), "name": name, "operator_uid": operator_uid, "schema_version": SCHEMA, "uid": uid})
    write_atomic(destination, value)
    return value


def load_all(root: Path) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise JsonInputError("approval root is invalid")
    values: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        if path.name != f"{path.stem}.json":
            raise JsonInputError("approval filename is invalid")
        value = validate(load_regular_json(path))
        if value["name"] != path.stem:
            raise JsonInputError("approval name/path mismatch")
        values.append(value)
    return values


def approved(snapshot: Any, digest: str, approvals: list[dict[str, Any]]) -> bool:
    command_hash = argv_digest(snapshot.argv)
    try:
        metadata = Path(snapshot.exe_path).stat(follow_symlinks=False)
    except OSError:
        return False
    return any(item["uid"] == snapshot.uid and item["executable"] == snapshot.exe_path and item["executable_device"] == metadata.st_dev and item["executable_inode"] == metadata.st_ino and item["executable_sha256"] == digest and item["argv_count"] == len(snapshot.argv) and item["argv_sha256"] == command_hash for item in approvals)


def revoke(root: Path, name: str) -> dict[str, Any]:
    path = _path(root, name)
    value = validate(load_regular_json(path))
    if value["name"] != name:
        raise JsonInputError("approval name/path mismatch")
    path.unlink()
    return {"name": name, "result": "REVOKED"}


def public(value: dict[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in ("argv_count", "argv_sha256", "created_monotonic_ns", "executable", "executable_sha256", "name", "operator_uid", "uid")}
