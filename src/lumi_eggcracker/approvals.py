"""Exact root-owned approval records for known AI invocations."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from .discovery import argv_digest, executable_digest
from .elfmarkers import inspect_path
from .jsonio import JsonInputError, load_regular_json
from .records import write_atomic

SCHEMA = "lumi-eggcracker.approval.v3"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
LAUNCH_KINDS = {"NATIVE_LLAMA", "PYTHON_SCRIPT"}
MAX_INTERPRETER_BYTES = 32 * 1024 * 1024
MAX_SCRIPT_BYTES = 4 * 1024 * 1024


def _path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise JsonInputError("approval name is invalid")
    return root / f"{name}.json"


def validate(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "administrator_uid",
        "argv_count",
        "argv_sha256",
        "bound_inputs",
        "created_monotonic_ns",
        "executable",
        "executable_device",
        "executable_inode",
        "executable_sha256",
        "launch_kind",
        "name",
        "schema_version",
        "uid",
    }
    if set(value) != expected or value.get("schema_version") != SCHEMA:
        raise JsonInputError("approval schema is invalid")
    if not isinstance(value["name"], str) or not NAME.fullmatch(value["name"]):
        raise JsonInputError("approval name is invalid")
    for key in ("argv_sha256", "executable_sha256"):
        if not isinstance(value[key], str) or not HEX.fullmatch(value[key]):
            raise JsonInputError("approval digest is invalid")
    if not isinstance(value["executable"], str) or not Path(value["executable"]).is_absolute():
        raise JsonInputError("approval executable path is invalid")
    for key in ("administrator_uid", "argv_count", "created_monotonic_ns", "executable_device", "executable_inode", "uid"):
        if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0:
            raise JsonInputError("approval integer field is invalid")
    if value["administrator_uid"] != 0:
        raise JsonInputError("approval administrator must be root")
    if value["launch_kind"] not in LAUNCH_KINDS:
        raise JsonInputError("approval launch kind is invalid")
    inputs = value["bound_inputs"]
    if not isinstance(inputs, list):
        raise JsonInputError("approval bound inputs are invalid")
    if value["launch_kind"] == "NATIVE_LLAMA" and inputs:
        raise JsonInputError("native approval cannot contain staged inputs")
    if value["launch_kind"] == "PYTHON_SCRIPT" and len(inputs) != 1:
        raise JsonInputError("Python approval requires one staged script")
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {
            "argument_index",
            "device",
            "inode",
            "sha256",
            "size",
        }:
            raise JsonInputError("approval bound input schema is invalid")
        for key in ("argument_index", "device", "inode", "size"):
            if isinstance(item[key], bool) or not isinstance(item[key], int) or item[key] < 1:
                raise JsonInputError("approval bound input integer is invalid")
        if item["argument_index"] >= value["argv_count"]:
            raise JsonInputError("approval bound input index is invalid")
        if not isinstance(item["sha256"], str) or not HEX.fullmatch(item["sha256"]):
            raise JsonInputError("approval bound input digest is invalid")
    return value


def _digest_descriptor(descriptor: int, *, maximum: int) -> tuple[str, bytes]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or metadata.st_size > maximum:
        raise JsonInputError("approval input is outside the supported size bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    remaining = metadata.st_size
    while remaining:
        block = os.read(descriptor, min(1024 * 1024, remaining))
        if not block:
            raise JsonInputError("approval input changed during hashing")
        digest.update(block)
        chunks.append(block)
        remaining -= len(block)
    return digest.hexdigest(), b"".join(chunks)


def _is_cpython(executable: Path) -> bool:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(executable, flags)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INTERPRETER_BYTES:
            return False
        found_main = False
        found_bytes_main = False
        overlap = b""
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            probe = overlap + block
            found_main = found_main or b"Py_Main" in probe
            found_bytes_main = found_bytes_main or b"Py_BytesMain" in probe
            if found_main and found_bytes_main:
                return True
            overlap = probe[-32:]
            remaining -= len(block)
        return False
    finally:
        os.close(descriptor)


def _open_bound_script(path_text: str) -> tuple[int, os.stat_result]:
    supplied = Path(path_text)
    if not supplied.is_absolute():
        raise JsonInputError("approved Python script must use an absolute path")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise JsonInputError("approved Python script cannot be resolved") from error
    if resolved != supplied:
        raise JsonInputError("approved Python script cannot traverse a symlink")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise JsonInputError("approved Python script cannot be opened") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise JsonInputError("approved Python script must be regular")
    return descriptor, metadata


def _classify(executable: Path, metadata: os.stat_result, argv: list[str]) -> tuple[str, list[dict[str, Any]]]:
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise JsonInputError("approved runtime must be root-owned and not writable")
    if inspect_path(executable) is not None:
        return "NATIVE_LLAMA", []
    if not _is_cpython(executable):
        raise JsonInputError("approval supports only qualified llama or CPython runtimes")
    if len(argv) < 2 or argv[1].startswith("-"):
        raise JsonInputError("CPython approval requires one absolute script operand")
    descriptor, script_metadata = _open_bound_script(argv[1])
    try:
        digest, _content = _digest_descriptor(descriptor, maximum=MAX_SCRIPT_BYTES)
    finally:
        os.close(descriptor)
    return (
        "PYTHON_SCRIPT",
        [
            {
                "argument_index": 1,
                "device": script_metadata.st_dev,
                "inode": script_metadata.st_ino,
                "sha256": digest,
                "size": script_metadata.st_size,
            }
        ],
    )


def create(root: Path, *, name: str, uid: int, argv: list[str], administrator_uid: int) -> dict[str, Any]:
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
    launch_kind, bound_inputs = _classify(executable, metadata, argv)
    value = validate({"administrator_uid": administrator_uid, "argv_count": len(argv), "argv_sha256": argv_digest(argv), "bound_inputs": bound_inputs, "created_monotonic_ns": time.monotonic_ns(), "executable": str(executable), "executable_device": metadata.st_dev, "executable_inode": metadata.st_ino, "executable_sha256": executable_digest(executable), "launch_kind": launch_kind, "name": name, "schema_version": SCHEMA, "uid": uid})
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


def match_launch(
    *, uid: int, argv: list[str], approvals: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Match one trusted, pre-exec launch request to a root approval.

    Linux exposes ``/proc/<pid>/cmdline`` through memory controlled by the
    process itself.  It is therefore evidence for diagnostics only and must
    never grant authority after exec.  The supervisor calls this function on
    the operator request before it releases its root-controlled launch gate.
    """
    if (
        isinstance(uid, bool)
        or not isinstance(uid, int)
        or uid < 1
        or not argv
        or not all(isinstance(item, str) and item for item in argv)
    ):
        return None
    try:
        executable = Path(argv[0]).resolve(strict=True)
        metadata = executable.stat(follow_symlinks=False)
        digest = executable_digest(executable)
    except OSError:
        return None
    command_hash = argv_digest(argv)
    return next(
        (
            item
            for item in approvals
            if item["uid"] == uid
            and item["executable"] == str(executable)
            and item["executable_device"] == metadata.st_dev
            and item["executable_inode"] == metadata.st_ino
            and item["executable_sha256"] == digest
            and item["argv_count"] == len(argv)
            and item["argv_sha256"] == command_hash
        ),
        None,
    )


def revoke(root: Path, name: str) -> dict[str, Any]:
    path = _path(root, name)
    value = validate(load_regular_json(path))
    if value["name"] != name:
        raise JsonInputError("approval name/path mismatch")
    path.unlink()
    return {"name": name, "result": "REVOKED"}


def public(value: dict[str, Any]) -> dict[str, Any]:
    result = {key: value[key] for key in ("administrator_uid", "argv_count", "argv_sha256", "created_monotonic_ns", "executable", "executable_sha256", "launch_kind", "name", "uid")}
    result["bound_input_count"] = len(value["bound_inputs"])
    return result


def stage_launch(
    approval: dict[str, Any], argv: list[str], destination: Path
) -> list[str]:
    """Create a stable root-owned code snapshot before the gate is released."""
    validate(approval)
    if len(argv) != approval["argv_count"] or argv_digest(argv) != approval["argv_sha256"]:
        raise JsonInputError("approved launch arguments drifted")
    if approval["launch_kind"] == "NATIVE_LLAMA":
        return list(argv)
    binding = approval["bound_inputs"][0]
    descriptor, metadata = _open_bound_script(argv[binding["argument_index"]])
    staged = destination / "script.py"
    created = False
    output = -1
    try:
        if (
            metadata.st_dev != binding["device"]
            or metadata.st_ino != binding["inode"]
            or metadata.st_size != binding["size"]
        ):
            raise JsonInputError("approved Python script identity drifted")
        destination.mkdir(mode=0o711, parents=False, exist_ok=False)
        created = True
        if hasattr(os, "chown"):
            os.chown(destination, 0, 0)
        os.chmod(destination, 0o711)
        output = os.open(
            staged,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise JsonInputError("approved Python script changed during staging")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(output, view)
                if written < 1:
                    raise JsonInputError("approved Python script staging failed")
                view = view[written:]
            remaining -= len(block)
        os.fsync(output)
        if digest.hexdigest() != binding["sha256"]:
            raise JsonInputError("approved Python script content drifted")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise JsonInputError("approved Python script changed during staging")
        if hasattr(os, "fchmod"):
            os.fchmod(output, 0o444)
        else:
            os.close(output)
            output = -1
            staged.chmod(0o444)
        effective = list(argv)
        effective[binding["argument_index"]] = str(staged)
        return effective
    except Exception:
        if output >= 0:
            os.close(output)
            output = -1
        if staged.exists():
            staged.chmod(0o600)
            staged.unlink()
        if created:
            destination.rmdir()
        raise
    finally:
        if output >= 0:
            os.close(output)
        os.close(descriptor)
