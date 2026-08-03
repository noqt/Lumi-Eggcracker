"""Strict JSON, canonical encoding, and atomic post-containment writes."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 32 * 1024


class JsonInputError(ValueError):
    """A local policy, record, protocol or output path is invalid."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_regular_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise JsonInputError(f"cannot stat JSON input: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise JsonInputError("JSON input must be a regular non-symlink file")
    if not 1 <= metadata.st_size <= max_bytes:
        raise JsonInputError(f"JSON input size must be between 1 and {max_bytes} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, JsonInputError) as error:
        raise JsonInputError(f"invalid JSON input: {error}") from error
    if not isinstance(value, dict):
        raise JsonInputError("JSON root must be an object")
    return value


def write_new_json(destination: Path, value: dict[str, Any], *, mode: int = 0o600) -> None:
    """Atomically create a new JSON file. Call only after containment succeeds."""
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise JsonInputError("output must be a new file under an existing directory")
    descriptor, raw = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, canonical_bytes(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise JsonInputError("output appeared while containment was running") from error
    finally:
        temporary.unlink(missing_ok=True)
