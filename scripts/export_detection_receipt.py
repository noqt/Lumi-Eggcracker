#!/usr/bin/env python3
"""Write a bounded, redacted export of one local detection receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "lumi-eggcracker.detection-receipt.v2"
EXPORT_SCHEMA = "lumi-eggcracker.redacted-detection-receipt-export.v1"
DETECTOR_SCHEMA = "lumi-eggcracker.detectors.v3"
MAX_INPUT_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 8_192
MAX_JSON_DEPTH = 64
MAX_MONOTONIC_NS = (1 << 63) - 1
_EVENT_ID = re.compile(r"[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z\Z"
)
_PROFILE_TRIGGER = {
    "content.gguf-llama": "UNAPPROVED_AI_MATCH",
    "content.gguf-ollama": "UNAPPROVED_OLLAMA_GGUF",
    "content.safetensors-pytorch": "UNAPPROVED_SAFETENSORS_PYTORCH",
    "content.safetensors-vllm": "UNAPPROVED_VLLM_SAFETENSORS",
}
_CONTAINMENT_PRIMITIVE = "pidfd-stop+cgroup.kill"
_REPARSE_POINT = 0x400


class ExportError(Exception):
    """A deliberately non-specific input, validation, or filesystem failure."""


def _fail() -> None:
    raise ExportError("receipt export could not be completed")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _parse_int(token: str) -> int:
    if len(token) > 64:
        _fail()
    return int(token)


def _parse_float(token: str) -> float:
    if len(token) > 128:
        _fail()
    value = float(token)
    if not math.isfinite(value):
        _fail()
    mantissa = token.lower().split("e", maxsplit=1)[0]
    if value == 0.0 and any(character in "123456789" for character in mantissa):
        _fail()
    return value


def _reject_constant(_token: str) -> None:
    _fail()


def _check_depth(text: str) -> None:
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail()
        elif character in "]}":
            depth -= 1
            if depth < 0:
                _fail()


def _decode_receipt(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        _fail()
    try:
        text = raw.decode("utf-8")
        _check_depth(text)
        value = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail()
    if not isinstance(value, dict):
        _fail()
    return value


def _path_without_parent_links(value: str | os.PathLike[str]) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute():
            if path.drive:
                _fail()
            path = Path.cwd() / path
        if not path.anchor or any(part == ".." for part in path.parts):
            _fail()
        if path.drive.startswith(("\\\\", "//")):
            _fail()
        return path
    except (OSError, TypeError, ValueError):
        _fail()


def _link_like(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & _REPARSE_POINT)


def _check_directory_chain(path: Path) -> None:
    try:
        anchor = Path(path.anchor)
        info = os.lstat(anchor)
        if _link_like(info) or not stat.S_ISDIR(info.st_mode):
            _fail()
        for part in path.parts[len(anchor.parts) :]:
            anchor = anchor / part
            info = os.lstat(anchor)
            if _link_like(info) or not stat.S_ISDIR(info.st_mode):
                _fail()
    except (OSError, ValueError):
        _fail()


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _read_source(path_value: str | os.PathLike[str]) -> bytes:
    path = _path_without_parent_links(path_value)
    _check_directory_chain(path.parent)
    try:
        before = os.lstat(path)
        if _link_like(before) or not stat.S_ISREG(before.st_mode):
            _fail()
        if before.st_size > MAX_INPUT_BYTES:
            _fail()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except (OSError, ValueError):
        _fail()

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _identity(opened) != _identity(before)
            or opened.st_size > MAX_INPUT_BYTES
        ):
            _fail()
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > MAX_INPUT_BYTES
            or len(raw) != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            _fail()
        return raw
    except (OSError, ValueError):
        _fail()
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _required_object(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        _fail()
    return value


def _required_text(
    parent: dict[str, Any],
    key: str,
    pattern: re.Pattern[str],
    *,
    max_length: int = 128,
) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or len(value) > max_length or not pattern.fullmatch(value):
        _fail()
    return value


def _required_monotonic_ns(parent: dict[str, Any], key: str) -> int:
    value = parent.get(key)
    if type(value) is not int or not 0 <= value <= MAX_MONOTONIC_NS:
        _fail()
    return value


def _required_ms(parent: dict[str, Any], key: str) -> int | float:
    value = parent.get(key)
    if type(value) not in (int, float) or not math.isfinite(value):
        _fail()
    if not 0 <= value <= MAX_MONOTONIC_NS / 1_000_000:
        _fail()
    return value


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        _fail()
    try:
        dt.datetime.fromisoformat(value)
    except ValueError:
        _fail()
    return value


def _project_receipt(receipt: dict[str, Any], expected_event_id: str) -> dict[str, Any]:
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        _fail()
    event_id = receipt.get("event_id")
    if not isinstance(event_id, str) or not _EVENT_ID.fullmatch(event_id):
        _fail()
    if event_id != expected_event_id:
        _fail()

    source_commit = _required_text(receipt, "source_commit", _COMMIT)
    version = _required_text(receipt, "version", _SEMVER, max_length=64)
    catalogue_sha256 = _required_text(receipt, "catalogue_sha256", _SHA256)
    receipt_written_utc = _validate_timestamp(receipt.get("receipt_written_utc"))

    detector = _required_object(receipt, "detector")
    profile = detector.get("profile")
    if not isinstance(profile, str) or profile not in _PROFILE_TRIGGER:
        _fail()
    detection_path = detector.get("detection_path")
    catalogue_schema = detector.get("catalogue_schema")
    if detection_path != "CONTENT" or catalogue_schema != DETECTOR_SCHEMA:
        _fail()

    trigger = _required_object(receipt, "trigger")
    trigger_kind = trigger.get("kind")
    if trigger_kind != _PROFILE_TRIGGER[profile]:
        _fail()

    result = receipt.get("result")
    if result not in ("TERMINATED", "CONTAINMENT_FAILED"):
        _fail()

    projection: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "event_id": event_id,
        "source_commit": source_commit,
        "version": version,
        "catalogue_sha256": catalogue_sha256,
        "receipt_written_utc": receipt_written_utc,
        "detector": {
            "profile": profile,
            "detection_path": detection_path,
            "catalogue_schema": catalogue_schema,
        },
        "trigger": {"kind": trigger_kind},
        "recorded_result": result,
    }

    if result == "CONTAINMENT_FAILED":
        if "containment" in receipt or "error" not in receipt:
            _fail()
        return projection

    if "error" in receipt:
        _fail()
    containment = _required_object(receipt, "containment")
    if containment.get("primitive") != _CONTAINMENT_PRIMITIVE:
        _fail()
    root_populated = containment.get("root_populated")
    surviving_pids = containment.get("surviving_pids")
    if type(root_populated) is not int or root_populated != 0:
        _fail()
    if type(surviving_pids) is not list or surviving_pids:
        _fail()

    first_stop_ns = _required_monotonic_ns(containment, "first_stop_monotonic_ns")
    kill_started_ns = _required_monotonic_ns(containment, "kill_write_started_monotonic_ns")
    kill_completed_ns = _required_monotonic_ns(containment, "kill_write_completed_monotonic_ns")
    empty_ns = _required_monotonic_ns(containment, "empty_verified_monotonic_ns")
    observed_ns = _required_monotonic_ns(trigger, "observed_monotonic_ns")
    if not first_stop_ns <= kill_started_ns <= kill_completed_ns <= empty_ns:
        _fail()
    if observed_ns != first_stop_ns:
        _fail()

    qualification_to_first_stop_ms = _required_ms(
        containment, "qualification_to_first_stop_ms"
    )
    trigger_to_empty_ms = _required_ms(containment, "trigger_to_empty_ms")
    expected_trigger_to_empty_ms = (empty_ns - first_stop_ns) / 1_000_000
    if not math.isclose(
        trigger_to_empty_ms, expected_trigger_to_empty_ms, rel_tol=0.0, abs_tol=1e-9
    ):
        _fail()

    projection["recorded_empty_evidence"] = {
        "empty_verified_monotonic_ns": empty_ns,
        "first_stop_monotonic_ns": first_stop_ns,
        "kill_write_completed_monotonic_ns": kill_completed_ns,
        "kill_write_started_monotonic_ns": kill_started_ns,
        "primitive": _CONTAINMENT_PRIMITIVE,
        "qualification_to_first_stop_ms": qualification_to_first_stop_ms,
        "root_populated": 0,
        "surviving_pids": [],
        "trigger_to_empty_ms": trigger_to_empty_ms,
    }
    return projection


def _unlink_if_owned(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = os.lstat(path)
        if (
            not _link_like(current)
            and stat.S_ISREG(current.st_mode)
            and _identity(current) == identity
        ):
            os.unlink(path)
    except OSError:
        pass


def _write_new_output(path_value: str | os.PathLike[str], payload: bytes) -> None:
    output = _path_without_parent_links(path_value)
    _check_directory_chain(output.parent)
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        _fail()
    else:
        _fail()

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    temporary: Path | None = None
    identity: tuple[int, int] | None = None
    descriptor: int | None = None
    published = False
    complete = False
    try:
        for _ in range(8):
            candidate = output.parent / f".lumi-eggcracker-export-{secrets.token_hex(12)}.tmp"
            try:
                descriptor = os.open(candidate, flags, 0o666)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or temporary is None:
            _fail()

        created = os.fstat(descriptor)
        identity = _identity(created)
        if not stat.S_ISREG(created.st_mode):
            _fail()
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _fail()
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        current_temporary = os.lstat(temporary)
        if (
            _link_like(current_temporary)
            or not stat.S_ISREG(current_temporary.st_mode)
            or _identity(current_temporary) != identity
        ):
            _fail()
        os.link(temporary, output, follow_symlinks=False)
        published = True
        current_output = os.lstat(output)
        if (
            _link_like(current_output)
            or not stat.S_ISREG(current_output.st_mode)
            or _identity(current_output) != identity
        ):
            _fail()
        complete = True
    except ExportError:
        raise
    except Exception:  # noqa: BLE001 - keep OS and path details out of diagnostics.
        _fail()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if published and not complete:
            _unlink_if_owned(output, identity)
        if temporary is not None:
            _unlink_if_owned(temporary, identity)


def export_receipt(
    input_path: str | os.PathLike[str],
    expected_event_id: str,
    output_path: str | os.PathLike[str],
) -> None:
    """Export one validated event; the output contains no unallowlisted fields."""
    if not isinstance(expected_event_id, str) or not _EVENT_ID.fullmatch(expected_event_id):
        _fail()
    raw = _read_source(input_path)
    receipt = _decode_receipt(raw)
    projected = _project_receipt(receipt, expected_event_id)
    document = {
        "export_schema": EXPORT_SCHEMA,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "authentication": "NOT_AUTHENTICATED",
        "live_verification": "NOT_PERFORMED",
        "receipt": projected,
    }
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail()
    _write_new_output(output_path, encoded)


class _QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid command line\n")


def main(argv: list[str] | None = None) -> int:
    parser = _QuietArgumentParser(
        prog="export_detection_receipt.py",
        description="Write a bounded redacted export of one local detection receipt.",
    )
    parser.add_argument("--input", required=True, help="path to a detection receipt JSON file")
    parser.add_argument("--expected-event-id", required=True, help="24 lowercase hex characters")
    parser.add_argument("--output", required=True, help="new output JSON path")
    args = parser.parse_args(argv)
    try:
        export_receipt(args.input, args.expected_event_id, args.output)
    except Exception:  # noqa: BLE001 - never echo untrusted input or OS error text.
        print("export failed: invalid receipt or filesystem path", file=sys.stderr)
        return 1
    print("detection receipt export complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
