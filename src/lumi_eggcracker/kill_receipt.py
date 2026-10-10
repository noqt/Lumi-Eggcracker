"""Offline validation of one bounded manual containment receipt."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "lumi-eggcracker.receipt.v3"
VALIDATION_SCHEMA = "lumi-eggcracker.kill-receipt-validation.v1"
MAX_INPUT_BYTES = 32 * 1024
MAX_OUTPUT_BYTES = 2048
MAX_JSON_DEPTH = 32
MAX_MONOTONIC_NS = (1 << 63) - 1
MAX_INTEGER = (1 << 63) - 1
MAX_TEXT_BYTES = 4096
MAX_RETURN_CODE = (1 << 31) - 1
SAFE_ERROR = "eggcracker validate-kill-receipt: receipt is invalid or cannot be read"
LIMITATIONS = (
    "Structural validation only; not authentication or independent containment proof."
)

_EVENT_ID = re.compile(r"[0-9a-f]{24}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_BOOT_ID = re.compile(r"[0-9a-f-]{36}\Z")
_RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_CGROUP = re.compile(r"/system\.slice/lumi-eggcracker-workload-([0-9a-f]{24})\.service\Z")
_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_UTC_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z\Z"
)
_REPARSE_POINT = 0x400
_TOP_LEVEL_FIELDS = {
    "cleanup",
    "containment",
    "event_id",
    "receipt_written_utc",
    "result",
    "schema_version",
    "source_commit",
    "trigger",
    "version",
    "workload",
}


class ReceiptValidationError(ValueError):
    """An input is not a current OPERATOR receipt."""


def _fail() -> None:
    raise ReceiptValidationError


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _parse_int(token: str) -> int:
    if len(token.lstrip("-")) > 20:
        _fail()
    value = int(token)
    if not -MAX_INTEGER <= value <= MAX_INTEGER:
        _fail()
    return value


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
            continue
        if character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail()
        elif character in "]}":
            depth -= 1
            if depth < 0:
                _fail()
    if quoted or escaped or depth:
        _fail()


def _decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT_BYTES:
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
    except (
        ReceiptValidationError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        _fail()
    if type(value) is not dict:
        _fail()
    return value


def _link_like(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _read_source(path_value: str | os.PathLike[str]) -> bytes:
    """Read one bounded regular file without following a replacing symlink."""

    if not isinstance(path_value, (str, os.PathLike)):
        _fail()
    descriptor: int | None = None
    try:
        path = Path(path_value)
        before = os.lstat(path)
        if _link_like(before) or not stat.S_ISREG(before.st_mode):
            _fail()
        if not 1 <= before.st_size <= MAX_INPUT_BYTES:
            _fail()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            _link_like(opened)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_identity(before, opened)
            or not 1 <= opened.st_size <= MAX_INPUT_BYTES
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
            not 1 <= len(raw) <= MAX_INPUT_BYTES
            or len(raw) != opened.st_size
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
        ):
            _fail()
        return raw
    except (ReceiptValidationError, OSError, TypeError, ValueError):
        _fail()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _expect_keys(value: object, expected: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        _fail()
    return value


def _bounded_text(
    value: object,
    *,
    maximum: int = MAX_TEXT_BYTES,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        _fail()
    try:
        if len(value.encode("utf-8", errors="strict")) > maximum:
            _fail()
    except UnicodeEncodeError:
        _fail()
    return value


def _required_text(
    parent: dict[str, Any],
    key: str,
    pattern: re.Pattern[str],
    *,
    maximum: int = MAX_TEXT_BYTES,
) -> str:
    value = parent.get(key)
    if type(value) is not str or len(value) > maximum or not pattern.fullmatch(value):
        _fail()
    return value


def _required_int(
    parent: dict[str, Any],
    key: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_INTEGER,
) -> int:
    value = parent.get(key)
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()
    return value


def _required_bool(parent: dict[str, Any], key: str, *, value: bool | None = None) -> bool:
    item = parent.get(key)
    if type(item) is not bool or value is not None and item is not value:
        _fail()
    return item


def _required_finite_ms(parent: dict[str, Any], key: str) -> float | int:
    value = parent.get(key)
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value:
        _fail()
    if value > MAX_MONOTONIC_NS / 1_000_000:
        _fail()
    return value


def _validate_timestamp(value: object) -> str:
    if type(value) is not str or not _UTC_TIMESTAMP.fullmatch(value):
        _fail()
    try:
        dt.datetime.fromisoformat(value)
    except ValueError:
        _fail()
    return value


def _validate_cleanup(value: object) -> None:
    if type(value) is not dict:
        _fail()
    if set(value) == {"attempted"}:
        _required_bool(value, "attempted", value=False)
        return
    expected = {"attempted", "systemctl_stop_returncode", "systemctl_stop_stderr"}
    if not expected <= set(value):
        _fail()
    _required_bool(value, "attempted", value=True)
    _required_int(
        value,
        "systemctl_stop_returncode",
        minimum=-MAX_RETURN_CODE,
        maximum=MAX_RETURN_CODE,
    )
    _bounded_text(
        value["systemctl_stop_stderr"], maximum=MAX_TEXT_BYTES, allow_empty=True
    )
    allowed = expected | {
        "offline_boundary",
        "offline_boundary_error",
    }
    if not set(value) <= allowed:
        _fail()
    if "offline_boundary_error" in value:
        _bounded_text(value["offline_boundary_error"], maximum=160, allow_empty=True)
    if "offline_boundary" in value:
        boundary = value["offline_boundary"]
        if type(boundary) is not dict:
            _fail()
        if set(boundary) == {"error"}:
            _bounded_text(boundary["error"], maximum=160, allow_empty=True)
        elif set(boundary) == {
            "removed",
            "workload_namespace_removed",
            "sink_namespace_removed",
        }:
            _required_int(boundary, "removed", maximum=2)
            _required_bool(boundary, "workload_namespace_removed", value=True)
            _required_bool(boundary, "sink_namespace_removed", value=True)
        else:
            _fail()


def _validate_containment(value: object, observed_ns: int) -> None:
    containment = _expect_keys(
        value,
        {
            "cgroup_kill_written",
            "descendant_cgroups_checked",
            "empty_verified_monotonic_ns",
            "kill_write_completed_monotonic_ns",
            "kill_write_started_monotonic_ns",
            "primitive",
            "root_populated",
            "surviving_pids",
            "trigger_to_empty_ms",
        },
    )
    _required_bool(containment, "cgroup_kill_written", value=True)
    _required_int(containment, "descendant_cgroups_checked", minimum=0, maximum=4096)
    kill_started_ns = _required_int(
        containment, "kill_write_started_monotonic_ns", maximum=MAX_MONOTONIC_NS
    )
    kill_completed_ns = _required_int(
        containment, "kill_write_completed_monotonic_ns", maximum=MAX_MONOTONIC_NS
    )
    empty_ns = _required_int(
        containment, "empty_verified_monotonic_ns", maximum=MAX_MONOTONIC_NS
    )
    if not observed_ns <= kill_started_ns <= kill_completed_ns <= empty_ns:
        _fail()
    if containment["primitive"] != "cgroup.kill":
        _fail()
    _required_int(containment, "root_populated", maximum=0)
    survivors = containment.get("surviving_pids")
    if type(survivors) is not list or survivors:
        _fail()
    trigger_to_empty_ms = _required_finite_ms(containment, "trigger_to_empty_ms")
    expected_ms = (empty_ns - observed_ns) / 1_000_000
    if not math.isclose(trigger_to_empty_ms, expected_ms, rel_tol=0.0, abs_tol=1e-9):
        _fail()


def _validate_workload(value: object) -> None:
    workload = _expect_keys(
        value,
        {
            "boot_id",
            "cgroup",
            "cgroup_device",
            "cgroup_inode",
            "name",
            "run_id",
            "unit",
            "workload_uid",
        },
    )
    _required_text(workload, "boot_id", _BOOT_ID, maximum=36)
    cgroup = _required_text(workload, "cgroup", _CGROUP, maximum=96)
    run_id = _required_text(workload, "run_id", _RUN_ID, maximum=24)
    if cgroup != f"/system.slice/lumi-eggcracker-workload-{run_id}.service":
        _fail()
    _required_text(workload, "name", _NAME, maximum=64)
    if workload["unit"] != f"lumi-eggcracker-workload-{run_id}.service":
        _fail()
    _required_int(workload, "cgroup_device", minimum=1)
    _required_int(workload, "cgroup_inode", minimum=1)
    _required_int(workload, "workload_uid", minimum=1, maximum=(1 << 32) - 1)


def _validate_receipt(value: dict[str, Any]) -> None:
    expected = _TOP_LEVEL_FIELDS
    optional_response_fields = {"receipt_path", "cleanup_update_error"}
    if not set(value) <= expected | optional_response_fields:
        _fail()
    if "cleanup_update_error" in value:
        _required_bool(value, "cleanup_update_error", value=True)
        if "receipt_path" not in value:
            _fail()
    if "receipt_path" in value:
        _bounded_text(value["receipt_path"], maximum=1024)
    if value["schema_version"] != RECEIPT_SCHEMA:
        _fail()
    if value["result"] != "TERMINATED":
        _fail()
    _required_text(value, "event_id", _EVENT_ID, maximum=24)
    _required_text(value, "source_commit", _COMMIT, maximum=40)
    _required_text(value, "version", _SEMVER, maximum=64)
    _validate_timestamp(value["receipt_written_utc"])

    trigger = _expect_keys(value["trigger"], {"kind", "observed_monotonic_ns"})
    if trigger["kind"] != "OPERATOR":
        _fail()
    observed_ns = _required_int(trigger, "observed_monotonic_ns", maximum=MAX_MONOTONIC_NS)
    _validate_containment(value["containment"], observed_ns)
    _validate_cleanup(value["cleanup"])
    _validate_workload(value["workload"])

    if "receipt_path" in value and value["cleanup"].get("attempted") is not True:
        _fail()


def validate_receipt(path: str | os.PathLike[str]) -> dict[str, str]:
    """Validate one receipt and return only fixed nonidentifying fields."""

    value = _decode(_read_source(path))
    _validate_receipt(value)
    result = {
        "limitations": LIMITATIONS,
        "result": "STRUCTURE_VALID",
        "schema_version": VALIDATION_SCHEMA,
    }
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail()
    return result


def main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(SAFE_ERROR, file=sys.stderr)
        return 4
    try:
        summary = validate_receipt(arguments[0])
    except Exception:  # noqa: BLE001 - never echo untrusted paths or receipt data.
        print(SAFE_ERROR, file=sys.stderr)
        return 4
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
