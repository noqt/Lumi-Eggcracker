"""Compare two bounded, redacted detection receipt exports.

The comparator is deliberately offline.  It reads exactly the two paths supplied
by its caller, validates the exporter v1 allowlist, and writes one bounded JSON
comparison to stdout.  It does not import the detector, containment, broker, or
any other runtime code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

EXPORT_SCHEMA = "lumi-eggcracker.redacted-detection-receipt-export.v1"
EXPORT_SCHEMA_V2 = "lumi-eggcracker.redacted-detection-receipt-export.v2"
CLASSIFICATION_BASIS = "COMPLETE_QUALIFIED_LOCAL_PROFILE_MATCH_NOT_AI_IDENTITY"
COMPARISON_SCHEMA = "lumi-eggcracker.redacted-detection-receipt-comparison.v1"
RECEIPT_SCHEMA = "lumi-eggcracker.detection-receipt.v2"
DETECTOR_SCHEMA = "lumi-eggcracker.detectors.v3"
MAX_INPUT_BYTES = 8_192
MAX_OUTPUT_BYTES = 8_192
MAX_JSON_DEPTH = 64
MAX_MONOTONIC_NS = (1 << 63) - 1
_REPARSE_POINT = 0x400
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
_TOP_LEVEL_FIELDS = {
    "authentication",
    "export_schema",
    "live_verification",
    "receipt",
    "source_sha256",
}
_RECEIPT_FIELDS = {
    "catalogue_sha256",
    "detector",
    "event_id",
    "receipt_written_utc",
    "recorded_result",
    "schema_version",
    "source_commit",
    "trigger",
    "version",
}
_RECEIPT_FIELDS_V2 = _RECEIPT_FIELDS | {"classification_basis"}
_DETECTOR_FIELDS = {"catalogue_schema", "detection_path", "profile"}
_TRIGGER_FIELDS = {"kind"}
_EVIDENCE_FIELDS = {
    "empty_verified_monotonic_ns",
    "first_stop_monotonic_ns",
    "kill_write_completed_monotonic_ns",
    "kill_write_started_monotonic_ns",
    "primitive",
    "qualification_to_first_stop_ms",
    "root_populated",
    "surviving_pids",
    "trigger_to_empty_ms",
}


class ComparisonError(ValueError):
    """A deliberately non-specific validation or filesystem failure."""


class OutputAlreadyExistsError(ComparisonError):
    """An existing output path must never be replaced."""


def _fail() -> None:
    raise ComparisonError("comparison failed")


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
    if quoted or escaped or depth:
        _fail()


def _decode_export(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
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
    except (ComparisonError, UnicodeDecodeError, json.JSONDecodeError, OverflowError, RecursionError, TypeError, ValueError):
        _fail()
    if not isinstance(value, dict):
        _fail()
    return value


def _path_without_parent_links(value: str | os.PathLike[str]) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _fail()
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
        # Reject Windows alternate data streams and device spellings.  The
        # comparator accepts ordinary files only; a colon is valid only in a
        # drive anchor, never in a path component.
        anchor_parts = len(Path(path.anchor).parts)
        if any(":" in part for part in path.parts[anchor_parts:]):
            _fail()
        if os.name == "nt":
            reserved = {"CON", "PRN", "AUX", "NUL"}
            reserved.update({f"COM{index}" for index in range(1, 10)})
            reserved.update({f"LPT{index}" for index in range(1, 10)})
            for part in path.parts[anchor_parts:]:
                stem = part.rstrip(" .").split(".", maxsplit=1)[0].upper()
                if stem in reserved:
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


def _ensure_output_distinct(
    output_value: str | os.PathLike[str],
    input_values: tuple[str | os.PathLike[str], str | os.PathLike[str]],
) -> Path:
    output = _path_without_parent_links(output_value)
    _check_directory_chain(output.parent)
    output_key = os.path.normcase(os.path.abspath(os.fspath(output)))
    for input_value in input_values:
        source = _path_without_parent_links(input_value)
        _check_directory_chain(source.parent)
        source_key = os.path.normcase(os.path.abspath(os.fspath(source)))
        if source_key == output_key:
            raise OutputAlreadyExistsError()
        try:
            source_info = os.lstat(source)
        except (OSError, ValueError):
            _fail()
        if _link_like(source_info) or not stat.S_ISREG(source_info.st_mode):
            _fail()
        try:
            output_info = os.lstat(output)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            _fail()
        if _link_like(output_info):
            _fail()
        if _identity(source_info) == _identity(output_info):
            raise OutputAlreadyExistsError()
    return output


def _read_source(path_value: str | os.PathLike[str]) -> bytes:
    """Read one explicit regular file with bounded, race-aware checks."""

    path = _path_without_parent_links(path_value)
    _check_directory_chain(path.parent)
    descriptor: int | None = None
    try:
        before = os.lstat(path)
        if _link_like(before) or not stat.S_ISREG(before.st_mode):
            _fail()
        if before.st_size > MAX_INPUT_BYTES:
            _fail()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _link_like(opened)
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
    except (ComparisonError, OSError, ValueError):
        _fail()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _expect_keys(value: object, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail()
    return value


def _required_text(
    parent: dict[str, Any],
    key: str,
    pattern: re.Pattern[str],
    *,
    maximum: int = 128,
) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or len(value) > maximum or not pattern.fullmatch(value):
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


def _validate_export(raw: bytes) -> dict[str, Any]:
    document = _expect_keys(_decode_export(raw), _TOP_LEVEL_FIELDS)
    export_schema = document["export_schema"]
    if export_schema not in (EXPORT_SCHEMA, EXPORT_SCHEMA_V2):
        _fail()
    if document["authentication"] != "NOT_AUTHENTICATED":
        _fail()
    if document["live_verification"] != "NOT_PERFORMED":
        _fail()
    _required_text(document, "source_sha256", _SHA256, maximum=64)

    receipt_value = document["receipt"]
    receipt_fields = (
        _RECEIPT_FIELDS_V2 if export_schema == EXPORT_SCHEMA_V2 else _RECEIPT_FIELDS
    )
    if not isinstance(receipt_value, dict) or not (
        set(receipt_value) == receipt_fields
        or set(receipt_value) == receipt_fields | {"recorded_empty_evidence"}
    ):
        _fail()
    receipt = receipt_value
    if (
        export_schema == EXPORT_SCHEMA_V2
        and receipt["classification_basis"] != CLASSIFICATION_BASIS
    ):
        _fail()
    if receipt["schema_version"] != RECEIPT_SCHEMA:
        _fail()
    _required_text(receipt, "event_id", _EVENT_ID, maximum=24)
    source_commit = _required_text(receipt, "source_commit", _COMMIT, maximum=40)
    version = _required_text(receipt, "version", _SEMVER, maximum=64)
    catalogue_sha256 = _required_text(receipt, "catalogue_sha256", _SHA256, maximum=64)
    receipt_written_utc = _validate_timestamp(receipt["receipt_written_utc"])

    detector = _expect_keys(receipt["detector"], _DETECTOR_FIELDS)
    profile = detector["profile"]
    if not isinstance(profile, str) or profile not in _PROFILE_TRIGGER:
        _fail()
    if detector["detection_path"] != "CONTENT" or detector["catalogue_schema"] != DETECTOR_SCHEMA:
        _fail()

    trigger = _expect_keys(receipt["trigger"], _TRIGGER_FIELDS)
    if trigger["kind"] != _PROFILE_TRIGGER[profile]:
        _fail()

    result = receipt["recorded_result"]
    if result not in ("TERMINATED", "CONTAINMENT_FAILED"):
        _fail()

    evidence: dict[str, Any] | None = None
    if result == "TERMINATED":
        # The exporter always emits all timing/empty-state fields for a
        # terminated result.  Missing fields are invalid input, not zeroes.
        if set(receipt) != receipt_fields | {"recorded_empty_evidence"}:
            _fail()
        evidence = _expect_keys(receipt["recorded_empty_evidence"], _EVIDENCE_FIELDS)
        if evidence["primitive"] != _CONTAINMENT_PRIMITIVE:
            _fail()
        if type(evidence["root_populated"]) is not int or evidence["root_populated"] != 0:
            _fail()
        if type(evidence["surviving_pids"]) is not list or evidence["surviving_pids"]:
            _fail()

        first_stop_ns = _required_monotonic_ns(evidence, "first_stop_monotonic_ns")
        kill_started_ns = _required_monotonic_ns(evidence, "kill_write_started_monotonic_ns")
        kill_completed_ns = _required_monotonic_ns(evidence, "kill_write_completed_monotonic_ns")
        empty_ns = _required_monotonic_ns(evidence, "empty_verified_monotonic_ns")
        if not first_stop_ns <= kill_started_ns <= kill_completed_ns <= empty_ns:
            _fail()
        qualification_ms = _required_ms(evidence, "qualification_to_first_stop_ms")
        trigger_to_empty_ms = _required_ms(evidence, "trigger_to_empty_ms")
        expected_trigger_to_empty_ms = (empty_ns - first_stop_ns) / 1_000_000
        if not math.isclose(
            trigger_to_empty_ms,
            expected_trigger_to_empty_ms,
            rel_tol=0.0,
            abs_tol=1e-9,
        ):
            _fail()
        timing = {
            "qualification_to_first_stop_ms": qualification_ms,
            "trigger_to_empty_ms": trigger_to_empty_ms,
            "primitive": _CONTAINMENT_PRIMITIVE,
        }
    else:
        # Failure exports intentionally contain neither timing nor raw error.
        if set(receipt) != receipt_fields:
            _fail()
        timing = None

    return {
        "source_commit": source_commit,
        "version": version,
        "catalogue_sha256": catalogue_sha256,
        "profile": profile,
        "trigger": trigger["kind"],
        "recorded_result": result,
        "receipt_written_utc": receipt_written_utc,
        "timing": timing,
    }


def _context(record: dict[str, Any]) -> tuple[str, ...]:
    timing = record["timing"]
    primitive = timing["primitive"] if timing is not None else ""
    return (
        record["source_commit"],
        record["version"],
        record["catalogue_sha256"],
        record["profile"],
        record["trigger"],
        primitive,
    )


def _result_change(before: str, after: str) -> str:
    if before == after:
        return "UNCHANGED"
    if before == "TERMINATED" and after == "CONTAINMENT_FAILED":
        return "TERMINATED_TO_CONTAINMENT_FAILED"
    if before == "CONTAINMENT_FAILED" and after == "TERMINATED":
        return "CONTAINMENT_FAILED_TO_TERMINATED"
    return "CHANGED"


def _record_summary(record: dict[str, Any]) -> dict[str, str]:
    return {
        "source_commit": record["source_commit"],
        "version": record["version"],
        "catalogue_sha256": record["catalogue_sha256"],
        "profile": record["profile"],
        "recorded_result": record["recorded_result"],
    }


def _timing_comparison(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_timing = before["timing"]
    after_timing = after["timing"]
    if before_timing is None or after_timing is None:
        return {
            "status": "UNAVAILABLE",
            "basis": "MISSING_RECORDED_TIMING",
        }
    if _context(before) != _context(after):
        return {
            "status": "INCOMPARABLE",
            "basis": "RECORDED_CONTEXT_MISMATCH",
        }

    before_durations = {
        "qualification_to_first_stop_ms": before_timing["qualification_to_first_stop_ms"],
        "trigger_to_empty_ms": before_timing["trigger_to_empty_ms"],
    }
    after_durations = {
        "qualification_to_first_stop_ms": after_timing["qualification_to_first_stop_ms"],
        "trigger_to_empty_ms": after_timing["trigger_to_empty_ms"],
    }
    return {
        "status": "COMPARABLE",
        "basis": "MATCHING_RECORDED_CONTEXT_ONLY",
        "before_durations_ms": before_durations,
        "after_durations_ms": after_durations,
        "delta_ms": {
            "qualification_to_first_stop_ms": (
                after_durations["qualification_to_first_stop_ms"]
                - before_durations["qualification_to_first_stop_ms"]
            ),
            "trigger_to_empty_ms": (
                after_durations["trigger_to_empty_ms"]
                - before_durations["trigger_to_empty_ms"]
            ),
        },
    }


def compare_receipts(
    before_path: str | os.PathLike[str],
    after_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Return a fixed-field comparison of exactly two explicit exports."""

    before = _validate_export(_read_source(before_path))
    after = _validate_export(_read_source(after_path))
    changes = {
        "source_commit": "UNCHANGED" if before["source_commit"] == after["source_commit"] else "CHANGED",
        "version": "UNCHANGED" if before["version"] == after["version"] else "CHANGED",
        "catalogue_sha256": (
            "UNCHANGED"
            if before["catalogue_sha256"] == after["catalogue_sha256"]
            else "CHANGED"
        ),
        "profile": "UNCHANGED" if before["profile"] == after["profile"] else "CHANGED",
        "recorded_result": _result_change(
            before["recorded_result"], after["recorded_result"]
        ),
    }
    return {
        "comparison_schema": COMPARISON_SCHEMA,
        "authentication": "NOT_AUTHENTICATED",
        "live_verification": "NOT_PERFORMED",
        "comparison_status": "RECORDED",
        "comparison_basis": "RECORDED_EXPORTS_ONLY",
        "before": _record_summary(before),
        "after": _record_summary(after),
        "changes": changes,
        "timing_comparison": _timing_comparison(before, after),
        "native_qualification": "NOT_PERFORMED",
        "independent_observation": "NOT_PERFORMED",
        "performance_evidence": "NOT_PERFORMED",
    }


def _encode_output(value: dict[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        _fail()
    if len(encoded) > MAX_OUTPUT_BYTES:
        _fail()
    return encoded


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
    """Publish one bounded output through an exclusive temp and no-clobber link."""

    output = _path_without_parent_links(path_value)
    _check_directory_chain(output.parent)
    try:
        existing = os.lstat(output)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        _fail()
    else:
        if not _link_like(existing) and stat.S_ISREG(existing.st_mode):
            raise OutputAlreadyExistsError()
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
            candidate = output.parent / f".lumi-eggcracker-comparison-{secrets.token_hex(12)}.tmp"
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
        if _link_like(created) or not stat.S_ISREG(created.st_mode):
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
    except ComparisonError:
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


class _QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: invalid command line\n")


def main(argv: list[str] | None = None) -> int:
    parser = _QuietArgumentParser(
        prog="compare_detection_receipts.py",
        description="Compare two explicit redacted detection receipt exports.",
    )
    parser.add_argument("--before", required=True, metavar="FILE", help="first export file")
    parser.add_argument("--after", required=True, metavar="FILE", help="second export file")
    parser.add_argument("--output", metavar="FILE", help="new comparison JSON file")
    args = parser.parse_args(argv)
    try:
        output = _encode_output(compare_receipts(args.before, args.after))
        if args.output is None:
            sys.stdout.write(output.decode("utf-8"))
            return 0
        _ensure_output_distinct(args.output, (args.before, args.after))
        _write_new_output(args.output, output)
    except OutputAlreadyExistsError:
        print(
            "comparison failed: OUTPUT_ALREADY_EXISTS; choose a new output filename",
            file=sys.stderr,
        )
        return 1
    except Exception:  # noqa: BLE001 - never echo untrusted input or OS error text.
        print("comparison failed: invalid redacted export or filesystem path", file=sys.stderr)
        return 1
    print("comparison written", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
