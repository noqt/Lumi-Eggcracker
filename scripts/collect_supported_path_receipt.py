#!/usr/bin/env python3
"""Create or verify one bounded, redacted local supported-path receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

MAX_INPUT_BYTES = 4_096
MAX_RECEIPT_BYTES = 8_192
SCHEMA_VERSION = "lumi-eggcracker-supported-path-receipt-v1"
RECEIPT_FIELDS = {
    "schema_version",
    "recorded_at_utc",
    "supported_environment",
    "supported_path",
    "exact_command",
    "expected_result",
    "observed_result",
    "permission_to_quote",
    "privacy",
}
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
SUPPORTED_ENVIRONMENT = "disposable-native-ubuntu-24.04-cgroup-v2"
SUPPORTED_PATH = "containment-primitive-probe"
EXACT_COMMAND = (
    "sudo /usr/bin/python3 -I -S scripts/containment_probe.py "
    "--i-understand-this-kills-a-test-tree"
)
EXPECTED_RESULT = (
    "result=TERMINATED,target_survivors=0,canary_survived=true,"
    "root_populated=0,cleanup_complete=true,exit=0"
)
SOURCE_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SOURCE_TREE_PATTERN = re.compile(r"[0-9a-f]{64}")
BLOCKER_STAGES = {"host-preflight", "command-start", "probe-execution", "receipt-check"}
BLOCKER_CODES = {
    "CGROUP_KILL_REQUIRED",
    "CGROUP_V2_REQUIRED",
    "COMMAND_FAILED",
    "OTHER_REDACTED_BLOCKER",
    "PIDFD_REQUIRED",
    "RECEIPT_INVALID",
    "RECEIPT_MISSING",
    "ROOT_REQUIRED",
    "SOURCE_IDENTITY_REQUIRED",
    "SYSTEMD_REQUIRED",
    "UNSUPPORTED_HOST",
}
INPUT_FIELDS = {
    "supported_environment",
    "supported_path",
    "exact_command",
    "expected_result",
    "observed_result",
    "permission_to_quote",
}
PRIVACY = {
    "redacted": True,
    "secrets_collected": False,
    "source_code_collected": False,
    "credentials_collected": False,
    "personal_data_collected": False,
    "raw_environment_collected": False,
    "raw_argv_collected": False,
    "raw_output_collected": False,
    "network_or_upload_used": False,
}


class ReceiptInputError(ValueError):
    """A bounded failure whose message never contains operator-supplied values."""


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ReceiptInputError("invalid command-line arguments")


def _reject_nonstandard_number(_value: str) -> object:
    raise ReceiptInputError("receipt contains a non-standard number")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            raise ReceiptInputError("input contains a duplicate object member")
        value[name] = item
    return value


def _read_input(path: Path) -> object:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReceiptInputError("input must be a regular file, not a link")
        with path.open("rb") as handle:
            encoded = handle.read(MAX_INPUT_BYTES + 1)
    except ReceiptInputError:
        raise
    except OSError as error:
        raise ReceiptInputError("input could not be read") from error
    if len(encoded) > MAX_INPUT_BYTES:
        raise ReceiptInputError("input exceeds its safe size bound")
    try:
        return json.loads(encoded.decode("utf-8"), object_pairs_hook=_unique_object)
    except ReceiptInputError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReceiptInputError("input is not bounded UTF-8 JSON") from error


def _require_exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ReceiptInputError(f"{label} does not match the closed schema")


def _validate_source_identity(observed: Mapping[str, object]) -> None:
    source_commit = observed["source_commit"]
    source_tree = observed["source_tree_sha256"]
    if not isinstance(source_commit, str) or SOURCE_COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise ReceiptInputError("source_commit is not an exact lowercase commit identity")
    if not isinstance(source_tree, str) or SOURCE_TREE_PATTERN.fullmatch(source_tree) is None:
        raise ReceiptInputError("source_tree_sha256 is not an exact lowercase tree identity")


def _validate_observed_result(observed: object) -> dict[str, object]:
    if not isinstance(observed, dict):
        raise ReceiptInputError("observed_result must be an object")
    outcome = observed.get("outcome")
    if outcome == "supported-success":
        _require_exact_fields(
            observed,
            {
                "outcome",
                "result",
                "target_survivors",
                "canary_survived",
                "root_populated",
                "cleanup_complete",
                "source_commit",
                "source_tree_sha256",
            },
            "supported success",
        )
        required_observations = {
            "result": "TERMINATED",
            "target_survivors": 0,
            "canary_survived": True,
            "root_populated": 0,
            "cleanup_complete": True,
        }
        for field, expected in required_observations.items():
            actual = observed[field]
            if type(actual) is not type(expected) or actual != expected:
                raise ReceiptInputError(f"observed success field {field} is not the required value")
        _validate_source_identity(observed)
    elif outcome == "reproducible-blocker":
        _require_exact_fields(
            observed,
            {
                "outcome",
                "blocker_stage",
                "blocker_code",
                "source_commit",
                "source_tree_sha256",
            },
            "reproducible blocker",
        )
        blocker_stage = observed["blocker_stage"]
        if not isinstance(blocker_stage, str) or blocker_stage not in BLOCKER_STAGES:
            raise ReceiptInputError("blocker_stage is not an allowed redacted value")
        blocker_code = observed["blocker_code"]
        if not isinstance(blocker_code, str) or blocker_code not in BLOCKER_CODES:
            raise ReceiptInputError("blocker_code is not an allowed redacted value")
        _validate_source_identity(observed)
    else:
        raise ReceiptInputError("observed_result outcome is not supported")

    return dict(observed)


def _validate_input(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReceiptInputError("input root must be an object")
    _require_exact_fields(value, INPUT_FIELDS, "input")

    fixed_strings = {
        "supported_environment": SUPPORTED_ENVIRONMENT,
        "supported_path": SUPPORTED_PATH,
        "exact_command": EXACT_COMMAND,
        "expected_result": EXPECTED_RESULT,
    }
    for field, expected in fixed_strings.items():
        if not isinstance(value[field], str) or value[field] != expected:
            raise ReceiptInputError(f"input field {field} is not the supported fixed value")

    permission = value["permission_to_quote"]
    if not isinstance(permission, bool):
        raise ReceiptInputError("permission_to_quote must be an explicit boolean")

    _validate_observed_result(value["observed_result"])
    return dict(value)


def _safe_receipt_parent(path: Path) -> Path:
    parent = Path(os.path.abspath(path.parent))
    try:
        for candidate in (parent, *parent.parents):
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ReceiptInputError("receipt parent must contain no links or non-directories")
    except ReceiptInputError:
        raise
    except (OSError, ValueError) as error:
        raise ReceiptInputError("receipt parent is not an existing regular directory") from error
    return parent


def _read_final_receipt(path: Path) -> tuple[object, str]:
    _safe_receipt_parent(path)
    descriptor = -1
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReceiptInputError("receipt must be a regular file, not a link")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            current = os.fstat(handle.fileno())
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
                raise ReceiptInputError("receipt must be a regular file, not a link")
            encoded = handle.read(MAX_RECEIPT_BYTES + 1)
    except ReceiptInputError:
        raise
    except (OSError, ValueError) as error:
        raise ReceiptInputError("receipt could not be read") from error
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ReceiptInputError("receipt exceeds its safe size bound")
    receipt_sha256 = hashlib.sha256(encoded).hexdigest()
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_number,
        )
    except ReceiptInputError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ReceiptInputError("receipt is not bounded UTF-8 JSON") from error
    return value, receipt_sha256


def _validate_expected_source_identity(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReceiptInputError(f"{label} is not an exact lowercase source identity")
    return value


def _validate_final_receipt(
    value: object,
    *,
    expected_source_commit: str,
    expected_source_tree_sha256: str,
) -> str:
    if not isinstance(value, dict):
        raise ReceiptInputError("receipt root must be an object")
    _require_exact_fields(value, RECEIPT_FIELDS, "receipt")

    fixed_strings = {
        "schema_version": SCHEMA_VERSION,
        "supported_environment": SUPPORTED_ENVIRONMENT,
        "supported_path": SUPPORTED_PATH,
        "exact_command": EXACT_COMMAND,
        "expected_result": EXPECTED_RESULT,
    }
    for field, expected in fixed_strings.items():
        if not isinstance(value[field], str) or value[field] != expected:
            raise ReceiptInputError(f"receipt field {field} is not the supported fixed value")

    recorded_at = value["recorded_at_utc"]
    if not isinstance(recorded_at, str) or TIMESTAMP_PATTERN.fullmatch(recorded_at) is None:
        raise ReceiptInputError("recorded_at_utc is not an exact UTC timestamp")
    try:
        datetime.strptime(recorded_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ReceiptInputError("recorded_at_utc is not an exact UTC timestamp") from error

    permission = value["permission_to_quote"]
    if not isinstance(permission, bool):
        raise ReceiptInputError("permission_to_quote must be an explicit boolean")

    privacy = value["privacy"]
    if not isinstance(privacy, dict):
        raise ReceiptInputError("privacy does not match the closed schema")
    _require_exact_fields(privacy, set(PRIVACY), "privacy")
    for field, expected in PRIVACY.items():
        actual = privacy[field]
        if type(actual) is not type(expected) or actual != expected:
            raise ReceiptInputError("privacy does not match the required redacted values")

    observed = _validate_observed_result(value["observed_result"])
    _validate_expected_source_identity(
        expected_source_commit, SOURCE_COMMIT_PATTERN, "expected source_commit"
    )
    _validate_expected_source_identity(
        expected_source_tree_sha256, SOURCE_TREE_PATTERN, "expected source_tree_sha256"
    )
    if (
        observed["source_commit"] != expected_source_commit
        or observed["source_tree_sha256"] != expected_source_tree_sha256
    ):
        raise ReceiptInputError("receipt source identity does not match the expected identities")
    outcome = observed["outcome"]
    if not isinstance(outcome, str):
        raise ReceiptInputError("observed_result outcome is not supported")
    return outcome


def _safe_output_parent(destination: Path) -> Path:
    parent = Path(os.path.abspath(destination.parent))
    try:
        for candidate in (parent, *parent.parents):
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ReceiptInputError("output parent must contain no links or non-directories")
    except ReceiptInputError:
        raise
    except OSError as error:
        raise ReceiptInputError("output parent is not an existing regular directory") from error
    return parent


def _write_new_receipt(destination: Path, receipt: Mapping[str, object]) -> None:
    parent = _safe_output_parent(destination)
    destination = parent / destination.name
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ReceiptInputError("output could not be checked safely") from error
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReceiptInputError("output must not be a link or non-regular file")
        raise ReceiptInputError("output already exists; refusing to overwrite it")

    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ReceiptInputError("receipt exceeds its safe size bound")

    temporary = parent / f".{destination.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    linked = False
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        linked = True
    except OSError as error:
        raise ReceiptInputError("receipt could not be written safely") from error
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            if not linked:
                raise ReceiptInputError("temporary receipt could not be removed safely") from None


def _build_receipt(value: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "recorded_at_utc": datetime.now(UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        **value,
        "privacy": dict(PRIVACY),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(
        description="write or verify one bounded local supported-path receipt"
    )
    verification_requested = "--verify-receipt" in (sys.argv[1:] if argv is None else argv)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--i-opt-in-to-write-local-receipt",
        action="store_true",
        help="explicitly allow this command to write the local redacted receipt",
    )
    modes.add_argument(
        "--verify-receipt",
        type=Path,
        help="read and verify one final local JSON receipt without writing",
    )
    parser.add_argument(
        "--expect-source-commit",
        help="expected exact lowercase source commit identity for verification",
    )
    parser.add_argument(
        "--expect-source-tree-sha256",
        help="expected exact lowercase source tree identity for verification",
    )
    parser.add_argument("--input", type=Path, help="bounded local JSON input")
    parser.add_argument("--output", type=Path, help="new local JSON receipt")
    try:
        arguments = parser.parse_args(argv)
        verification_requested = arguments.verify_receipt is not None
        if arguments.verify_receipt is not None:
            if (
                arguments.i_opt_in_to_write_local_receipt
                or arguments.input is not None
                or arguments.output is not None
            ):
                raise ReceiptInputError("verification mode cannot be combined with write mode")
            if (
                arguments.expect_source_commit is None
                or arguments.expect_source_tree_sha256 is None
            ):
                raise ReceiptInputError("verification requires both expected source identities")
            _validate_expected_source_identity(
                arguments.expect_source_commit, SOURCE_COMMIT_PATTERN, "expected source_commit"
            )
            _validate_expected_source_identity(
                arguments.expect_source_tree_sha256,
                SOURCE_TREE_PATTERN,
                "expected source_tree_sha256",
            )
            receipt, receipt_sha256 = _read_final_receipt(arguments.verify_receipt)
            outcome = _validate_final_receipt(
                receipt,
                expected_source_commit=arguments.expect_source_commit,
                expected_source_tree_sha256=arguments.expect_source_tree_sha256,
            )
            print(
                json.dumps(
                    {"outcome": outcome, "receipt_sha256": receipt_sha256},
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0
        if (
            arguments.expect_source_commit is not None
            or arguments.expect_source_tree_sha256 is not None
        ):
            raise ReceiptInputError("expected source identities require --verify-receipt")
        if not arguments.i_opt_in_to_write_local_receipt:
            raise ReceiptInputError("explicit opt-in is required; no receipt was written")
        if arguments.input is None or arguments.output is None:
            raise ReceiptInputError("write mode requires --input and --output")
        value = _validate_input(_read_input(arguments.input))
        _write_new_receipt(arguments.output, _build_receipt(value))
    except ReceiptInputError as error:
        prefix = "NOT VERIFIED" if verification_requested else "NOT WRITTEN"
        print(f"{prefix}: {error}", file=sys.stderr)
        return 2
    print("WROTE local redacted supported-path receipt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
