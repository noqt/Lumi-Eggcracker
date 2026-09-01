#!/usr/bin/env python3
"""Validate one bounded hosted-proof receipt against the public v1 contract."""

from __future__ import annotations

import argparse
import json
import math
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "hosted-proof-receipt-v1.schema.json"
MAX_RECEIPT_BYTES = 16_384
MAX_SCHEMA_BYTES = 65_536
SUPPORTED_DIALECT = "https://json-schema.org/draft/2020-12/schema"
ANNOTATION_KEYWORDS = {"$id", "$schema", "description", "title"}
VALIDATION_KEYWORDS = {
    "additionalProperties",
    "const",
    "enum",
    "maximum",
    "minimum",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "type",
}


class ReceiptValidationError(ValueError):
    """A bounded validation failure that never includes receipt values."""


class SchemaContractError(ReceiptValidationError):
    """The checked-in schema uses a contract this validator cannot enforce."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for name, item in pairs:
        if name in value:
            raise ReceiptValidationError("JSON contains a duplicate object member")
        value[name] = item
    return value


def _reject_nonstandard_number(_value: str) -> None:
    raise ReceiptValidationError("JSON contains a non-standard number")


def _read_json(path: Path, *, maximum_bytes: int, label: str) -> object:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptValidationError(f"{label} must be a regular file")
        with path.open("rb") as handle:
            encoded = handle.read(maximum_bytes + 1)
    except ReceiptValidationError:
        raise
    except OSError as error:
        raise ReceiptValidationError(f"{label} could not be read") from error
    if len(encoded) > maximum_bytes:
        raise ReceiptValidationError(f"{label} exceeds its safe size bound")
    try:
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_number,
        )
    except ReceiptValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReceiptValidationError(f"{label} is not bounded UTF-8 JSON") from error


def _json_equal(left: object, right: object) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    return type(left) is type(right) and left == right


def _matches_type(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and (isinstance(value, int) or value.is_integer())
        )
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )
    raise SchemaContractError("schema uses an unsupported type")


def _preflight_schema(schema: Mapping[str, Any], *, root: bool = False) -> None:
    """Reject schema drift anywhere before a receipt can select a branch."""
    unknown = set(schema) - ANNOTATION_KEYWORDS - VALIDATION_KEYWORDS
    if unknown:
        raise SchemaContractError("schema uses an unsupported validation keyword")

    for keyword in ANNOTATION_KEYWORDS & set(schema):
        if not isinstance(schema[keyword], str):
            raise SchemaContractError("schema has an invalid annotation")
    if root and schema.get("$schema") != SUPPORTED_DIALECT:
        raise SchemaContractError("schema uses an unsupported dialect")
    if not root and "$schema" in schema:
        raise SchemaContractError("schema has a nested dialect declaration")

    expected_type = schema.get("type")
    if expected_type is not None and expected_type not in {
        "integer",
        "number",
        "object",
        "string",
    }:
        raise SchemaContractError("schema uses an unsupported type")

    branches = schema.get("oneOf")
    if branches is not None:
        if not isinstance(branches, list) or not branches:
            raise SchemaContractError("schema has an invalid oneOf contract")
        for branch in branches:
            if not isinstance(branch, dict):
                raise SchemaContractError("schema has an invalid oneOf branch")
            _preflight_schema(branch)

    properties = schema.get("properties")
    required = schema.get("required")
    additional = schema.get("additionalProperties")
    has_object_contract = (
        properties is not None
        or required is not None
        or "additionalProperties" in schema
    )
    if has_object_contract:
        if (
            expected_type != "object"
            or not isinstance(properties, dict)
            or not isinstance(required, list)
            or additional is not False
            or not all(isinstance(item, str) for item in required)
            or len(required) != len(set(required))
        ):
            raise SchemaContractError("schema has an invalid object contract")
        for name, item_schema in properties.items():
            if not isinstance(name, str) or not isinstance(item_schema, dict):
                raise SchemaContractError("schema has an invalid property contract")
            _preflight_schema(item_schema)

    allowed = schema.get("enum")
    if allowed is not None and (not isinstance(allowed, list) or not allowed):
        raise SchemaContractError("schema has an invalid enum contract")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str) or expected_type != "string":
            raise SchemaContractError("schema has an invalid string pattern")
        try:
            re.compile(pattern)
        except re.error as error:
            raise SchemaContractError("schema has an invalid string pattern") from error

    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if minimum is not None or maximum is not None:
        if expected_type not in {"integer", "number"}:
            raise SchemaContractError("schema has an invalid numeric bound")
        for bound in (minimum, maximum):
            if bound is not None and not _matches_type(bound, "number"):
                raise SchemaContractError("schema has an invalid numeric bound")
        if minimum is not None and maximum is not None and minimum > maximum:
            raise SchemaContractError("schema has inconsistent numeric bounds")


def _validate(value: object, schema: Mapping[str, Any], path: str = "receipt") -> None:
    unknown = set(schema) - ANNOTATION_KEYWORDS - VALIDATION_KEYWORDS
    if unknown:
        raise SchemaContractError("schema uses an unsupported validation keyword")

    branches = schema.get("oneOf")
    if branches is not None:
        if not isinstance(branches, list) or not branches:
            raise SchemaContractError("schema has an invalid oneOf contract")
        matches = 0
        for branch in branches:
            if not isinstance(branch, dict):
                raise SchemaContractError("schema has an invalid oneOf branch")
            try:
                _validate(value, branch, path)
            except SchemaContractError:
                raise
            except ReceiptValidationError:
                continue
            matches += 1
        if matches != 1:
            raise ReceiptValidationError("receipt does not match exactly one v1 shape")

    expected_type = schema.get("type")
    if expected_type is not None and not isinstance(expected_type, str):
        raise SchemaContractError("schema has an invalid type contract")
    if isinstance(expected_type, str) and not _matches_type(value, expected_type):
        raise ReceiptValidationError(f"{path} has the wrong JSON type")

    if "const" in schema and not _json_equal(value, schema["const"]):
        raise ReceiptValidationError(f"{path} does not match its required value")

    allowed = schema.get("enum")
    if allowed is not None and not isinstance(allowed, list):
        raise SchemaContractError("schema has an invalid enum contract")
    if isinstance(allowed, list) and not any(_json_equal(value, item) for item in allowed):
        raise ReceiptValidationError(f"{path} is not an allowed value")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str) or not isinstance(value, str):
            raise SchemaContractError("schema has an invalid string pattern")
        try:
            matches_pattern = re.fullmatch(pattern, value) is not None
        except re.error as error:
            raise SchemaContractError("schema has an invalid string pattern") from error
        if not matches_pattern:
            raise ReceiptValidationError(f"{path} does not match its required format")

    if "minimum" in schema or "maximum" in schema:
        if not _matches_type(value, "number"):
            raise ReceiptValidationError(f"{path} has the wrong JSON type")
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and not _matches_type(minimum, "number"):
            raise SchemaContractError("schema has an invalid minimum")
        if maximum is not None and not _matches_type(maximum, "number"):
            raise SchemaContractError("schema has an invalid maximum")
        if minimum is not None and value < minimum:
            raise ReceiptValidationError(f"{path} is below its allowed bound")
        if maximum is not None and value > maximum:
            raise ReceiptValidationError(f"{path} is above its allowed bound")

    properties = schema.get("properties")
    required = schema.get("required")
    if properties is not None or required is not None or schema.get("additionalProperties") is False:
        if not isinstance(value, dict) or not isinstance(properties, dict):
            raise SchemaContractError("schema has an invalid object contract")
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            raise SchemaContractError("schema has an invalid required-field contract")
        missing = set(required) - set(value)
        if missing:
            raise ReceiptValidationError("receipt is missing a required field")
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            raise ReceiptValidationError("receipt contains an unexpected field")
        for name, item_schema in properties.items():
            if not isinstance(name, str) or not isinstance(item_schema, dict):
                raise SchemaContractError("schema has an invalid property contract")
            if name in value:
                _validate(value[name], item_schema, f"{path}.{name}")


def validate_receipt(receipt: object, schema: object) -> None:
    if not isinstance(schema, dict):
        raise SchemaContractError("schema root must be an object")
    _preflight_schema(schema, root=True)
    _validate(receipt, schema)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="validate one local Lumi Eggcracker hosted-proof receipt against v1"
    )
    parser.add_argument("receipt", type=Path, help="path to one JSON receipt object")
    arguments = parser.parse_args(argv)
    try:
        schema = _read_json(SCHEMA_PATH, maximum_bytes=MAX_SCHEMA_BYTES, label="schema")
        receipt = _read_json(
            arguments.receipt,
            maximum_bytes=MAX_RECEIPT_BYTES,
            label="receipt input",
        )
        validate_receipt(receipt, schema)
    except ReceiptValidationError as error:
        print(f"INVALID hosted-proof receipt v1: {error}", file=sys.stderr)
        return 1
    print("VALID hosted-proof receipt v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
