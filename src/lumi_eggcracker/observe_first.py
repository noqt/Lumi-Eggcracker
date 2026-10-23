"""Offline, synthetic observe-first detector preview.

This module is intentionally a read-only adapter around the bundled detector
catalogue.  It accepts one bounded JSON description of a synthetic, quiescent,
offline observation and reports what the existing detector would decide.  It
does not observe processes, request approval, or perform any actuation.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import detectors

SCHEMA = "lumi-eggcracker.observe-first.v1"
MAX_INPUT_BYTES = 32 * 1024
MAX_ARRAY_ITEMS = 64
MAX_STRING_LENGTH = 256
MAX_ARG_LENGTH = 512

_SAFE_IDENTIFIER = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")
_SAFE_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,512}\Z")
_GROUPS = ("MODEL_CONTENT", "MODEL_RUNTIME", "MODEL_TOPOLOGY")
_LIMITATIONS = (
    (
        "No live observation, approval, identity, topology, provenance, containment, "
        "safety, qualification, or release claim is provided."
    ),
)
_SELECTION_RULE = (
    "The detector selects the first complete CONTENT requirement profile in maintained "
    "catalogue order."
)
_SELECTION_LIMITATION = (
    "This explanation covers bounded synthetic evidence only; it does not establish "
    "true workload or framework identity, topology, provenance, safety, native "
    "qualification, or authorization."
)


class ObserveFirstInputError(ValueError):
    """The caller supplied an invalid observe-first input."""


@dataclass(frozen=True)
class _Snapshot:
    exe_basename: str
    argv: tuple[str, ...]
    fd_paths: tuple[str, ...]
    map_basenames: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    """Validated synthetic input accepted by :func:`evaluate`."""

    snapshot: _Snapshot
    evidence: dict[str, set[str]]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ObserveFirstInputError("duplicate JSON object member")
        result[key] = value
    return result


def _decode(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise ObserveFirstInputError("input JSON exceeds the 32 KiB bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except ObserveFirstInputError:
        raise
    except RecursionError as error:
        raise ObserveFirstInputError("input JSON nesting exceeds the bound") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ObserveFirstInputError("input is not valid bounded UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ObserveFirstInputError("input JSON root must be an object")
    return value


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ObserveFirstInputError(f"{label} schema is invalid")
    return value


def _bounded_text(value: object, *, label: str, maximum: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or _SAFE_TEXT.fullmatch(value) is None:
        raise ObserveFirstInputError(f"{label} is invalid")
    return value


def _safe_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ObserveFirstInputError(f"{label} is invalid")
    return value


def _bounded_strings(
    value: object,
    *,
    label: str,
    maximum_length: int = MAX_STRING_LENGTH,
    identifiers: bool = False,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_ARRAY_ITEMS:
        raise ObserveFirstInputError(f"{label} array is invalid")
    if not allow_empty and not value:
        raise ObserveFirstInputError(f"{label} array must not be empty")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        parsed = (
            _safe_identifier(item, label=label)
            if identifiers
            else _bounded_text(item, label=label, maximum=maximum_length)
        )
        if parsed in seen:
            raise ObserveFirstInputError(f"{label} array contains a duplicate")
        seen.add(parsed)
        result.append(parsed)
    return tuple(result)


def _parse_snapshot(value: object) -> _Snapshot:
    snapshot = _exact_keys(
        value,
        {"exe_basename", "argv", "fd_paths", "map_basenames"},
        "snapshot",
    )
    executable = _safe_identifier(snapshot["exe_basename"], label="snapshot executable")
    argv = _bounded_strings(
        snapshot["argv"],
        label="snapshot argv",
        maximum_length=MAX_ARG_LENGTH,
        allow_empty=False,
    )
    fd_paths = _bounded_strings(snapshot["fd_paths"], label="snapshot file descriptors")
    map_basenames = _bounded_strings(snapshot["map_basenames"], label="snapshot mappings")
    return _Snapshot(executable, argv, fd_paths, map_basenames)


def _parse_evidence(value: object) -> dict[str, set[str]]:
    evidence = _exact_keys(value, set(_GROUPS), "evidence")
    return {
        group: set(
            _bounded_strings(
                evidence[group],
                label=f"evidence {group}",
                identifiers=True,
            )
        )
        for group in _GROUPS
    }


def parse_input(value: object) -> Observation:
    """Validate a decoded observe-first object without consulting live state."""

    root = _exact_keys(
        value,
        {"schema_version", "synthetic", "quiescent", "offline", "snapshot", "evidence"},
        "observe-first input",
    )
    if root["schema_version"] != SCHEMA:
        raise ObserveFirstInputError("observe-first schema version is invalid")
    for flag in ("synthetic", "quiescent", "offline"):
        if root[flag] is not True:
            raise ObserveFirstInputError(f"{flag} must be explicitly true")
    return Observation(_parse_snapshot(root["snapshot"]), _parse_evidence(root["evidence"]))


def load_input(path: Path) -> Observation:
    """Load one bounded regular non-symlink JSON input file."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise ObserveFirstInputError("cannot inspect input file") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ObserveFirstInputError("input must be a regular non-symlink file")
    if not 1 <= metadata.st_size <= MAX_INPUT_BYTES:
        raise ObserveFirstInputError("input file must be between 1 and 32 KiB")
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        raise ObserveFirstInputError("cannot read input file") from error
    try:
        after = path.lstat()
    except OSError as error:
        raise ObserveFirstInputError("input file changed while being read") from error
    before_identity = (
        stat.S_IFMT(metadata.st_mode),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    after_identity = (
        stat.S_IFMT(after.st_mode),
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if (
        before_identity != after_identity
        or stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or len(raw) != after.st_size
        or len(raw) > MAX_INPUT_BYTES
    ):
        raise ObserveFirstInputError("input file changed or exceeds the 32 KiB bound")
    return parse_input(_decode(raw))


def _allowed_evidence_ids(catalogue: detectors.Catalogue) -> dict[str, set[str]]:
    allowed = {group: set() for group in _GROUPS}
    for profile in catalogue.profiles:
        for requirement in profile.groups:
            allowed[requirement["group"]].update(requirement["any"])
    return allowed


def _validate_evidence(catalogue: detectors.Catalogue, evidence: dict[str, set[str]]) -> None:
    allowed = _allowed_evidence_ids(catalogue)
    for group in _GROUPS:
        if evidence[group] - allowed[group]:
            raise ObserveFirstInputError(
                f"evidence {group} contains an unknown or wrong-group identifier"
            )


def _content_explanation(
    catalogue: detectors.Catalogue, evidence: dict[str, set[str]]
) -> dict[str, list[dict[str, Any]]]:
    """Describe catalogue requirements without deriving another verdict."""

    profiles: list[dict[str, Any]] = []
    for profile in catalogue.profiles:
        if profile.path != "CONTENT":
            continue
        requirements: list[dict[str, Any]] = []
        for requirement in profile.groups:
            alternatives = tuple(requirement["any"])
            supplied = tuple(
                value
                for value in alternatives
                if value in evidence.get(requirement["group"], set())
            )
            satisfied = bool(supplied)
            requirements.append(
                {
                    "any": list(alternatives),
                    "group": requirement["group"],
                    "missing": [] if satisfied else list(alternatives),
                    "satisfied": satisfied,
                    "supplied": list(supplied),
                }
            )
        profiles.append(
            {
                "path": profile.path,
                "profile": profile.identifier,
                "requirements": requirements,
            }
        )
    return {"profiles": profiles}


def _selection_explanation(
    catalogue: detectors.Catalogue,
    evidence: dict[str, set[str]],
    detected: detectors.DetectionMatch | None,
) -> dict[str, Any]:
    complete_profiles: list[str] = []
    for profile in catalogue.profiles:
        if profile.path != "CONTENT":
            continue
        if all(
            any(
                evidence.get(requirement["group"], set()).intersection(requirement["any"])
            )
            for requirement in profile.groups
        ):
            complete_profiles.append(profile.identifier)
    return {
        "complete_content_profile_ids": complete_profiles,
        "limitations": [_SELECTION_LIMITATION],
        "selected_profile": None if detected is None else detected.profile,
        "selection_rule": _SELECTION_RULE,
    }


def evaluate(
    observation: Observation,
    *,
    explain_selection: bool = False,
) -> dict[str, Any]:
    """Return a deterministic inert result using the current detector APIs."""

    catalogue = detectors.load_bundled()
    _validate_evidence(catalogue, observation.evidence)
    detected = detectors.match(
        catalogue,
        observation.snapshot,
        evidence=observation.evidence,
    )
    result: dict[str, Any] = {
        "actuation_performed": False,
        "limitations": list(_LIMITATIONS),
        "non_match_not_safety": True,
        "offline_only": True,
        "result": "NO_COMPLETE_MATCH" if detected is None else "WOULD_ACT",
        "schema_version": SCHEMA,
        "simulation_only": True,
    }
    result["explanation"] = _content_explanation(catalogue, observation.evidence)
    if explain_selection:
        result["selection_explanation"] = _selection_explanation(
            catalogue, observation.evidence, detected
        )
    if detected is None:
        result["match"] = None
    else:
        result["match"] = {
            "evidence": list(detected.evidence),
            "path": detected.path,
            "profile": detected.profile,
        }
    return result


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the dedicated ``python -m lumi_eggcracker.observe_first`` command."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    explain_selection_flag = "--explain-selection"
    selected_flags = [argument for argument in arguments if argument == explain_selection_flag]
    if len(selected_flags) > 1:
        print("usage: python -m lumi_eggcracker.observe_first FILE", file=sys.stderr)
        return 2
    explain_selection = bool(selected_flags)
    if explain_selection:
        arguments = [argument for argument in arguments if argument != explain_selection_flag]
    if len(arguments) != 1:
        print("usage: python -m lumi_eggcracker.observe_first FILE", file=sys.stderr)
        return 2
    try:
        result = evaluate(
            load_input(Path(arguments[0])), explain_selection=explain_selection
        )
    except ObserveFirstInputError as error:
        print(f"observe-first input rejected: {error}", file=sys.stderr)
        return 2
    except RecursionError:
        print("observe-first input rejected", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("observe-first input rejected", file=sys.stderr)
        return 2
    print(_canonical_json(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
