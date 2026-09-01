"""Strict deterministic content-evidence detector catalogue."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .jsonio import JsonInputError, canonical_bytes

SCHEMA = "lumi-eggcracker.detectors.v3"
HEX = re.compile(r"[0-9a-f]{64}\Z")
KINDS = {"exe_basename", "argv_token", "argv_model_suffix", "open_model_suffix", "map_basename"}
REQUIRED_GROUPS = {"MODEL_CONTENT", "MODEL_RUNTIME"}
OPTIONAL_GROUPS = {"MODEL_TOPOLOGY"}
GROUPS = REQUIRED_GROUPS | OPTIONAL_GROUPS


class Snapshot(Protocol):
    exe_basename: str
    argv: tuple[str, ...]
    fd_paths: tuple[str, ...]
    map_basenames: tuple[str, ...]


@dataclass(frozen=True)
class Profile:
    identifier: str
    path: str
    predicates: tuple[dict[str, Any], ...] = ()
    groups: tuple[dict[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class Catalogue:
    digest: str
    profiles: tuple[Profile, ...]


@dataclass(frozen=True)
class DetectionMatch:
    profile: str
    path: str
    evidence: tuple[str, ...]


def bundled_bytes() -> bytes:
    return (
        importlib.resources.files("lumi_eggcracker")
        .joinpath("detector_catalogue.json")
        .read_bytes()
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonInputError("duplicate detector catalogue key")
        result[key] = value
    return result


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", value):
        raise JsonInputError("detector profile identity is invalid")
    return value


def _values(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in value)
    ):
        raise JsonInputError("detector evidence values are invalid")
    if len(set(value)) != len(value):
        raise JsonInputError("detector evidence values are duplicated")
    return tuple(value)


def load_catalogue(raw: bytes, *, expected_digest: str | None = None) -> Catalogue:
    digest = hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and (
        not HEX.fullmatch(expected_digest) or digest != expected_digest
    ):
        raise JsonInputError("detector catalogue digest is invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, JsonInputError) as error:
        raise JsonInputError(f"detector catalogue is invalid: {error}") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"profiles", "schema_version"}
        or value.get("schema_version") != SCHEMA
    ):
        raise JsonInputError("detector catalogue schema is invalid")
    raw_profiles = value["profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise JsonInputError("detector catalogue profiles are invalid")
    profiles: list[Profile] = []
    seen: set[str] = set()
    for item in raw_profiles:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise JsonInputError("detector profile schema is invalid")
        identifier = _identifier(item.get("id"))
        if identifier in seen:
            raise JsonInputError("detector profile identity is duplicated")
        path = item["path"]
        if path == "FAST_NAME" and set(item) == {"all", "id", "path"}:
            predicates: list[dict[str, Any]] = []
            if not isinstance(item["all"], list) or not item["all"]:
                raise JsonInputError("detector profile predicates are invalid")
            for predicate in item["all"]:
                if (
                    not isinstance(predicate, dict)
                    or set(predicate) != {"kind", "values"}
                    or predicate["kind"] not in KINDS
                ):
                    raise JsonInputError("detector predicate schema is invalid")
                predicates.append(
                    {"kind": predicate["kind"], "values": _values(predicate["values"])}
                )
            profile = Profile(identifier, path, tuple(predicates))
        elif path == "CONTENT" and set(item) == {"id", "path", "require_all_groups"}:
            raw_groups = item["require_all_groups"]
            if not isinstance(raw_groups, list) or len(raw_groups) < 2:
                raise JsonInputError("content profile requires independent evidence groups")
            groups: list[dict[str, tuple[str, ...]]] = []
            present: set[str] = set()
            for group in raw_groups:
                if (
                    not isinstance(group, dict)
                    or set(group) != {"any", "group"}
                    or group["group"] not in GROUPS
                    or group["group"] in present
                ):
                    raise JsonInputError("content evidence group is invalid")
                present.add(group["group"])
                groups.append({"group": group["group"], "any": _values(group["any"])})
            if not REQUIRED_GROUPS <= present:
                raise JsonInputError("content profile must require model and runtime evidence")
            profile = Profile(identifier, path, groups=tuple(groups))
        else:
            raise JsonInputError("detector profile schema is invalid")
        seen.add(identifier)
        profiles.append(profile)
    return Catalogue(digest, tuple(profiles))


def load_bundled(*, expected_digest: str | None = None) -> Catalogue:
    return load_catalogue(bundled_bytes(), expected_digest=expected_digest)


def _matches(snapshot: Snapshot, predicate: dict[str, Any]) -> bool:
    values = tuple(predicate["values"])
    kind = predicate["kind"]
    if kind == "exe_basename":
        return snapshot.exe_basename in values
    if kind == "argv_token":
        return any(token in values for token in snapshot.argv)
    if kind == "argv_model_suffix":
        return any(argument.lower().endswith(tuple(values)) for argument in snapshot.argv)
    if kind == "open_model_suffix":
        return any(path.lower().endswith(tuple(values)) for path in snapshot.fd_paths)
    if kind == "map_basename":
        return any(name in values for name in snapshot.map_basenames)
    raise JsonInputError("unknown detector predicate")


def match(
    catalogue: Catalogue, snapshot: Snapshot, *, evidence: dict[str, set[str]] | None = None
) -> DetectionMatch | None:
    """Return one complete profile match, never partial, fuzzy or scored evidence."""
    supplied = evidence or {}
    for profile in catalogue.profiles:
        if profile.path == "FAST_NAME":
            matched = tuple(
                predicate["kind"]
                for predicate in profile.predicates
                if _matches(snapshot, predicate)
            )
            if len(matched) == len(profile.predicates):
                return DetectionMatch(profile.identifier, profile.path, matched)
        else:
            matched_ids: list[str] = []
            for group in profile.groups:
                values = tuple(
                    sorted(set(group["any"]).intersection(supplied.get(group["group"], set())))
                )
                if not values:
                    break
                matched_ids.extend(values)
            else:
                return DetectionMatch(profile.identifier, profile.path, tuple(matched_ids))
    return None


def public_catalogue(catalogue: Catalogue) -> dict[str, Any]:
    profiles: list[dict[str, object]] = []
    for profile in catalogue.profiles:
        value: dict[str, object] = {"id": profile.identifier, "path": profile.path}
        if profile.path == "FAST_NAME":
            value["predicates"] = [item["kind"] for item in profile.predicates]
        else:
            value["evidence_groups"] = [
                {"group": item["group"], "any": list(item["any"])} for item in profile.groups
            ]
        profiles.append(value)
    return {"digest": catalogue.digest, "profiles": profiles, "schema_version": SCHEMA}


def canonical_catalogue_bytes(catalogue: Catalogue) -> bytes:
    return canonical_bytes(public_catalogue(catalogue))
