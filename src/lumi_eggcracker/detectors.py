"""Strict deterministic AI-runtime detector catalogue."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .jsonio import JsonInputError, canonical_bytes

SCHEMA = "lumi-eggcracker.detectors.v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
KINDS = {"exe_basename", "argv_token", "argv_model_suffix", "open_model_suffix", "map_basename"}


class Snapshot(Protocol):
    exe_basename: str
    argv: tuple[str, ...]
    fd_paths: tuple[str, ...]
    map_basenames: tuple[str, ...]


@dataclass(frozen=True)
class Profile:
    identifier: str
    predicates: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class Catalogue:
    digest: str
    profiles: tuple[Profile, ...]


def bundled_bytes() -> bytes:
    return importlib.resources.files("lumi_eggcracker").joinpath("detector_catalogue.json").read_bytes()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonInputError("duplicate detector catalogue key")
        result[key] = value
    return result


def load_catalogue(raw: bytes, *, expected_digest: str | None = None) -> Catalogue:
    digest = hashlib.sha256(raw).hexdigest()
    if expected_digest is not None and (not HEX.fullmatch(expected_digest) or digest != expected_digest):
        raise JsonInputError("detector catalogue digest is invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, JsonInputError) as error:
        raise JsonInputError(f"detector catalogue is invalid: {error}") from error
    if not isinstance(value, dict) or set(value) != {"profiles", "schema_version"} or value.get("schema_version") != SCHEMA:
        raise JsonInputError("detector catalogue schema is invalid")
    profiles = value["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise JsonInputError("detector catalogue profiles are invalid")
    result: list[Profile] = []
    seen: set[str] = set()
    for item in profiles:
        if not isinstance(item, dict) or set(item) != {"all", "id"}:
            raise JsonInputError("detector profile schema is invalid")
        identifier, predicates = item["id"], item["all"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", identifier) or identifier in seen:
            raise JsonInputError("detector profile identity is invalid")
        if not isinstance(predicates, list) or not predicates:
            raise JsonInputError("detector profile predicates are invalid")
        clean: list[dict[str, Any]] = []
        for predicate in predicates:
            if not isinstance(predicate, dict) or set(predicate) != {"kind", "values"}:
                raise JsonInputError("detector predicate schema is invalid")
            kind, values = predicate["kind"], predicate["values"]
            if kind not in KINDS or not isinstance(values, list) or not values or not all(isinstance(entry, str) and 1 <= len(entry) <= 128 for entry in values):
                raise JsonInputError("detector predicate is invalid")
            clean.append({"kind": kind, "values": tuple(values)})
        seen.add(identifier)
        result.append(Profile(identifier, tuple(clean)))
    return Catalogue(digest, tuple(result))


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


def match(catalogue: Catalogue, snapshot: Snapshot) -> tuple[str, tuple[str, ...]] | None:
    """Return one complete profile match, never a partial or scored decision."""
    for profile in catalogue.profiles:
        matched = tuple(predicate["kind"] for predicate in profile.predicates if _matches(snapshot, predicate))
        if len(matched) == len(profile.predicates):
            return profile.identifier, matched
    return None


def public_catalogue(catalogue: Catalogue) -> dict[str, Any]:
    return {"digest": catalogue.digest, "profiles": [{"id": profile.identifier, "predicates": [item["kind"] for item in profile.predicates]} for profile in catalogue.profiles], "schema_version": SCHEMA}


def canonical_catalogue_bytes(catalogue: Catalogue) -> bytes:
    """Small deterministic public representation used only by direct tests."""
    return canonical_bytes(public_catalogue(catalogue))
