"""Bounded root-owned local lockdown records.

An incident is deliberately a small post-containment disposition.  It never
participates in the trigger critical path: the supervisor writes the original
empty-cgroup receipt first, then creates or updates one of these records.
"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from .jsonio import JsonInputError, canonical_bytes, load_regular_json
from .records import RUN_ID, write_atomic

SCHEMA = "lumi-eggcracker.incident.v1"
INCIDENT_ID = re.compile(r"[0-9a-f]{24}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
SAFE_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
STATES = {"ACTIVE", "ACKNOWLEDGED", "CLEARED"}
MAX_INCIDENTS = 128
MAX_LINKED_RECEIPTS = 64
MAX_EVIDENCE = 16


def _path(root: Path, incident_id: str) -> Path:
    if not isinstance(incident_id, str) or INCIDENT_ID.fullmatch(incident_id) is None:
        raise JsonInputError("incident identity is invalid")
    return root / f"{incident_id}.json"


def _hex(value: Any, message: str) -> None:
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        raise JsonInputError(message)


def _nonnegative(value: Any, message: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JsonInputError(message)


def _validate_match(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "argv_sha256",
        "executable_sha256",
        "profile",
        "uid",
    }:
        raise JsonInputError("incident match identity is invalid")
    _hex(value["argv_sha256"], "incident argv identity is invalid")
    _hex(value["executable_sha256"], "incident executable identity is invalid")
    if value["profile"] is not None and (
        not isinstance(value["profile"], str) or SAFE_TOKEN.fullmatch(value["profile"]) is None
    ):
        raise JsonInputError("incident profile identity is invalid")
    _nonnegative(value["uid"], "incident match uid is invalid")
    if value["uid"] < 1:
        raise JsonInputError("incident match uid is invalid")
    return value


def _validate_approval(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "argv_sha256",
        "bound_input_sha256",
        "created_monotonic_ns",
        "executable_sha256",
        "name",
        "uid",
    }:
        raise JsonInputError("incident approval identity is invalid")
    if not isinstance(value["name"], str) or SAFE_TOKEN.fullmatch(value["name"]) is None:
        raise JsonInputError("incident approval name is invalid")
    _hex(value["argv_sha256"], "incident approval argv is invalid")
    _hex(value["executable_sha256"], "incident approval executable is invalid")
    _nonnegative(value["created_monotonic_ns"], "incident approval timestamp is invalid")
    _nonnegative(value["uid"], "incident approval uid is invalid")
    if value["uid"] < 1:
        raise JsonInputError("incident approval uid is invalid")
    bound = value["bound_input_sha256"]
    if not isinstance(bound, list) or not 1 <= len(bound) <= 32:
        raise JsonInputError("incident approval inputs are invalid")
    for item in bound:
        _hex(item, "incident approval input digest is invalid")
    return value


def _validate_workload(value: Any) -> dict[str, Any]:
    expected = {"boot_id", "cgroup", "cgroup_device", "cgroup_inode", "run_id", "unit", "uid"}
    if not isinstance(value, dict) or set(value) != expected:
        raise JsonInputError("incident workload identity is invalid")
    if not isinstance(value["boot_id"], str) or not value["boot_id"] or len(value["boot_id"]) > 128:
        raise JsonInputError("incident workload boot identity is invalid")
    if (
        not isinstance(value["cgroup"], str)
        or not value["cgroup"].startswith("/system.slice/lumi-eggcracker-workload-")
        or len(value["cgroup"]) > 256
    ):
        raise JsonInputError("incident workload cgroup identity is invalid")
    if not isinstance(value["unit"], str) or value["unit"] != value["cgroup"].rsplit("/", 1)[-1]:
        raise JsonInputError("incident workload unit identity is invalid")
    if not isinstance(value["run_id"], str) or RUN_ID.fullmatch(value["run_id"]) is None:
        raise JsonInputError("incident workload run identity is invalid")
    for key in ("cgroup_device", "cgroup_inode", "uid"):
        _nonnegative(value[key], "incident workload integer is invalid")
    if value["uid"] < 1:
        raise JsonInputError("incident workload uid is invalid")
    return value


def _validate_ack(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"monotonic_ns", "uid"}:
        raise JsonInputError("incident acknowledgement is invalid")
    _nonnegative(value["monotonic_ns"], "incident acknowledgement timestamp is invalid")
    if value["uid"] != 0:
        raise JsonInputError("incident acknowledgement authority is invalid")
    return value


def _validate_response(value: Any) -> dict[str, Any]:
    expected = {
        "approval_revoked",
        "completed",
        "relaunch_suppressed",
        "response_completed_monotonic_ns",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise JsonInputError("incident response state is invalid")
    for key in ("approval_revoked", "completed", "relaunch_suppressed"):
        if not isinstance(value[key], bool):
            raise JsonInputError("incident response flag is invalid")
    _nonnegative(value["response_completed_monotonic_ns"], "incident response timestamp is invalid")
    return value


def _validate_recurrence(value: Any) -> dict[str, Any]:
    expected = {"contained_matches", "complete_matches", "partial_matches", "sweep_count"}
    if not isinstance(value, dict) or set(value) != expected:
        raise JsonInputError("incident recurrence state is invalid")
    for key in expected:
        _nonnegative(value[key], "incident recurrence count is invalid")
    return value


def _body(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "integrity_sha256"}


def integrity(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(_body(value))).hexdigest()


def validate(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "acknowledgement",
        "approval",
        "catalogue_sha256",
        "clearance",
        "created_monotonic_ns",
        "detector",
        "generation",
        "incident_id",
        "integrity_sha256",
        "linked_receipts",
        "match",
        "original_receipt_digest",
        "policy_sha256",
        "recurrence",
        "response",
        "schema_version",
        "source_commit",
        "state",
        "trigger",
        "version",
        "workload",
    }
    if set(value) != expected or value.get("schema_version") != SCHEMA:
        raise JsonInputError("incident schema is invalid")
    if not isinstance(value["incident_id"], str) or INCIDENT_ID.fullmatch(value["incident_id"]) is None:
        raise JsonInputError("incident identity is invalid")
    _hex(value["integrity_sha256"], "incident integrity is invalid")
    if integrity(value) != value["integrity_sha256"]:
        raise JsonInputError("incident integrity does not match contents")
    for key in ("catalogue_sha256", "original_receipt_digest", "policy_sha256"):
        _hex(value[key], "incident digest is invalid")
    if not isinstance(value["source_commit"], str) or SOURCE.fullmatch(value["source_commit"]) is None:
        raise JsonInputError("incident source identity is invalid")
    if not isinstance(value["version"], str) or SAFE_TOKEN.fullmatch(value["version"]) is None:
        raise JsonInputError("incident version is invalid")
    if not isinstance(value["trigger"], str) or SAFE_TOKEN.fullmatch(value["trigger"]) is None:
        raise JsonInputError("incident trigger is invalid")
    if value["state"] not in STATES:
        raise JsonInputError("incident state is invalid")
    for key in ("created_monotonic_ns", "generation"):
        _nonnegative(value[key], "incident integer is invalid")
    if value["generation"] < 1:
        raise JsonInputError("incident generation is invalid")
    detector = value["detector"]
    if not isinstance(detector, dict) or set(detector) != {"evidence", "profile"}:
        raise JsonInputError("incident detector identity is invalid")
    if detector["profile"] is not None and (
        not isinstance(detector["profile"], str) or SAFE_TOKEN.fullmatch(detector["profile"]) is None
    ):
        raise JsonInputError("incident detector profile is invalid")
    evidence = detector["evidence"]
    if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE:
        raise JsonInputError("incident detector evidence is invalid")
    if any(not isinstance(item, str) or SAFE_TOKEN.fullmatch(item) is None for item in evidence):
        raise JsonInputError("incident detector evidence is invalid")
    _validate_match(value["match"])
    _validate_approval(value["approval"])
    _validate_workload(value["workload"])
    _validate_ack(value["acknowledgement"])
    _validate_ack(value["clearance"])
    _validate_response(value["response"])
    _validate_recurrence(value["recurrence"])
    linked = value["linked_receipts"]
    if not isinstance(linked, list) or len(linked) > MAX_LINKED_RECEIPTS:
        raise JsonInputError("incident linked receipts are invalid")
    for item in linked:
        _hex(item, "incident linked receipt digest is invalid")
    if len(set(linked)) != len(linked):
        raise JsonInputError("incident linked receipt is duplicated")
    if value["state"] == "CLEARED" and value["clearance"] is None:
        raise JsonInputError("cleared incident lacks root clearance")
    return value


def load_all(root: Path) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    if root.is_symlink() or not root.is_dir():
        raise JsonInputError("incident root is invalid")
    paths = sorted(root.glob("*.json"))
    if len(paths) > MAX_INCIDENTS:
        raise JsonInputError("incident store exceeds bounded capacity")
    values: list[dict[str, Any]] = []
    for path in paths:
        if path.is_symlink() or path.name != f"{path.stem}.json":
            raise JsonInputError("incident filename is invalid")
        value = validate(load_regular_json(path))
        if value["incident_id"] != path.stem:
            raise JsonInputError("incident name/path mismatch")
        values.append(value)
    return values


def _write(root: Path, value: dict[str, Any]) -> dict[str, Any]:
    checked = validate(value)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_atomic(_path(root, checked["incident_id"]), checked)
    return checked


def receipt_digest(receipt: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(receipt)).hexdigest()


def policy_digest(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(policy)).hexdigest()


def create(
    root: Path,
    *,
    receipt: dict[str, Any],
    policy: dict[str, Any],
    catalogue_sha256: str,
    source_commit: str,
    version: str,
    trigger: str,
    profile: str | None,
    evidence: list[str],
    match: dict[str, Any],
    workload: dict[str, Any],
    approval: dict[str, Any] | None,
) -> dict[str, Any]:
    event_id = receipt.get("event_id")
    if not isinstance(event_id, str) or INCIDENT_ID.fullmatch(event_id) is None:
        raise JsonInputError("incident requires an exact receipt identity")
    value: dict[str, Any] = {
        "acknowledgement": None,
        "approval": approval,
        "catalogue_sha256": catalogue_sha256,
        "clearance": None,
        "created_monotonic_ns": time.monotonic_ns(),
        "detector": {"evidence": list(evidence[:MAX_EVIDENCE]), "profile": profile},
        "generation": 1,
        "incident_id": event_id,
        "integrity_sha256": "0" * 64,
        "linked_receipts": [],
        "match": dict(match),
        "original_receipt_digest": receipt_digest(receipt),
        "policy_sha256": policy_digest(policy),
        "recurrence": {
            "contained_matches": 0,
            "complete_matches": 0,
            "partial_matches": 0,
            "sweep_count": 0,
        },
        "response": {
            "approval_revoked": False,
            "completed": False,
            "relaunch_suppressed": True,
            "response_completed_monotonic_ns": 0,
        },
        "schema_version": SCHEMA,
        "source_commit": source_commit,
        "state": "ACTIVE",
        "trigger": trigger,
        "version": version,
        "workload": dict(workload),
    }
    value["integrity_sha256"] = integrity(value)
    return _write(root, value)


def update(root: Path, value: dict[str, Any], **changes: Any) -> dict[str, Any]:
    current = validate(dict(value))
    if any(key not in current for key in changes):
        raise JsonInputError("incident update field is invalid")
    updated = dict(current)
    updated.update(changes)
    updated["generation"] = current["generation"] + 1
    updated["integrity_sha256"] = integrity(updated)
    return _write(root, updated)


def active(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [value for value in values if value["state"] in {"ACTIVE", "ACKNOWLEDGED"}]


def find_match(
    values: list[dict[str, Any]],
    *,
    argv_sha256: str,
    uid: int,
    executable_sha256: str | None = None,
    profile: str | None = None,
) -> dict[str, Any] | None:
    for value in active(values):
        identity = value["match"]
        if identity["uid"] != uid or identity["argv_sha256"] != argv_sha256:
            continue
        expected_executable = identity["executable_sha256"]
        if executable_sha256 is not None and expected_executable != "0" * 64 and executable_sha256 != expected_executable:
            continue
        expected_profile = identity["profile"]
        if profile is not None and expected_profile is not None and profile != expected_profile:
            continue
        return value
    return None


def link(root: Path, value: dict[str, Any], receipt: dict[str, Any], *, partial: bool = False) -> dict[str, Any]:
    linked = list(value["linked_receipts"])
    digest = receipt_digest(receipt)
    if digest not in linked:
        if len(linked) >= MAX_LINKED_RECEIPTS:
            raise JsonInputError("incident linked receipt capacity reached")
        linked.append(digest)
    recurrence = dict(value["recurrence"])
    recurrence["complete_matches"] += 1
    recurrence["contained_matches"] += 1
    if partial:
        recurrence["partial_matches"] += 1
    return update(root, value, linked_receipts=linked, recurrence=recurrence)


def summary(value: dict[str, Any]) -> dict[str, Any]:
    checked = validate(value)
    return {
        "incident_id": checked["incident_id"],
        "state": checked["state"],
        "trigger": checked["trigger"],
        "created_monotonic_ns": checked["created_monotonic_ns"],
        "generation": checked["generation"],
        "relaunch_suppressed": checked["response"]["relaunch_suppressed"],
        "response_completed": checked["response"]["completed"],
        "recurrence_contained": checked["recurrence"]["contained_matches"],
    }


def public_detail(value: dict[str, Any]) -> dict[str, Any]:
    """Return bounded exact detail for the root-admin socket only."""
    checked = validate(value)
    return {
        "incident_id": checked["incident_id"],
        "state": checked["state"],
        "trigger": checked["trigger"],
        "version": checked["version"],
        "source_commit": checked["source_commit"],
        "catalogue_sha256": checked["catalogue_sha256"],
        "policy_sha256": checked["policy_sha256"],
        "detector": checked["detector"],
        "match": checked["match"],
        "approval": checked["approval"],
        "workload": checked["workload"],
        "original_receipt_digest": checked["original_receipt_digest"],
        "linked_receipts": list(checked["linked_receipts"]),
        "recurrence": checked["recurrence"],
        "response": checked["response"],
        "acknowledgement": checked["acknowledgement"],
        "clearance": checked["clearance"],
        "generation": checked["generation"],
    }
