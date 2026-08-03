"""Strict root-owned run records and post-containment receipts."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .containment import CgroupIdentity, EmptyProof
from .jsonio import JsonInputError, canonical_bytes, load_regular_json


RUN_SCHEMA = "lumi-nutcracker.run.v1"
RECEIPT_SCHEMA = "lumi-nutcracker.receipt.v1"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, canonical_bytes(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def record_path(runs: Path, name: str) -> Path:
    if not NAME.fullmatch(name):
        raise JsonInputError("workload name is invalid")
    return runs / f"{name}.json"


def validate_run(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "argv", "boot_id", "cgroup", "cgroup_device", "cgroup_inode", "created_monotonic_ns",
        "max_pids", "name", "operator_uid", "run_id", "schema_version", "state", "unit",
        "workload_gid", "workload_uid",
    }
    if set(value) != expected or value.get("schema_version") != RUN_SCHEMA:
        raise JsonInputError("run record schema is invalid")
    if not isinstance(value["name"], str) or not NAME.fullmatch(value["name"]):
        raise JsonInputError("run record name is invalid")
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"[0-9a-f]{24}", value["run_id"]):
        raise JsonInputError("run record identity is invalid")
    if value["unit"] != f"lumi-nutcracker-workload-{value['run_id']}.service":
        raise JsonInputError("run record unit is invalid")
    if not isinstance(value["argv"], list) or not value["argv"] or not all(isinstance(item, str) and item for item in value["argv"]):
        raise JsonInputError("run record argv is invalid")
    keys = ("cgroup_device", "cgroup_inode", "created_monotonic_ns", "operator_uid", "workload_gid", "workload_uid", "max_pids")
    if any(isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0 for key in keys):
        raise JsonInputError("run record integer field is invalid")
    if value["state"] not in {"RUNNING", "COMPLETED_ALLOWED", "TERMINATED", "CONTAINMENT_FAILED", "CONTAINED_RECEIPT_FAILED"}:
        raise JsonInputError("run record state is invalid")
    return value


def identity_from_run(value: dict[str, Any]) -> CgroupIdentity:
    record = validate_run(value)
    return CgroupIdentity(record["boot_id"], record["cgroup"], record["cgroup_device"], record["cgroup_inode"], record["run_id"], record["unit"])


def load_run(runs: Path, name: str) -> dict[str, Any]:
    return validate_run(load_regular_json(record_path(runs, name)))


def make_receipt(
    *, record: dict[str, Any], trigger: str, trigger_ns: int, kill_started_ns: int, kill_complete_ns: int,
    empty_ns: int, proof: EmptyProof, version: str, source_commit: str, cleanup: dict[str, Any], event_id: str,
) -> dict[str, Any]:
    if trigger not in {"OPERATOR", "PID_LIMIT", "SUPERVISOR_RESTART_FAIL_CLOSED"} or not re.fullmatch(r"[0-9a-f]{24}", event_id):
        raise JsonInputError("receipt trigger or event identity is invalid")
    if not proof.complete or proof.root_populated != 0 or proof.surviving_pids:
        raise JsonInputError("cannot issue a success receipt before exact emptiness proof")
    return {
        "cleanup": cleanup,
        "containment": {
            "cgroup_kill_written": True,
            "descendant_cgroups_checked": proof.descendant_cgroups_checked,
            "empty_verified_monotonic_ns": empty_ns,
            "kill_write_completed_monotonic_ns": kill_complete_ns,
            "kill_write_started_monotonic_ns": kill_started_ns,
            "primitive": "cgroup.kill",
            "root_populated": proof.root_populated,
            "surviving_pids": proof.surviving_pids,
            "trigger_to_empty_ms": (empty_ns - trigger_ns) / 1_000_000,
        },
        "event_id": event_id,
        "receipt_written_utc": None,
        "result": "TERMINATED",
        "schema_version": RECEIPT_SCHEMA,
        "source_commit": source_commit,
        "trigger": {"kind": trigger, "observed_monotonic_ns": trigger_ns},
        "version": version,
        "workload": {
            "boot_id": record["boot_id"], "cgroup": record["cgroup"], "cgroup_device": record["cgroup_device"],
            "cgroup_inode": record["cgroup_inode"], "name": record["name"], "run_id": record["run_id"],
            "unit": record["unit"], "workload_uid": record["workload_uid"],
        },
    }
