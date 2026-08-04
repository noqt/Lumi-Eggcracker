"""Strict root-owned run records and post-containment receipts."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .containment import CgroupIdentity, EmptyProof
from .jsonio import JsonInputError, canonical_bytes, load_regular_json

RUN_SCHEMA = "lumi-eggcracker.run.v3"
RECEIPT_SCHEMA = "lumi-eggcracker.receipt.v2"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
ACTIVE_STATES = {"STARTING", "RUNNING"}
TERMINAL_STATES = {"COMPLETED_ALLOWED", "TERMINATED", "CONTAINMENT_FAILED", "CONTAINED_RECEIPT_FAILED"}


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        os.write(descriptor, canonical_bytes(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not hasattr(os, "fchmod"):
        os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    try:
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return  # Directory fsync is unavailable on Windows test hosts.
    try:
        os.fsync(directory)
    except OSError:
        return
    finally:
        os.close(directory)


def run_path(runs: Path, run_id: str) -> Path:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise JsonInputError("workload run identity is invalid")
    return runs / f"{run_id}.json"


def name_path(names: Path, name: str) -> Path:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise JsonInputError("workload name is invalid")
    return names / f"{name}.json"


def command_summary(argv: list[str]) -> dict[str, Any]:
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise JsonInputError("workload argv is invalid")
    return {"argv_count": len(argv), "argv_sha256": hashlib.sha256("\0".join(argv).encode("utf-8")).hexdigest(), "executable": argv[0]}


def validate_run(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "argv_count", "argv_sha256", "boot_id", "cgroup", "cgroup_device", "cgroup_inode",
        "created_monotonic_ns", "cpu_quota_percent", "executable", "max_memory_mib", "max_pids", "name", "operator_uid", "run_id",
        "schema_version", "state", "unit", "workload_gid", "workload_uid",
    }
    if set(value) != expected or value.get("schema_version") != RUN_SCHEMA:
        raise JsonInputError("run record schema is invalid")
    if not isinstance(value["name"], str) or not NAME.fullmatch(value["name"]):
        raise JsonInputError("run record name is invalid")
    if not isinstance(value["run_id"], str) or not RUN_ID.fullmatch(value["run_id"]):
        raise JsonInputError("run record identity is invalid")
    if value["unit"] != f"lumi-eggcracker-workload-{value['run_id']}.service":
        raise JsonInputError("run record unit is invalid")
    if not isinstance(value["executable"], str) or not value["executable"]:
        raise JsonInputError("run record executable is invalid")
    if not isinstance(value["argv_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["argv_sha256"]):
        raise JsonInputError("run record command hash is invalid")
    keys = ("cgroup_device", "cgroup_inode", "created_monotonic_ns", "cpu_quota_percent", "max_memory_mib", "operator_uid", "workload_gid", "workload_uid", "max_pids", "argv_count")
    if any(isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0 for key in keys):
        raise JsonInputError("run record integer field is invalid")
    if value["state"] not in ACTIVE_STATES | TERMINAL_STATES:
        raise JsonInputError("run record state is invalid")
    return value


def identity_from_run(value: dict[str, Any]) -> CgroupIdentity:
    record = validate_run(value)
    return CgroupIdentity(record["boot_id"], record["cgroup"], record["cgroup_device"], record["cgroup_inode"], record["run_id"], record["unit"])


def load_run(runs: Path, run_id: str) -> dict[str, Any]:
    return validate_run(load_regular_json(run_path(runs, run_id)))


def make_receipt(
    *, record: dict[str, Any], trigger: str, trigger_ns: int, kill_started_ns: int, kill_complete_ns: int,
    empty_ns: int, proof: EmptyProof, version: str, source_commit: str, event_id: str,
) -> dict[str, Any]:
    if trigger not in {"OPERATOR", "PID_LIMIT", "SUPERVISOR_FAILURE", "SUPERVISOR_RESTART_FAIL_CLOSED"} or not RUN_ID.fullmatch(event_id):
        raise JsonInputError("receipt trigger or event identity is invalid")
    if not proof.complete or proof.root_populated != 0 or proof.surviving_pids:
        raise JsonInputError("cannot issue a success receipt before exact emptiness proof")
    return {
        "cleanup": {"attempted": False},
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
