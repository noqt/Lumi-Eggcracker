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
from .offline_boundary import BoundaryIdentity

RUN_SCHEMA = "lumi-eggcracker.run.v5"
RECEIPT_SCHEMA = "lumi-eggcracker.receipt.v3"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
ACTIVE_STATES = {"STARTING", "RUNNING"}
TERMINAL_STATES = {"COMPLETED_ALLOWED", "TERMINATED", "CONTAINMENT_FAILED", "CONTAINED_RECEIPT_FAILED"}
RECEIPT_TRIGGERS = {"OPERATOR", "PID_LIMIT", "SUPERVISOR_FAILURE", "SUPERVISOR_RESTART_FAIL_CLOSED", "NETWORK_BOUNDARY", "EXECUTION_BOUNDARY"}


def write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    closed = False
    directory = -1
    published = False
    new_target = not path.exists() and not path.is_symlink()
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        pending = memoryview(canonical_bytes(value))
        while pending:
            written = os.write(descriptor, pending)
            if written < 1:
                raise OSError("atomic record write made no progress")
            pending = pending[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        closed = True
        if not hasattr(os, "fchmod"):
            os.chmod(temporary, 0o600)
        try:
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
        except OSError:
            if os.name != "nt":
                raise
        os.replace(temporary, path)
        published = True
        if directory >= 0:
            os.fsync(directory)
    except BaseException:
        if not closed:
            os.close(descriptor)
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        # Receipt paths are new event identities.  If the final directory
        # durability barrier fails, remove that newly published success
        # record before reporting failure so no caller can mistake it for a
        # durable containment receipt.
        if published and new_target and path.exists() and not path.is_symlink():
            path.unlink()
            if directory >= 0:
                try:
                    os.fsync(directory)
                except OSError:
                    pass
        raise
    finally:
        if directory >= 0:
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
        "argv_count",
        "argv_sha256",
        "boot_id",
        "boundary",
        "cgroup",
        "cgroup_device",
        "cgroup_inode",
        "created_monotonic_ns",
        "cpu_quota_percent",
        "exec_policy_digest",
        "exec_policy_id",
        "executable",
        "max_memory_mib",
        "max_pids",
        "name",
        "network_mode",
        "operator_uid",
        "run_id",
        "schema_version",
        "state",
        "unit",
        "workload_gid",
        "workload_uid",
    }
    legacy_expected = expected - {"exec_policy_digest", "exec_policy_id"}
    if set(value) not in (expected, legacy_expected) or value.get("schema_version") not in {RUN_SCHEMA, "lumi-eggcracker.run.v4"}:
        raise JsonInputError("run record schema is invalid")
    if set(value) == legacy_expected:
        # A 0.7 terminal record may still be present when the supervisor is
        # upgraded in place.  It is never an active 0.8 sealed run, but it is
        # retained as bounded historical state so recovery and diagnostics do
        # not become a destructive migration step.
        value = dict(value)
        value["exec_policy_id"] = "legacy"
        value["exec_policy_digest"] = "0" * 64
        value["schema_version"] = RUN_SCHEMA
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
    if not isinstance(value["exec_policy_id"], str) or not value["exec_policy_id"]:
        raise JsonInputError("run record execution policy identity is invalid")
    if not isinstance(value["exec_policy_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["exec_policy_digest"]):
        raise JsonInputError("run record execution policy digest is invalid")
    keys = ("cgroup_device", "cgroup_inode", "created_monotonic_ns", "cpu_quota_percent", "max_memory_mib", "operator_uid", "workload_gid", "workload_uid", "max_pids", "argv_count")
    if any(isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 0 for key in keys):
        raise JsonInputError("run record integer field is invalid")
    if value["state"] not in ACTIVE_STATES | TERMINAL_STATES:
        raise JsonInputError("run record state is invalid")
    if value["network_mode"] not in {"offline", "none"}:
        raise JsonInputError("run record network mode is invalid")
    boundary = value["boundary"]
    if boundary is not None:
        parsed = BoundaryIdentity.from_record(boundary)
        if parsed.run_id != value["run_id"]:
            raise JsonInputError("run record boundary identity does not match run")
        if value["network_mode"] != "offline":
            raise JsonInputError("run record boundary requires offline mode")
    elif value["network_mode"] != "none":
        raise JsonInputError("run record network mode requires a boundary")
    return value


def identity_from_run(value: dict[str, Any]) -> CgroupIdentity:
    record = validate_run(value)
    return CgroupIdentity(record["boot_id"], record["cgroup"], record["cgroup_device"], record["cgroup_inode"], record["run_id"], record["unit"])


def load_run(runs: Path, run_id: str) -> dict[str, Any]:
    return validate_run(load_regular_json(run_path(runs, run_id)))


def make_receipt(
    *, record: dict[str, Any], trigger: str, trigger_ns: int, kill_started_ns: int, kill_complete_ns: int,
    empty_ns: int, proof: EmptyProof, version: str, source_commit: str, event_id: str,
    boundary: dict[str, str] | None = None,
    execution_boundary: dict[str, str] | None = None,
) -> dict[str, Any]:
    if trigger not in RECEIPT_TRIGGERS or not RUN_ID.fullmatch(event_id):
        raise JsonInputError("receipt trigger or event identity is invalid")
    if not proof.complete or proof.root_populated != 0 or proof.surviving_pids:
        raise JsonInputError("cannot issue a success receipt before exact emptiness proof")
    if trigger == "NETWORK_BOUNDARY":
        expected_boundary = {"address_family", "mode", "policy_sha256", "violation"}
        if not isinstance(boundary, dict) or set(boundary) != expected_boundary:
            raise JsonInputError("network boundary receipt metadata is invalid")
        if boundary.get("mode") != "offline" or boundary.get("violation") != "NON_LOOPBACK_EGRESS":
            raise JsonInputError("network boundary receipt metadata is invalid")
        if boundary.get("address_family") not in {"INET", "INET6", "UNSPECIFIED"} or not isinstance(boundary.get("policy_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", boundary["policy_sha256"]):
            raise JsonInputError("network boundary receipt metadata is invalid")
    elif boundary is not None:
        raise JsonInputError("unexpected network boundary receipt metadata")
    if trigger == "EXECUTION_BOUNDARY":
        expected_execution = {"policy_id", "policy_sha256"}
        if not isinstance(execution_boundary, dict) or set(execution_boundary) != expected_execution:
            raise JsonInputError("execution boundary receipt metadata is invalid")
        if not isinstance(execution_boundary["policy_id"], str) or not execution_boundary["policy_id"]:
            raise JsonInputError("execution boundary receipt metadata is invalid")
        if not isinstance(execution_boundary["policy_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", execution_boundary["policy_sha256"]):
            raise JsonInputError("execution boundary receipt metadata is invalid")
    elif execution_boundary is not None:
        raise JsonInputError("unexpected execution boundary receipt metadata")
    receipt = {
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
    if boundary is not None:
        receipt["boundary"] = boundary
    if execution_boundary is not None:
        receipt["execution_boundary"] = execution_boundary
    return receipt
