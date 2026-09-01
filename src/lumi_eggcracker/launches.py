"""Root-owned provenance for an exact command admitted before exec."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .containment import CgroupIdentity, validate_identity
from .discovery import ProcessIdentity, ProcessSnapshot
from .jsonio import JsonInputError, load_regular_json
from .records import RUN_ID, write_atomic

SCHEMA = "lumi-eggcracker.launch-provenance.v3"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def provenance_path(root: Path, run_id: str) -> Path:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise JsonInputError("launch provenance run identity is invalid")
    return root / f"{run_id}.json"


def validate(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "approval_created_monotonic_ns",
        "approval_name",
        "argv_count",
        "argv_sha256",
        "bound_input_sha256",
        "boot_id",
        "cgroup",
        "cgroup_device",
        "cgroup_inode",
        "executable",
        "executable_device",
        "executable_inode",
        "executable_sha256",
        "launch_kind",
        "pid",
        "run_id",
        "schema_version",
        "start_time",
        "uid",
    }
    if set(value) != expected or value.get("schema_version") != SCHEMA:
        raise JsonInputError("launch provenance schema is invalid")
    if not isinstance(value["run_id"], str) or not RUN_ID.fullmatch(value["run_id"]):
        raise JsonInputError("launch provenance run identity is invalid")
    if not isinstance(value["approval_name"], str) or not value["approval_name"]:
        raise JsonInputError("launch provenance approval name is invalid")
    if not isinstance(value["executable"], str) or not value["executable"].startswith("/"):
        raise JsonInputError("launch provenance executable is invalid")
    if not isinstance(value["cgroup"], str) or not value["cgroup"].startswith(
        "/system.slice/lumi-eggcracker-workload-"
    ):
        raise JsonInputError("launch provenance cgroup is invalid")
    if not isinstance(value["boot_id"], str) or not value["boot_id"]:
        raise JsonInputError("launch provenance boot identity is invalid")
    for key in ("argv_sha256", "executable_sha256"):
        if not isinstance(value[key], str) or not SHA256.fullmatch(value[key]):
            raise JsonInputError("launch provenance digest is invalid")
    if value["launch_kind"] not in {"NATIVE_LLAMA", "PYTHON_SCRIPT"}:
        raise JsonInputError("launch provenance kind is invalid")
    bound = value["bound_input_sha256"]
    if not isinstance(bound, list) or any(
        not isinstance(item, str) or not SHA256.fullmatch(item) for item in bound
    ):
        raise JsonInputError("launch provenance bound input is invalid")
    if not bound:
        raise JsonInputError("launch provenance requires bound material")
    integers = (
        "approval_created_monotonic_ns",
        "argv_count",
        "cgroup_device",
        "cgroup_inode",
        "executable_device",
        "executable_inode",
        "pid",
        "start_time",
        "uid",
    )
    if any(
        isinstance(value[key], bool)
        or not isinstance(value[key], int)
        or value[key] < 1
        for key in integers
    ):
        raise JsonInputError("launch provenance integer is invalid")
    return value


def create(
    root: Path,
    *,
    run: dict[str, Any],
    process: ProcessIdentity,
    approval: dict[str, Any],
) -> dict[str, Any]:
    value = validate(
        {
            "approval_created_monotonic_ns": approval["created_monotonic_ns"],
            "approval_name": approval["name"],
            "argv_count": approval["argv_count"],
            "argv_sha256": approval["argv_sha256"],
            "bound_input_sha256": [
                item["sha256"] for item in approval["bound_inputs"]
            ],
            "boot_id": run["boot_id"],
            "cgroup": run["cgroup"],
            "cgroup_device": run["cgroup_device"],
            "cgroup_inode": run["cgroup_inode"],
            "executable": approval["executable"],
            "executable_device": approval["executable_device"],
            "executable_inode": approval["executable_inode"],
            "executable_sha256": approval["executable_sha256"],
            "launch_kind": approval["launch_kind"],
            "pid": process.pid,
            "run_id": run["run_id"],
            "schema_version": SCHEMA,
            "start_time": process.start_time,
            "uid": approval["uid"],
        }
    )
    write_atomic(provenance_path(root, run["run_id"]), value)
    return value


def load_all(root: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    if not root.exists():
        return values
    for path in sorted(root.glob("*.json")):
        value = validate(load_regular_json(path))
        if value["run_id"] != path.stem:
            raise JsonInputError("launch provenance name/path mismatch")
        values.append(value)
    return values


def approval_is_active(
    provenance: dict[str, Any], approvals: list[dict[str, Any]]
) -> bool:
    """Require the exact root approval generation that admitted a launch.

    Launch provenance proves what root admitted before exec; it is not a
    perpetual approval.  Once root revokes that exact approval record, a
    still-running AI workload must become an autonomous enforcement target.
    A same-named replacement approval cannot revive the old launch.
    """
    validate(provenance)
    matches = []
    for approval in approvals:
        try:
            bound_input_sha256 = [
                item["sha256"] for item in approval["bound_inputs"]
            ]
            matches.append(
                approval["name"] == provenance["approval_name"]
                and approval["created_monotonic_ns"]
                == provenance["approval_created_monotonic_ns"]
                and approval["argv_count"] == provenance["argv_count"]
                and approval["argv_sha256"] == provenance["argv_sha256"]
                and bound_input_sha256 == provenance["bound_input_sha256"]
                and approval["executable"] == provenance["executable"]
                and approval["executable_device"]
                == provenance["executable_device"]
                and approval["executable_inode"]
                == provenance["executable_inode"]
                and approval["executable_sha256"]
                == provenance["executable_sha256"]
                and approval["launch_kind"] == provenance["launch_kind"]
                and approval["uid"] == provenance["uid"]
            )
        except (KeyError, TypeError):
            return False
    return matches.count(True) == 1


def authorizes(
    snapshot: ProcessSnapshot,
    executable_sha256: str,
    executable_metadata: tuple[int, int] | None,
    provenance: dict[str, Any],
) -> bool:
    """Authorize only the exact PID/start-time admitted through the gate."""
    if executable_metadata is None:
        return False
    try:
        validate_identity(
            CgroupIdentity(
                provenance["boot_id"],
                provenance["cgroup"],
                provenance["cgroup_device"],
                provenance["cgroup_inode"],
                provenance["run_id"],
                f"lumi-eggcracker-workload-{provenance['run_id']}.service",
            )
        )
    except (JsonInputError, OSError):
        return False
    return (
        snapshot.identity == ProcessIdentity(provenance["pid"], provenance["start_time"])
        and snapshot.uid == provenance["uid"]
        and snapshot.exe_path.removesuffix(" (deleted)") == provenance["executable"]
        and executable_metadata
        == (provenance["executable_device"], provenance["executable_inode"])
        and executable_sha256 == provenance["executable_sha256"]
        and any(
            line == f"0::{provenance['cgroup']}" for line in snapshot.cgroups
        )
    )
