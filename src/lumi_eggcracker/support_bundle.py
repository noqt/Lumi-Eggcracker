"""Create a small, local-only support bundle without copying private evidence."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import platform
import re
import signal
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__
from .client import request
from .jsonio import JsonInputError, write_new_json

Query = Callable[..., dict[str, Any]]
MAX_DETECTIONS = 100
TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SUPPORT_BUNDLE_SCHEMA = "lumi-eggcracker.support-bundle.v1"
MAX_VALIDATION_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_AGGREGATE_COUNT = 1_000_000_000
MAX_STATE_KEYS = 4096


def _token(value: object) -> str | None:
    return value if isinstance(value, str) and TOKEN.fullmatch(value) else None


def _systemd_version() -> str | None:
    try:
        result = subprocess.run(
            ["/usr/bin/systemd-run", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    line = (result.stdout or "").splitlines()
    return line[0][:80] if result.returncode == 0 and line else None


def _host() -> dict[str, Any]:
    controllers: list[str] = []
    try:
        controllers = sorted(
            value
            for value in Path("/sys/fs/cgroup/cgroup.controllers")
            .read_text(encoding="ascii")
            .split()
            if value in {"cpu", "memory", "pids"}
        )
    except (OSError, UnicodeDecodeError):
        pass
    return {
        "platform": platform.system(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": ".".join(str(value) for value in sys.version_info[:3]),
        "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "controllers": controllers,
        "pidfd_open": hasattr(os, "pidfd_open"),
        "pidfd_send_signal": hasattr(signal, "pidfd_send_signal"),
        "systemd": _systemd_version(),
    }


def _doctor(value: dict[str, Any]) -> dict[str, Any]:
    discovery = value.get("discovery") if isinstance(value.get("discovery"), dict) else {}
    network = value.get("network") if isinstance(value.get("network"), dict) else {}
    primitives = network.get("primitives") if isinstance(network.get("primitives"), dict) else {}
    return {
        "result": _token(value.get("result")),
        "backend": _token(value.get("backend")),
        "version": _token(value.get("version")),
        "workload_uid": value.get("workload_uid"),
        "autonomous_discovery": value.get("autonomous_discovery"),
        "cgroup_v2": value.get("cgroup_v2"),
        "pidfd": value.get("pidfd"),
        "execution_boundary": value.get("execution_boundary"),
        "installation": value.get("installation"),
        "incidents": value.get("incidents"),
        "network": {
            "mode": _token(network.get("mode")),
            "cleanup_healthy": network.get("cleanup_healthy"),
            "primitives_supported": primitives.get("supported"),
        },
        "discovery": {
            "healthy": discovery.get("healthy"),
            "consecutive_failures": discovery.get("consecutive_failures"),
            "last_scan_duration_ms": discovery.get("last_scan_duration_ms"),
            "last_scan_completed": discovery.get("last_scan_completed"),
            "receipt_persistence_healthy": discovery.get("receipt_persistence_healthy"),
        },
    }


def _detection(value: dict[str, Any]) -> dict[str, Any]:
    detector = value.get("detector") if isinstance(value.get("detector"), dict) else {}
    trigger_value = value.get("trigger")
    trigger = trigger_value.get("kind") if isinstance(trigger_value, dict) else trigger_value
    result = {
        "event_id": _token(value.get("event_id")),
        "result": _token(value.get("result")),
        "trigger": _token(trigger),
        "version": _token(value.get("version")),
        "profile": _token(detector.get("profile")),
    }
    boundary = value.get("boundary")
    if isinstance(boundary, dict):
        policy_sha256 = boundary.get("policy_sha256")
        result["boundary"] = {
            "address_family": _token(boundary.get("address_family")),
            "mode": _token(boundary.get("mode")),
            "policy_sha256": (
                policy_sha256
                if isinstance(policy_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", policy_sha256)
                else None
            ),
            "violation": _token(boundary.get("violation")),
        }
    return result


def _workload_health(value: dict[str, Any]) -> dict[str, Any]:
    runs = value.get("runs") if isinstance(value.get("runs"), list) else []
    states: dict[str, int] = {}
    for item in runs:
        if not isinstance(item, dict):
            continue
        state = _token(item.get("state"))
        if state is not None:
            states[state] = states.get(state, 0) + 1
    return {"run_count": len(runs), "states": states}


def _incident_health(value: dict[str, Any]) -> dict[str, Any]:
    incidents = value.get("incidents") if isinstance(value.get("incidents"), list) else []
    active = 0
    states: dict[str, int] = {}
    for item in incidents:
        if not isinstance(item, dict):
            continue
        state = _token(item.get("state"))
        if state is not None:
            states[state] = states.get(state, 0) + 1
            if state in {"ACTIVE", "ACKNOWLEDGED"}:
                active += 1
    return {"count": len(incidents), "active": active, "states": states}


def collect(query: Query = request) -> dict[str, Any]:
    """Collect only bounded fields from public read-only supervisor queries."""
    doctor = query("doctor")
    detections_raw = query("detections")
    list_raw = query("list")
    incidents_raw = query("incidents")
    detections = detections_raw.get("detections")
    if not isinstance(detections, list):
        detections = []
    return {
        "schema_version": "lumi-eggcracker.support-bundle.v1",
        "generated_utc": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        "product": "Lumi Eggcracker",
        "version": _token(doctor.get("version", __version__)) or __version__,
        "host": _host(),
        "health": _doctor(doctor),
        "workloads": _workload_health(list_raw),
        "incidents": _incident_health(incidents_raw),
        "receipts": [_detection(item) for item in detections[:MAX_DETECTIONS] if isinstance(item, dict)],
        "privacy": {
            "network": "aggregate-boundary-events-only",
            "raw_receipts": False,
            "argv": False,
            "paths": False,
            "pids": False,
            "model_data": False,
        },
    }


def write_bundle(destination: Path, query: Query = request) -> dict[str, Any]:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise JsonInputError("support bundle output must be a new file under an existing directory")
    value = collect(query)
    write_new_json(destination, value)
    return value


def main(destination: Path) -> int:
    try:
        write_bundle(destination)
    except (JsonInputError, OSError) as error:
        print(f"eggcracker support-bundle: {error}", file=sys.stderr)
        return 4
    print(json.dumps({"result": "WRITTEN", "path": str(destination)}, sort_keys=True))
    return 0


class _InvalidSupportBundle(ValueError):
    """Internal marker for a support bundle outside the bounded v1 contract."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidSupportBundle
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise _InvalidSupportBundle


def _finite_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise _InvalidSupportBundle
    return result


def _check_json_depth(value: str) -> None:
    depth = 0
    quoted = False
    escaped = False
    for character in value:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _InvalidSupportBundle
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise _InvalidSupportBundle


def _read_bounded_regular_file(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_VALIDATION_BYTES:
            raise _InvalidSupportBundle
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= (
            getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_VALIDATION_BYTES
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise _InvalidSupportBundle
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = bytearray()
            while len(data) <= MAX_VALIDATION_BYTES:
                block = handle.read(min(64 * 1024, MAX_VALIDATION_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > MAX_VALIDATION_BYTES:
                raise _InvalidSupportBundle
            return bytes(data)
    except (OSError, TypeError, ValueError):
        raise _InvalidSupportBundle from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_object(value: object, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _InvalidSupportBundle
    return value


def _require_text(value: object, *, maximum: int = 256) -> None:
    if not isinstance(value, str) or len(value) > maximum:
        raise _InvalidSupportBundle
    try:
        if len(value.encode("utf-8", errors="strict")) > maximum * 4:
            raise _InvalidSupportBundle
    except UnicodeEncodeError:
        raise _InvalidSupportBundle from None


def _require_token(value: object, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if _token(value) is None:
        raise _InvalidSupportBundle


def _require_bool(value: object, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if type(value) is not bool:
        raise _InvalidSupportBundle


def _require_count(value: object, *, nullable: bool = False, maximum: int = MAX_AGGREGATE_COUNT) -> None:
    if nullable and value is None:
        return
    if type(value) is not int or value < 0 or value > maximum:
        raise _InvalidSupportBundle


def _require_finite_number(value: object, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if type(value) is int:
        if value < 0 or value > MAX_AGGREGATE_COUNT:
            raise _InvalidSupportBundle
        return
    if type(value) is not float or not math.isfinite(value) or value < 0:
        raise _InvalidSupportBundle


def _validate_state_counts(value: object, total: int) -> int:
    if not isinstance(value, dict) or len(value) > MAX_STATE_KEYS:
        raise _InvalidSupportBundle
    subtotal = 0
    for state, count in value.items():
        _require_token(state)
        _require_count(count, maximum=total)
        if count == 0:
            raise _InvalidSupportBundle
        subtotal += count
    if subtotal > total:
        raise _InvalidSupportBundle
    return len(value)


def _validate_health(value: object) -> None:
    health = _require_object(
        value,
        {
            "result",
            "backend",
            "version",
            "workload_uid",
            "autonomous_discovery",
            "cgroup_v2",
            "pidfd",
            "execution_boundary",
            "installation",
            "incidents",
            "network",
            "discovery",
        },
    )
    for name in ("result", "backend", "version"):
        _require_token(health[name], nullable=True)
    _require_count(health["workload_uid"], nullable=True, maximum=2**32 - 1)
    for name in ("autonomous_discovery", "cgroup_v2", "pidfd"):
        _require_bool(health[name], nullable=True)

    execution_boundary = health["execution_boundary"]
    if execution_boundary is not None:
        execution = _require_object(
            execution_boundary,
            {"linux", "architecture", "fcntl", "libc", "user_notification", "supported"},
        )
        for fact in execution.values():
            _require_bool(fact)

    installation = health["installation"]
    if installation is not None:
        if not isinstance(installation, dict) or set(installation) not in (
            {"state", "journal", "files_match"},
            {"state", "journal", "files_match", "manifest_version"},
        ):
            raise _InvalidSupportBundle
        _require_token(installation["state"])
        _require_bool(installation["journal"])
        _require_bool(installation["files_match"])
        if "manifest_version" in installation:
            _require_token(installation["manifest_version"])

    incidents = health["incidents"]
    if incidents is not None:
        incident_health = _require_object(
            incidents,
            {"healthy", "count", "active", "lockdown"},
        )
        _require_bool(incident_health["healthy"])
        _require_bool(incident_health["lockdown"])
        _require_count(incident_health["count"])
        _require_count(incident_health["active"], maximum=incident_health["count"])

    network = _require_object(
        health["network"],
        {"mode", "cleanup_healthy", "primitives_supported"},
    )
    _require_token(network["mode"], nullable=True)
    _require_bool(network["cleanup_healthy"], nullable=True)
    _require_bool(network["primitives_supported"], nullable=True)

    discovery = _require_object(
        health["discovery"],
        {
            "healthy",
            "consecutive_failures",
            "last_scan_duration_ms",
            "last_scan_completed",
            "receipt_persistence_healthy",
        },
    )
    _require_bool(discovery["healthy"], nullable=True)
    _require_count(discovery["consecutive_failures"], nullable=True)
    _require_finite_number(discovery["last_scan_duration_ms"], nullable=True)
    _require_bool(discovery["last_scan_completed"], nullable=True)
    _require_bool(discovery["receipt_persistence_healthy"], nullable=True)


def _validate_support_bundle(value: object) -> dict[str, Any]:
    bundle = _require_object(
        value,
        {
            "schema_version",
            "generated_utc",
            "product",
            "version",
            "host",
            "health",
            "workloads",
            "incidents",
            "receipts",
            "privacy",
        },
    )
    if bundle["schema_version"] != SUPPORT_BUNDLE_SCHEMA or bundle["product"] != "Lumi Eggcracker":
        raise _InvalidSupportBundle
    generated = bundle["generated_utc"]
    if (
        not isinstance(generated, str)
        or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", generated)
    ):
        raise _InvalidSupportBundle
    try:
        dt.datetime.fromisoformat(generated)
    except ValueError:
        raise _InvalidSupportBundle from None
    _require_token(bundle["version"])

    host = _require_object(
        bundle["host"],
        {
            "platform",
            "kernel",
            "machine",
            "python",
            "cgroup_v2",
            "controllers",
            "pidfd_open",
            "pidfd_send_signal",
            "systemd",
        },
    )
    for name in ("platform", "kernel", "machine", "python"):
        _require_text(host[name])
    for name in ("cgroup_v2", "pidfd_open", "pidfd_send_signal"):
        _require_bool(host[name])
    controllers = host["controllers"]
    if (
        not isinstance(controllers, list)
        or len(controllers) > 3
        or any(controller not in {"cpu", "memory", "pids"} for controller in controllers)
        or controllers != sorted(set(controllers))
    ):
        raise _InvalidSupportBundle
    if host["systemd"] is not None:
        _require_text(host["systemd"], maximum=80)

    _validate_health(bundle["health"])

    workloads = _require_object(bundle["workloads"], {"run_count", "states"})
    _require_count(workloads["run_count"])
    workload_state_count = _validate_state_counts(workloads["states"], workloads["run_count"])

    incidents = _require_object(bundle["incidents"], {"count", "active", "states"})
    _require_count(incidents["count"])
    _require_count(incidents["active"], maximum=incidents["count"])
    incident_state_count = _validate_state_counts(incidents["states"], incidents["count"])
    active_from_states = sum(
        count for state, count in incidents["states"].items() if state in {"ACTIVE", "ACKNOWLEDGED"}
    )
    if incidents["active"] != active_from_states:
        raise _InvalidSupportBundle

    receipts = bundle["receipts"]
    if not isinstance(receipts, list) or len(receipts) > MAX_DETECTIONS:
        raise _InvalidSupportBundle
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) not in (
            {"event_id", "result", "trigger", "version", "profile"},
            {"event_id", "result", "trigger", "version", "profile", "boundary"},
        ):
            raise _InvalidSupportBundle
        for name in ("event_id", "result", "trigger", "version", "profile"):
            _require_token(receipt[name], nullable=True)
        if "boundary" in receipt:
            boundary = _require_object(
                receipt["boundary"],
                {"address_family", "mode", "policy_sha256", "violation"},
            )
            for name in ("address_family", "mode", "violation"):
                _require_token(boundary[name], nullable=True)
            digest = boundary["policy_sha256"]
            if digest is not None and (
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            ):
                raise _InvalidSupportBundle

    privacy = _require_object(
        bundle["privacy"],
        {"network", "raw_receipts", "argv", "paths", "pids", "model_data"},
    )
    if (
        type(privacy["network"]) is not str
        or privacy["network"] != "aggregate-boundary-events-only"
        or any(
            type(privacy[name]) is not bool or privacy[name] is not False
            for name in ("raw_receipts", "argv", "paths", "pids", "model_data")
        )
    ):
        raise _InvalidSupportBundle

    return {
        "result": "STRUCTURE_VALID",
        "schema_version": SUPPORT_BUNDLE_SCHEMA,
        "receipts": {
            "included": len(receipts),
            "maximum_included": MAX_DETECTIONS,
            "total_represented": False,
        },
        "workloads": {
            "run_count": workloads["run_count"],
            "reported_state_count": workload_state_count,
        },
        "incidents": {
            "count": incidents["count"],
            "active_count": incidents["active"],
            "reported_state_count": incident_state_count,
        },
        "limitations": (
            "Structural validation only; not authentication, privacy assurance, completeness, "
            "containment, or incident truth."
        ),
    }


def validate_bundle(path: Path) -> dict[str, Any]:
    """Validate a bounded v1 support bundle and return only aggregate counts."""
    try:
        content = _read_bounded_regular_file(Path(path))
        text = content.decode("utf-8", errors="strict")
        _check_json_depth(text)
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_finite_json_float,
        )
        return _validate_support_bundle(value)
    except (
        _InvalidSupportBundle,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise JsonInputError("support bundle is invalid or cannot be read") from None


def validate_main(arguments: list[str]) -> int:
    if len(arguments) != 1:
        print(
            "eggcracker validate-support-bundle: expected exactly one FILE argument",
            file=sys.stderr,
        )
        return 4
    try:
        summary = validate_bundle(Path(arguments[0]))
    except JsonInputError:
        print(
            "eggcracker validate-support-bundle: support bundle is invalid or cannot be read",
            file=sys.stderr,
        )
        return 4
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0
