"""Create a small, local-only support bundle without copying private evidence."""

from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import signal
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
    return {
        "result": _token(value.get("result")),
        "backend": _token(value.get("backend")),
        "version": _token(value.get("version")),
        "workload_uid": value.get("workload_uid"),
        "autonomous_discovery": value.get("autonomous_discovery"),
        "cgroup_v2": value.get("cgroup_v2"),
        "pidfd": value.get("pidfd"),
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
    return {
        "event_id": _token(value.get("event_id")),
        "result": _token(value.get("result")),
        "trigger": _token(trigger),
        "version": _token(value.get("version")),
        "profile": _token(detector.get("profile")),
    }


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


def collect(query: Query = request) -> dict[str, Any]:
    """Collect only bounded fields from public read-only supervisor queries."""
    doctor = query("doctor")
    detections_raw = query("detections")
    list_raw = query("list")
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
        "receipts": [_detection(item) for item in detections[:MAX_DETECTIONS] if isinstance(item, dict)],
        "privacy": {
            "network": "none",
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
