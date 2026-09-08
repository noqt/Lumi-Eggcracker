"""Read-only, fixed-cardinality doctor metrics for a trusted textfile directory."""

from __future__ import annotations

import argparse
import math
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

from .client import doctor_strict
from .jsonio import JsonInputError

MARKER = "# lumi-eggcracker monitoring v1; collector-owned\n"
MAX_OUTPUT = 8192
HELP = {
    "query_valid": "Whether the latest doctor query supplied valid selected health fields.",
    "collection_timestamp_seconds": "Unix time of the latest collection attempt, not a sample timestamp.",
    "reported_ready": "Supervisor-reported autonomous discovery readiness, not containment assurance.",
    "discovery_healthy": "Supervisor-reported discovery health.",
    "receipt_storage_healthy": "Supervisor-reported receipt persistence health.",
    "installation_healthy": "Whether the supervisor reports installation state HEALTHY.",
}


def selected_health(value: dict) -> dict[str, int]:
    """Ignore rich nonselected data; missing or malformed health is unavailable."""
    try:
        ready = value["autonomous_discovery"]
        discovery = value["discovery"]["healthy"]
        receipts = value["discovery"]["receipt_persistence_healthy"]
        installation = value["installation"]["state"]
    except (KeyError, TypeError) as error:
        raise ValueError("unavailable health") from error
    if any(type(item) is not bool for item in (ready, discovery, receipts)):
        raise ValueError("invalid health")
    if installation not in ("HEALTHY", "DRIFT", "RECOVERY_REQUIRED", "NOT_INSTALLED"):
        raise ValueError("unknown installation state")
    return {
        "reported_ready": int(ready),
        "discovery_healthy": int(discovery),
        "receipt_storage_healthy": int(receipts),
        "installation_healthy": int(installation == "HEALTHY"),
    }


def render_metrics(health: dict[str, int] | None, now: float) -> str:
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        raise ValueError("invalid clock")
    metrics = {"query_valid": int(health is not None), "collection_timestamp_seconds": now}
    if health is not None:
        metrics.update(health)
    lines = [MARKER.rstrip()]
    for key, value in metrics.items():
        name = "eggcracker_" + key
        lines.extend((f"# HELP {name} {HELP[key]}", f"# TYPE {name} gauge", f"{name} {value}"))
    return "\n".join(lines) + "\n"


def _unsafe(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def validate_path(output: Path) -> None:
    if not output.is_absolute() or output.suffix != ".prom" or ".." in output.parts:
        raise ValueError("output must be an absolute .prom path")
    for parent in (output.parent, *output.parent.parents):
        info = parent.lstat()
        if _unsafe(info) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("unsafe parent")
        if os.name == "posix":
            if info.st_uid not in (0, os.geteuid()):
                raise ValueError("untrusted parent owner")
            # System sticky temporary ancestors are permitted, never the output parent.
            if info.st_mode & 0o022 and not (parent != output.parent and info.st_mode & stat.S_ISVTX):
                raise ValueError("writable parent")
    try:
        info = output.lstat()
    except FileNotFoundError:
        return
    if _unsafe(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("unsafe output")
    if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError("unowned output")
    if info.st_size > MAX_OUTPUT or not output.read_bytes().startswith(MARKER.encode()):
        raise ValueError("unrelated output")


def collect(output: Path) -> bool:
    """Lock before querying; publish invalid telemetry when the query fails."""
    validate_path(output)
    lock = output.with_name(output.name + ".lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    temporary = None
    try:
        os.close(descriptor)
        try:
            health = selected_health(doctor_strict())
        except (OSError, JsonInputError, ValueError, TypeError):
            health = None
        payload = render_metrics(health, time.time())
        descriptor, name = tempfile.mkstemp(prefix=".eggcracker-", suffix=".tmp", dir=output.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        validate_path(output)
        os.replace(temporary, output)
        temporary = None
        return health is not None
    finally:
        if temporary is not None:
            temporary.unlink()
        lock.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        valid = collect(args.output)
    except (OSError, ValueError):
        print("Monitoring output operation failed; check output freshness.", file=sys.stderr)
        return 2
    if not valid:
        print("Doctor query unavailable; query-invalid metrics published.", file=sys.stderr)
        return 1
    return 0
