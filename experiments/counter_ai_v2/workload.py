"""Harmless selected-tree workload used by the v2 native demonstration.

It writes only fixed fake data to the supplied local sink and emits a bounded
self-report.  It has no controller, admission-state, observer, network, or
host-share access.  The parent creates one descendant so process-group
observation is meaningful.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover - this workload is Linux-only
    resource = None  # type: ignore[assignment]

MAX_SINK_BYTES = 16 * 1024 * 1024
MAX_CPU_SECONDS = 5
MAX_ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
MAX_PROCESSES = 32


def _write(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.pending")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _child(sink: Path, report: Path, generation: int) -> int:
    _write(report, {"role": "descendant", "pid": os.getpid(), "generation": generation, "state": "RUNNING"})
    while True:
        _append_fake(sink)
        time.sleep(0.05)


def _append_fake(sink: Path) -> None:
    if sink.exists() and sink.stat().st_size >= MAX_SINK_BYTES:
        raise SystemExit("fake sink limit reached")
    with sink.open("a", encoding="utf-8") as stream:
        stream.write("FAKE-DATA-ONLY\n")


def _apply_limits() -> None:
    """Keep the harmless selected tree inside the proposed envelope."""
    if resource is None:
        raise RuntimeError("the harmless workload requires Linux resource limits")
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE_BYTES, MAX_ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SINK_BYTES, MAX_SINK_BYTES))


def _wait_for_gate(path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.is_file() and not path.is_symlink():
            return
        time.sleep(0.01)
    raise RuntimeError("controller launch gate did not open")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("target", "canary", "descendant"), required=True)
    parser.add_argument("--sink", type=Path, required=True)
    parser.add_argument("--self-report", type=Path, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--start-gate", type=Path)
    args = parser.parse_args(argv)
    _apply_limits()
    if args.role == "descendant":
        return _child(args.sink, args.self_report, args.generation)
    if args.start_gate is not None:
        _wait_for_gate(args.start_gate)
    descendant_report = args.self_report.with_name(f"{args.self_report.stem}-descendant.json")
    descendant = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--role",
            "descendant",
            "--sink",
            str(args.sink),
            "--self-report",
            str(descendant_report),
            "--generation",
            str(args.generation),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    _write(
        args.self_report,
        {
            "role": args.role,
            "pid": os.getpid(),
            "descendant_pid": descendant.pid,
            "generation": args.generation,
            "state": "RUNNING",
        },
    )
    try:
        while True:
            _append_fake(args.sink)
            time.sleep(0.05 if args.role == "target" else 0.1)
    finally:
        if descendant.poll() is None:
            descendant.terminate()
        descendant.wait(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
