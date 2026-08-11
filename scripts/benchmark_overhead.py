"""Measure bounded supervisor discovery overhead on a disposable Linux host.

This benchmark exercises the same discovery and deep-inspection path used by
the supervisor.  It creates ordinary sleeping children only; run it as root
in a disposable qualification environment because the supervisor policy may
containment-match other local workloads while it scans.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import sys
import time
from pathlib import Path
from typing import Any

from lumi_eggcracker.supervisor import Supervisor


def _percentile(values: list[float], percent: int) -> float:
    ordered = sorted(values)
    return ordered[max(0, (len(ordered) * percent + 99) // 100 - 1)]


def _proc_metrics() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            key, _, raw = line.partition(":")
            if key in {"VmRSS", "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}:
                value = raw.strip().split()[0]
                if value.isdigit():
                    values[key] = int(value)
        for line in Path("/proc/self/io").read_text(encoding="ascii").splitlines():
            key, _, raw = line.partition(":")
            if key in {"read_bytes", "rchar"} and raw.strip().isdigit():
                values[key] = int(raw.strip())
    except OSError as error:
        raise RuntimeError(f"cannot read benchmark process metrics: {error}") from error
    usage = resource.getrusage(resource.RUSAGE_SELF)
    values["cpu_time_us"] = int((usage.ru_utime + usage.ru_stime) * 1_000_000)
    return values


def _spawn_children(count: int) -> list[int]:
    children: list[int] = []
    for _ in range(count):
        pid = os.fork()
        if pid == 0:
            time.sleep(120)
            os._exit(0)
        children.append(pid)
    return children


def _reap(children: list[int]) -> None:
    for pid in children:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def _measure(supervisor: Supervisor, count: int, repetitions: int) -> dict[str, Any]:
    children = _spawn_children(count)
    try:
        # Prime inode-keyed caches before collecting the measured samples.
        supervisor._scan_once(synchronous=True)
        samples: list[dict[str, Any]] = []
        for _ in range(repetitions):
            before = _proc_metrics()
            started = time.perf_counter_ns()
            supervisor._scan_once(synchronous=True)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            after = _proc_metrics()
            samples.append(
                {
                    "duration_ms": elapsed_ms,
                    "cpu_time_us_delta": after["cpu_time_us"] - before["cpu_time_us"],
                    "read_bytes_delta": after.get("read_bytes", 0) - before.get("read_bytes", 0),
                    "rchar_delta": after.get("rchar", 0) - before.get("rchar", 0),
                    "rss_kib": after.get("VmRSS", 0),
                    "context_switches_delta": (
                        after.get("voluntary_ctxt_switches", 0)
                        + after.get("nonvoluntary_ctxt_switches", 0)
                        - before.get("voluntary_ctxt_switches", 0)
                        - before.get("nonvoluntary_ctxt_switches", 0)
                    ),
                }
            )
        durations = [float(item["duration_ms"]) for item in samples]
        host_processes = sum(1 for item in Path("/proc").iterdir() if item.name.isdigit())
        return {
            "synthetic_children": count,
            "host_processes_observed": host_processes,
            "samples": samples,
            "summary": {
                "duration_ms_p50": _percentile(durations, 50),
                "duration_ms_p95": _percentile(durations, 95),
                "duration_ms_max": max(durations),
                "cpu_time_us_p95": _percentile(
                    [float(item["cpu_time_us_delta"]) for item in samples], 95
                ),
                "read_bytes_p95": _percentile(
                    [float(item["read_bytes_delta"]) for item in samples], 95
                ),
                "rchar_p95": _percentile(
                    [float(item["rchar_delta"]) for item in samples], 95
                ),
                "rss_kib_max": max(int(item["rss_kib"]) for item in samples),
                "context_switches_p95": _percentile(
                    [float(item["context_switches_delta"]) for item in samples], 95
                ),
            },
            "cache_entries": {
                "artifacts": len(supervisor.artifact_cache),
                "runtime": len(supervisor.runtime_cache),
            },
        }
    finally:
        _reap(children)


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("overhead benchmark must run as root on Linux")
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    if args.repetitions < 3 or args.repetitions > 20:
        raise SystemExit("repetitions must be between 3 and 20")
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    supervisor = Supervisor(args.policy)
    measurements = [_measure(supervisor, count, args.repetitions) for count in (50, 200, 1000)]
    value = {
        "schema_version": "lumi-eggcracker-overhead.v1",
        "result": "PASS",
        "source_commit": supervisor.policy["source_commit"],
        "version": supervisor.policy["version"],
        "python": sys.version,
        "platform": platform.platform(),
        "measurements": measurements,
        "interpretation": "Discovery and deep inspection only; no model workload is created.",
    }
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"result": "PASS", "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
