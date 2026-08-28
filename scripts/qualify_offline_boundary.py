#!/usr/bin/env python3
"""Qualify the 0.6.0 offline boundary primitive on disposable native Linux.

This harness is intentionally independent of the supervisor state machine.  It
creates one exact namespace pair, exercises loopback and synthetic IPv4/IPv6
egress, and records only bounded counters and before/after host digests.  It
must be run as root on the disposable qualification VM; a Windows or WSL run
is not evidence for the release gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lumi_eggcracker import __version__
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.offline_boundary import OfflineBoundary

SCHEMA = "lumi-eggcracker.offline-boundary-primitive.v1"
ATTEMPTS = 100
MAX_CAPTURE = 128 * 1024


def run(argv: list[str], *, input_text: str | None = None, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise JsonInputError("primitive command failed") from error
    if len(result.stdout) > MAX_CAPTURE or len(result.stderr) > MAX_CAPTURE:
        raise JsonInputError("primitive command output is too large")
    return result


def require(argv: list[str], *, input_text: str | None = None, timeout: float = 10.0) -> str:
    result = run(argv, input_text=input_text, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[:200]
        raise JsonInputError(detail or "primitive command returned an error")
    return result.stdout


def canonical_digest(raw: str) -> str:
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        value = raw
    if isinstance(value, (dict, list)):
        value = _strip_volatile(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_volatile(item)
            for key, item in value.items()
            if key not in {"expires", "lastuse"}
        }
    if isinstance(value, list):
        return [_strip_volatile(item) for item in value]
    return value


def host_snapshot() -> dict[str, str]:
    """Return hashes only; raw host routes/interfaces never enter evidence."""
    values: dict[str, str] = {}
    for name, argv in (
        ("links", ["/usr/sbin/ip", "-j", "link", "show"]),
        ("routes4", ["/usr/sbin/ip", "-j", "-4", "route", "show"]),
        ("routes6", ["/usr/sbin/ip", "-j", "-6", "route", "show"]),
        ("ruleset", ["/usr/sbin/nft", "-j", "list", "ruleset"]),
    ):
        result = run(argv)
        if result.returncode and name == "ruleset" and "no such file" in result.stderr.lower():
            raw = ""
        elif result.returncode:
            raise JsonInputError(f"host {name} snapshot failed")
        else:
            raw = result.stdout
        values[name] = canonical_digest(raw)
    for name, path in (
        ("ipv4_forwarding", Path("/proc/sys/net/ipv4/ip_forward")),
        ("ipv6_forwarding", Path("/proc/sys/net/ipv6/conf/all/forwarding")),
    ):
        try:
            values[name] = canonical_digest(path.read_text(encoding="ascii"))
        except OSError as error:
            raise JsonInputError(f"host {name} snapshot failed") from error
    return values


def endpoint_counters(namespace: str, interface: str) -> tuple[int, int]:
    raw = require(["/usr/sbin/ip", "-j", "-s", "-n", namespace, "link", "show", interface])
    try:
        values = json.loads(raw)
        item = values[0]
        stats = item["stats64"]["rx"]
        return int(stats["packets"]), int(stats["bytes"])
    except (TypeError, ValueError, KeyError, IndexError, json.JSONDecodeError) as error:
        raise JsonInputError("veth counter output is invalid") from error


def loopback_probe(namespace: str) -> bool:
    code = """
import socket
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.bind(('127.0.0.1', 0)); tcp.listen(1)
port = tcp.getsockname()[1]
client = socket.create_connection(('127.0.0.1', port), timeout=1)
server, _ = tcp.accept(); client.sendall(b'ok'); server.recv(2)
client.close(); server.close(); tcp.close()
udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp.bind(('::1', 0)); udp.sendto(b'ok', ('::1', udp.getsockname()[1])); udp.close()
"""
    result = run(
        [
            "/usr/sbin/ip",
            "netns",
            "exec",
            namespace,
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            code,
        ],
        timeout=10.0,
    )
    return result.returncode == 0


def blocked_probe(namespace: str) -> dict[str, bool]:
    code = f"""
import socket
attempts = {ATTEMPTS}
def tcp(family, address):
    for _ in range(attempts):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(0.01)
        try: s.connect((address, 9))
        except OSError: pass
        finally: s.close()
def udp(family, address):
    for _ in range(attempts):
        s = socket.socket(family, socket.SOCK_DGRAM)
        try: s.sendto(b'x', (address, 9))
        except OSError: pass
        finally: s.close()
tcp(socket.AF_INET, '192.0.2.1')
udp(socket.AF_INET, '192.0.2.1')
tcp(socket.AF_INET6, '2001:db8::1')
udp(socket.AF_INET6, '2001:db8::1')
"""
    result = run(
        ["/usr/sbin/ip", "netns", "exec", namespace, "/usr/bin/python3", "-I", "-S", "-c", code],
        timeout=20.0,
    )
    if result.returncode:
        raise JsonInputError("blocked traffic probe failed")
    return {"ipv4_tcp": True, "ipv4_udp": True, "ipv6_tcp": True, "ipv6_udp": True}


def hostile_probe(namespace: str, table: str, interface: str) -> dict[str, bool]:
    """Exercise the unprivileged namespace identity, not root-in-netns."""
    code = f"""
import subprocess
checks = {{
  'nft': subprocess.run(['/usr/sbin/nft', 'flush', 'table', 'inet', {table!r}], capture_output=True).returncode != 0,
  'link': subprocess.run(['/usr/sbin/ip', 'link', 'set', {interface!r}, 'down'], capture_output=True).returncode != 0,
  'namespace': subprocess.run(['/usr/bin/unshare', '-n', 'true'], capture_output=True).returncode != 0,
}}
print(checks)
assert all(checks.values())
"""
    result = run(
        [
            "/usr/sbin/ip",
            "netns",
            "exec",
            namespace,
            "/usr/sbin/runuser",
            "-u",
            "nobody",
            "--",
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            code,
        ],
        timeout=10.0,
    )
    if result.returncode:
        raise JsonInputError("unprivileged boundary modification probe failed")
    return {"nft": True, "link": True, "namespace": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="qualify the native 0.6.0 offline boundary primitive")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("native primitive qualification requires root Linux")
    if args.output.exists() or not args.output.parent.is_dir():
        raise SystemExit("output must be a new file under an existing directory")
    run_id = secrets.token_hex(12)
    before = host_snapshot()
    boundary: OfflineBoundary | None = None
    result: dict[str, Any] = {
        "schema_version": SCHEMA,
        "version": __version__,
        "run_id": run_id,
        "attempts_per_family": ATTEMPTS,
    }
    try:
        boundary = OfflineBoundary.create(run_id)
        identity = boundary.identity
        canary = subprocess.Popen(["/bin/sleep", "5"], close_fds=True)
        sink_before = endpoint_counters(identity.sink_namespace, identity.sink_interface)
        try:
            result["loopback_allowed"] = loopback_probe(identity.workload_namespace)
            blocked_probe(identity.workload_namespace)
            time.sleep(0.1)
            counter = boundary.counter()
            sink_after = endpoint_counters(identity.sink_namespace, identity.sink_interface)
            result["blocked_counter"] = {"packets": counter.packets, "bytes": counter.bytes}
            result["blocked_counter_increased"] = counter.packets >= 4 * ATTEMPTS
            result["sink_rx_unchanged"] = sink_before == sink_after
            result["same_host_canary_survived"] = canary.poll() is None
            result["hostile_unprivileged"] = hostile_probe(
                identity.workload_namespace, identity.table, identity.workload_interface
            )
            result["identity"] = {
                "mode": "offline",
                "workload_namespace": identity.workload_namespace,
                "sink_namespace": identity.sink_namespace,
                "workload_interface": identity.workload_interface,
                "sink_interface": identity.sink_interface,
                "policy_sha256": identity.policy_sha256,
            }
        finally:
            if canary.poll() is None:
                canary.terminate()
                canary.wait(timeout=2)
    finally:
        if boundary is not None:
            result["teardown"] = boundary.teardown()
    result["host_before"] = before
    result["host_after"] = host_snapshot()
    result["host_unchanged"] = result["host_before"] == result["host_after"]
    result["result"] = "PASS" if all(
        result.get(key) is True
        for key in (
            "loopback_allowed",
            "blocked_counter_increased",
            "sink_rx_unchanged",
            "same_host_canary_survived",
            "host_unchanged",
        )
    ) and result.get("teardown", {}).get("removed") == 2 else "FAIL"
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": result["result"], "output": str(args.output)}, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
