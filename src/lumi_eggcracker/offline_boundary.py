"""A root-owned, transient offline network boundary for one selected run.

The boundary is intentionally small.  A workload namespace has a veth peer in
an isolated sink namespace and a namespace-local nftables output rule that
counts and drops every non-loopback packet.  The supervisor observes the
bounded counter and uses the existing cgroup kill path when it changes.  The
kernel drop is the enforcement primitive; observation is only the kill trigger.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .jsonio import JsonInputError

RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
IP = Path("/usr/sbin/ip")
NFT = Path("/usr/sbin/nft")
NSENTER = Path("/usr/bin/nsenter")
NETNS_DIR = Path("/run/netns")
WORKLOAD_PREFIX = "lumi-eggcracker-w-"
SINK_PREFIX = "lumi-eggcracker-s-"
TABLE_PREFIX = "lumi_eggcracker_"
COUNTER_NAME = "violation"
CONTROL_COUNTER_NAME = "control"
CONTROL_ICMPV6_TYPES = frozenset(
    {
        "mld-listener-query",
        "mld-listener-report",
        "mld-listener-done",
        "nd-router-solicit",
        "nd-router-advert",
        "nd-neighbor-solicit",
        "nd-neighbor-advert",
        "nd-redirect",
        "mld2-listener-report",
    }
)
OUTPUT_CHAIN = "output"
INPUT_CHAIN = "input"
POLL_INTERVAL_SECONDS = 0.05
HEALTH_INTERVAL_SECONDS = 0.25
WARMUP_TIMEOUT_SECONDS = 5.0
WARMUP_QUIET_SECONDS = 1.5
MAX_COMMAND_OUTPUT = 128 * 1024
MAX_COUNTER = (1 << 63) - 1


@dataclass(frozen=True)
class BoundaryNames:
    run_id: str
    workload_namespace: str
    sink_namespace: str
    workload_interface: str
    sink_interface: str
    table: str
    input_chain: str = INPUT_CHAIN
    output_chain: str = OUTPUT_CHAIN
    counter: str = COUNTER_NAME
    control_counter: str = CONTROL_COUNTER_NAME


@dataclass(frozen=True)
class BoundaryIdentity:
    run_id: str
    workload_namespace: str
    sink_namespace: str
    workload_interface: str
    sink_interface: str
    workload_interface_index: int
    sink_interface_index: int
    table: str
    input_chain: str
    output_chain: str
    counter: str
    control_counter: str
    workload_namespace_device: int
    workload_namespace_inode: int
    sink_namespace_device: int
    sink_namespace_inode: int
    policy_sha256: str

    def as_record(self) -> dict[str, Any]:
        return {
            "control_counter": self.control_counter,
            "counter": self.counter,
            "input_chain": self.input_chain,
            "mode": "offline",
            "output_chain": self.output_chain,
            "policy_sha256": self.policy_sha256,
            "run_id": self.run_id,
            "sink_interface": self.sink_interface,
            "sink_interface_index": self.sink_interface_index,
            "sink_namespace": self.sink_namespace,
            "sink_namespace_device": self.sink_namespace_device,
            "sink_namespace_inode": self.sink_namespace_inode,
            "table": self.table,
            "workload_interface": self.workload_interface,
            "workload_interface_index": self.workload_interface_index,
            "workload_namespace": self.workload_namespace,
            "workload_namespace_device": self.workload_namespace_device,
            "workload_namespace_inode": self.workload_namespace_inode,
        }

    @classmethod
    def from_record(cls, value: object) -> BoundaryIdentity:
        if not isinstance(value, dict):
            raise JsonInputError("offline boundary identity is invalid")
        run_id = value.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise JsonInputError("offline boundary run identity is invalid")
        expected = names(run_id)
        strings = {
            "mode": "offline",
            "workload_namespace": expected.workload_namespace,
            "sink_namespace": expected.sink_namespace,
            "workload_interface": expected.workload_interface,
            "sink_interface": expected.sink_interface,
            "table": expected.table,
            "input_chain": expected.input_chain,
            "output_chain": expected.output_chain,
            "counter": expected.counter,
            "control_counter": expected.control_counter,
        }
        if any(value.get(key) != expected_value for key, expected_value in strings.items()):
            raise JsonInputError("offline boundary object identity is invalid")
        policy_sha256 = value.get("policy_sha256")
        if not isinstance(policy_sha256, str) or not SHA256.fullmatch(policy_sha256):
            raise JsonInputError("offline boundary policy identity is invalid")
        if policy_sha256 != policy_digest(expected.table):
            raise JsonInputError("offline boundary policy identity is invalid")
        integers = (
            "workload_interface_index",
            "sink_interface_index",
            "workload_namespace_device",
            "workload_namespace_inode",
            "sink_namespace_device",
            "sink_namespace_inode",
        )
        if any(
            isinstance(value.get(key), bool)
            or not isinstance(value.get(key), int)
            or value[key] < 1
            for key in integers
        ):
            raise JsonInputError("offline boundary namespace identity is invalid")
        if set(value) != {
            "control_counter",
            "counter",
            "input_chain",
            "mode",
            "output_chain",
            "policy_sha256",
            "run_id",
            "sink_interface",
            "sink_interface_index",
            "sink_namespace",
            "sink_namespace_device",
            "sink_namespace_inode",
            "table",
            "workload_interface",
            "workload_interface_index",
            "workload_namespace",
            "workload_namespace_device",
            "workload_namespace_inode",
        }:
            raise JsonInputError("offline boundary identity fields are invalid")
        return cls(
            run_id=run_id,
            workload_namespace=expected.workload_namespace,
            sink_namespace=expected.sink_namespace,
            workload_interface=expected.workload_interface,
            sink_interface=expected.sink_interface,
            workload_interface_index=value["workload_interface_index"],
            sink_interface_index=value["sink_interface_index"],
            table=expected.table,
            input_chain=expected.input_chain,
            output_chain=expected.output_chain,
            counter=expected.counter,
            control_counter=expected.control_counter,
            workload_namespace_device=value["workload_namespace_device"],
            workload_namespace_inode=value["workload_namespace_inode"],
            sink_namespace_device=value["sink_namespace_device"],
            sink_namespace_inode=value["sink_namespace_inode"],
            policy_sha256=policy_sha256,
        )


@dataclass(frozen=True)
class CounterSnapshot:
    packets: int
    bytes: int


def names(run_id: str) -> BoundaryNames:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise JsonInputError("offline boundary run identity is invalid")
    suffix = run_id[:12]
    return BoundaryNames(
        run_id=run_id,
        workload_namespace=f"{WORKLOAD_PREFIX}{run_id}",
        sink_namespace=f"{SINK_PREFIX}{run_id}",
        workload_interface=f"lew{suffix}",
        sink_interface=f"les{suffix}",
        table=f"{TABLE_PREFIX}{run_id}",
    )


def _command_output(result: subprocess.CompletedProcess[str], action: str) -> str:
    output = (result.stderr or result.stdout or "").strip()
    if len(output) > 256:
        output = output[:256]
    return output or f"{action} failed"


def _run(
    argv: list[str],
    *,
    action: str,
    input_text: str | None = None,
    timeout: float = 5.0,
) -> subprocess.CompletedProcess[str]:
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
        raise JsonInputError(f"offline boundary {action} failed") from error
    if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > MAX_COMMAND_OUTPUT:
        raise JsonInputError(f"offline boundary {action} output is too large")
    return result


def _require(
    argv: list[str],
    *,
    action: str,
    input_text: str | None = None,
    timeout: float = 5.0,
) -> subprocess.CompletedProcess[str]:
    result = _run(argv, action=action, input_text=input_text, timeout=timeout)
    if result.returncode:
        raise JsonInputError(_command_output(result, action))
    return result


def _run_host_mount(argv: list[str], *, action: str) -> subprocess.CompletedProcess[str]:
    """Run one exact netns mount operation in PID 1's mount namespace.

    The supervisor service intentionally keeps its protective read-only mount
    namespace. Bind mounts made by ``ip netns add`` there would be invisible to
    systemd when it later resolves ``NetworkNamespacePath``. Entering only PID
    1's mount namespace for this iproute2 operation keeps the namespace file
    visible to both the supervisor and the service manager.
    """
    return _require(
        [str(NSENTER), "-t", "1", "-m", "--", *argv],
        action=action,
    )


def _netns_path(namespace: str) -> Path:
    if not namespace.startswith((WORKLOAD_PREFIX, SINK_PREFIX)):
        raise JsonInputError("offline boundary namespace is outside the owned prefix")
    return NETNS_DIR / namespace


def _namespace_identity(namespace: str) -> tuple[int, int]:
    path = _netns_path(namespace)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise JsonInputError("offline boundary namespace is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise JsonInputError("offline boundary namespace is not a regular mount")
    return metadata.st_dev, metadata.st_ino


def _namespace_links(namespace: str) -> dict[str, int]:
    result = _require(
        [str(IP), "-j", "-n", namespace, "link", "show"],
        action="link inspection",
    )
    try:
        value = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise JsonInputError("offline boundary link output is invalid") from error
    if not isinstance(value, list) or len(value) > 16:
        raise JsonInputError("offline boundary link output is invalid")
    values: dict[str, int] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("ifname"), str)
            or isinstance(item.get("ifindex"), bool)
            or not isinstance(item.get("ifindex"), int)
            or item["ifindex"] < 1
        ):
            raise JsonInputError("offline boundary link identity is invalid")
        interface = item["ifname"]
        if len(interface) > 15 or interface in values:
            raise JsonInputError("offline boundary link identity is invalid")
        values[interface] = item["ifindex"]
    return values


def _default_route(namespace: str, family: str = "") -> str:
    result = _require(
        [str(IP), "-n", namespace, *([family] if family else []), "route", "show", "default"],
        action="route inspection",
    )
    return result.stdout.strip()


def _nft_program(table: str) -> str:
    # Keep this text fixed.  The run ID is validated before it reaches here.
    return "\n".join(
        (
            f"add table inet {table}",
            f"add counter inet {table} {COUNTER_NAME}",
            f"add counter inet {table} {CONTROL_COUNTER_NAME}",
            f"add chain inet {table} {INPUT_CHAIN} {{ type filter hook input priority 0; policy drop; }}",
            f"add chain inet {table} {OUTPUT_CHAIN} {{ type filter hook output priority 0; policy drop; }}",
            f"add rule inet {table} {INPUT_CHAIN} iifname \"lo\" accept",
            f"add rule inet {table} {OUTPUT_CHAIN} oifname \"lo\" accept",
            f"add rule inet {table} {OUTPUT_CHAIN} ip6 nexthdr icmpv6 icmpv6 type {{ 130, 131, 132, 133, 134, 135, 136, 137, 143 }} counter name {CONTROL_COUNTER_NAME} drop",
            f"add rule inet {table} {OUTPUT_CHAIN} counter name {COUNTER_NAME} drop",
            "",
        )
    )


def policy_digest(table: str) -> str:
    return hashlib.sha256(_nft_program(table).encode("utf-8")).hexdigest()


def primitives_available() -> dict[str, Any]:
    """Return bounded, read-only host prerequisite facts."""
    return {
        "ip": IP.is_file() and os.access(IP, os.X_OK),
        "nft": NFT.is_file() and os.access(NFT, os.X_OK),
        "nsenter": NSENTER.is_file() and os.access(NSENTER, os.X_OK),
        "netns_directory": NETNS_DIR.is_dir() or NETNS_DIR.parent.is_dir(),
        "supported": all(
            path.is_file() and os.access(path, os.X_OK)
            for path in (IP, NFT, NSENTER)
        ),
    }


def _assert_run_owner(run_id: str) -> BoundaryNames:
    value = names(run_id)
    if any(
        path.exists() or path.is_symlink()
        for path in (
            _netns_path(value.workload_namespace),
            _netns_path(value.sink_namespace),
        )
    ):
        raise JsonInputError("offline boundary namespace name is already in use")
    return value


def _delete_namespace(namespace: str) -> None:
    path = _netns_path(namespace)
    if not path.exists() and not path.is_symlink():
        return
    _run_host_mount([str(IP), "netns", "del", namespace], action="namespace teardown")
    if path.exists() or path.is_symlink():
        raise JsonInputError("offline boundary namespace remained after teardown")


class OfflineBoundary:
    """One exact workload/sink namespace pair and its deny counter."""

    def __init__(self, identity: BoundaryIdentity) -> None:
        self.identity = identity

    @property
    def workload_namespace_path(self) -> Path:
        return _netns_path(self.identity.workload_namespace)

    @classmethod
    def create(cls, run_id: str) -> OfflineBoundary:
        if os.geteuid() != 0:
            raise JsonInputError("offline boundary setup requires root")
        value = _assert_run_owner(run_id)
        if not primitives_available()["supported"]:
            raise JsonInputError("iproute2 and nftables are required for offline boundary")
        created: list[str] = []
        try:
            _run_host_mount(
                [str(IP), "netns", "add", value.workload_namespace],
                action="workload namespace setup",
            )
            created.append(value.workload_namespace)
            _run_host_mount(
                [str(IP), "netns", "add", value.sink_namespace],
                action="sink namespace setup",
            )
            created.append(value.sink_namespace)
            _require(
                [str(IP), "link", "add", value.workload_interface, "type", "veth", "peer", "name", value.sink_interface],
                action="veth setup",
            )
            _require(
                [str(IP), "link", "set", value.workload_interface, "netns", value.workload_namespace],
                action="workload veth placement",
            )
            _require(
                [str(IP), "link", "set", value.sink_interface, "netns", value.sink_namespace],
                action="sink veth placement",
            )
            _require([str(IP), "-n", value.workload_namespace, "link", "set", "lo", "up"], action="workload loopback setup")
            _require([str(IP), "-n", value.sink_namespace, "link", "set", "lo", "up"], action="sink loopback setup")
            _require([str(IP), "-n", value.workload_namespace, "link", "set", value.workload_interface, "up"], action="workload veth activation")
            _require([str(IP), "-n", value.sink_namespace, "link", "set", value.sink_interface, "up"], action="sink veth activation")
            _require([str(IP), "-n", value.workload_namespace, "addr", "add", "192.0.2.2/30", "dev", value.workload_interface], action="workload IPv4 setup")
            _require([str(IP), "-n", value.sink_namespace, "addr", "add", "192.0.2.1/30", "dev", value.sink_interface], action="sink IPv4 setup")
            _require([str(IP), "-n", value.workload_namespace, "-6", "addr", "add", "2001:db8::2/126", "dev", value.workload_interface, "nodad"], action="workload IPv6 setup")
            _require([str(IP), "-n", value.sink_namespace, "-6", "addr", "add", "2001:db8::1/126", "dev", value.sink_interface, "nodad"], action="sink IPv6 setup")
            _require([str(IP), "-n", value.workload_namespace, "route", "add", "default", "via", "192.0.2.1", "dev", value.workload_interface], action="workload IPv4 route setup")
            _require([str(IP), "-n", value.workload_namespace, "-6", "route", "add", "default", "via", "2001:db8::1", "dev", value.workload_interface], action="workload IPv6 route setup")
            _require(
                [str(IP), "netns", "exec", value.workload_namespace, str(NFT), "-f", "-"],
                action="namespace deny-rule setup",
                input_text=_nft_program(value.table),
            )
            workload_device, workload_inode = _namespace_identity(value.workload_namespace)
            sink_device, sink_inode = _namespace_identity(value.sink_namespace)
            workload_links = _namespace_links(value.workload_namespace)
            sink_links = _namespace_links(value.sink_namespace)
            if set(workload_links) != {"lo", value.workload_interface} or set(sink_links) != {
                "lo",
                value.sink_interface,
            }:
                raise JsonInputError("offline boundary links are invalid after setup")
            boundary = cls(
                BoundaryIdentity(
                    run_id=run_id,
                    workload_namespace=value.workload_namespace,
                    sink_namespace=value.sink_namespace,
                    workload_interface=value.workload_interface,
                    sink_interface=value.sink_interface,
                    workload_interface_index=workload_links[value.workload_interface],
                    sink_interface_index=sink_links[value.sink_interface],
                    table=value.table,
                    input_chain=value.input_chain,
                    output_chain=value.output_chain,
                    counter=value.counter,
                    control_counter=value.control_counter,
                    workload_namespace_device=workload_device,
                    workload_namespace_inode=workload_inode,
                    sink_namespace_device=sink_device,
                    sink_namespace_inode=sink_inode,
                    policy_sha256=policy_digest(value.table),
                )
            )
            # Namespace construction itself can emit kernel control traffic
            # while the veth and routes settle. Establish the authenticated
            # zero baseline only after the complete topology and ruleset are
            # in place; no selected workload exists at this point.
            boundary.reset_counter()
            return boundary
        except BaseException:
            for namespace in reversed(created):
                try:
                    _delete_namespace(namespace)
                except (JsonInputError, OSError):
                    pass
            # If veth creation failed before either endpoint moved, remove only
            # the exact generated root-side names.
            _run([str(IP), "link", "del", value.workload_interface], action="partial veth teardown")
            raise

    @classmethod
    def from_record(cls, value: object) -> OfflineBoundary:
        return cls(BoundaryIdentity.from_record(value))

    def _assert_namespace_identity(self, namespace: str, device: int, inode: int) -> None:
        current = _namespace_identity(namespace)
        if current != (device, inode):
            raise JsonInputError("offline boundary namespace identity drifted")

    def _table(self) -> dict[str, Any]:
        result = _require(
            [str(IP), "netns", "exec", self.identity.workload_namespace, str(NFT), "-j", "list", "table", "inet", self.identity.table],
            action="deny-rule inspection",
        )
        try:
            value = json.loads(result.stdout)
        except (TypeError, json.JSONDecodeError) as error:
            raise JsonInputError("offline boundary deny-rule output is invalid") from error
        if not isinstance(value, dict) or not isinstance(value.get("nftables"), list) or len(value["nftables"]) > 64:
            raise JsonInputError("offline boundary deny-rule output is invalid")
        self._validate_ruleset(value["nftables"])
        return value

    def _validate_ruleset(self, objects: list[Any]) -> None:
        """Validate the one exact ruleset; handles and counters are not trusted."""
        tables: list[dict[str, Any]] = []
        counters: list[dict[str, Any]] = []
        chains: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = []
        for item in objects:
            if not isinstance(item, dict):
                raise JsonInputError("offline boundary deny-rule output is invalid")
            if isinstance(item.get("table"), dict):
                tables.append(item["table"])
            elif isinstance(item.get("counter"), dict):
                counters.append(item["counter"])
            elif isinstance(item.get("chain"), dict):
                chains.append(item["chain"])
            elif isinstance(item.get("rule"), dict):
                rules.append(item["rule"])
            elif "metainfo" not in item:
                raise JsonInputError("offline boundary deny-rule output contains an unknown object")
        if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != self.identity.table:
            raise JsonInputError("offline boundary table identity is invalid")
        if len(counters) != 2:
            raise JsonInputError("offline boundary counter identity is invalid")
        expected_counters = {self.identity.counter, self.identity.control_counter}
        if {
            counter.get("name") for counter in counters
        } != expected_counters or any(
            counter.get("family") != "inet" or counter.get("table") != self.identity.table
            for counter in counters
        ):
            raise JsonInputError("offline boundary counter identity is invalid")
        expected_chains = {
            self.identity.input_chain: "input",
            self.identity.output_chain: "output",
        }
        if len(chains) != len(expected_chains) or {
            chain.get("name") for chain in chains
        } != set(expected_chains):
            raise JsonInputError("offline boundary chain identity is invalid")
        for chain in chains:
            if (
                chain.get("family") != "inet"
                or chain.get("table") != self.identity.table
                or chain.get("hook") != expected_chains.get(chain.get("name"))
                or chain.get("policy") != "drop"
                or chain.get("type") != "filter"
                or chain.get("prio") != 0
            ):
                raise JsonInputError("offline boundary chain policy is invalid")
        if len(rules) != 4:
            raise JsonInputError("offline boundary rule count is invalid")
        loopback_rules: set[tuple[str, str]] = set()
        deny_rules = 0
        control_rules = 0
        for rule in rules:
            if (
                rule.get("family") != "inet"
                or rule.get("table") != self.identity.table
                or not isinstance(rule.get("chain"), str)
                or not isinstance(rule.get("expr"), list)
            ):
                raise JsonInputError("offline boundary rule identity is invalid")
            chain = rule["chain"]
            expr = rule["expr"]
            if len(expr) == 2:
                first, second = expr
            elif len(expr) == 4 and chain == self.identity.output_chain:
                first, second, third, fourth = expr
                first_match = first.get("match") if isinstance(first, dict) else None
                second_match = second.get("match") if isinstance(second, dict) else None
                first_left = first_match.get("left") if isinstance(first_match, dict) else None
                second_left = second_match.get("left") if isinstance(second_match, dict) else None
                first_payload = first_left.get("payload") if isinstance(first_left, dict) else None
                second_payload = second_left.get("payload") if isinstance(second_left, dict) else None
                right = second_match.get("right") if isinstance(second_match, dict) else None
                right_set = right.get("set") if isinstance(right, dict) else None
                if (
                    not isinstance(first_match, dict)
                    or first_match.get("op") != "=="
                    or first_payload != {"field": "nexthdr", "protocol": "ip6"}
                    or first_match.get("right") != "ipv6-icmp"
                    or not isinstance(second_match, dict)
                    or second_match.get("op") != "=="
                    or second_payload != {"field": "type", "protocol": "icmpv6"}
                    or not isinstance(right_set, list)
                    or set(right_set) != CONTROL_ICMPV6_TYPES
                    or len(right_set) != len(CONTROL_ICMPV6_TYPES)
                    or third != {"counter": self.identity.control_counter}
                    or fourth != {"drop": None}
                ):
                    raise JsonInputError("offline boundary control rule is invalid")
                control_rules += 1
                continue
            else:
                raise JsonInputError("offline boundary rule identity is invalid")
            if not isinstance(first, dict) or not isinstance(second, dict):
                raise JsonInputError("offline boundary rule expression is invalid")
            match = first.get("match")
            if isinstance(match, dict) and "accept" in second:
                left = match.get("left")
                if (
                    match.get("op") != "=="
                    or not isinstance(left, dict)
                    or not isinstance(left.get("meta"), dict)
                    or left["meta"].get("key") not in {"iifname", "oifname"}
                    or match.get("right") != "lo"
                ):
                    raise JsonInputError("offline boundary loopback rule is invalid")
                loopback_rules.add((chain, left["meta"]["key"]))
                continue
            counter = first.get("counter")
            if (
                chain != self.identity.output_chain
                or counter != self.identity.counter
                or "drop" not in second
            ):
                raise JsonInputError("offline boundary deny rule is invalid")
            deny_rules += 1
        if loopback_rules != {
            (self.identity.input_chain, "iifname"),
            (self.identity.output_chain, "oifname"),
        } or deny_rules != 1 or control_rules != 1:
            raise JsonInputError("offline boundary rule set is incomplete")

    def counter(self) -> CounterSnapshot:
        value = self._table()
        found: CounterSnapshot | None = None
        for item in value["nftables"]:
            if not isinstance(item, dict) or not isinstance(item.get("counter"), dict):
                continue
            counter = item["counter"]
            if counter.get("name") != self.identity.counter:
                continue
            packets, byte_count = counter.get("packets"), counter.get("bytes")
            if (
                isinstance(packets, bool)
                or not isinstance(packets, int)
                or not 0 <= packets <= MAX_COUNTER
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or not 0 <= byte_count <= MAX_COUNTER
            ):
                raise JsonInputError("offline boundary counter values are invalid")
            if found is not None:
                raise JsonInputError("offline boundary counter is duplicated")
            found = CounterSnapshot(packets, byte_count)
        if found is None:
            raise JsonInputError("offline boundary counter is unavailable")
        return found

    def reset_counter(self) -> CounterSnapshot:
        """Clear setup-only namespace traffic while the pre-exec gate is closed."""
        for counter in (self.identity.control_counter, self.identity.counter):
            _require(
                [
                    str(IP),
                    "netns",
                    "exec",
                    self.identity.workload_namespace,
                    str(NFT),
                    "reset",
                    "counter",
                    "inet",
                    self.identity.table,
                    counter,
                ],
                action="deny-rule counter reset",
            )
        return self.assert_healthy(require_zero=True)

    def warmup(self) -> CounterSnapshot:
        """Prime namespace network state before the selected workload is released.

        Linux may emit delayed IPv6 neighbour-discovery and multicast-control
        packets when a transient namespace is first entered.  A root-owned
        no-op enters the exact namespace while the launch FIFO is still
        closed; the supervisor then waits for that bounded setup traffic to
        become quiet.  The watcher resets the counter immediately afterward,
        so only post-release workload traffic can trigger containment.
        """
        _require(
            [str(IP), "netns", "exec", self.identity.workload_namespace, "/bin/true"],
            action="namespace warmup",
        )
        deadline = time.monotonic() + WARMUP_TIMEOUT_SECONDS
        quiet_since = time.monotonic()
        previous = self.counter()
        while True:
            time.sleep(POLL_INTERVAL_SECONDS)
            current = self.counter()
            now = time.monotonic()
            if current != previous:
                previous = current
                quiet_since = now
            elif now - quiet_since >= WARMUP_QUIET_SECONDS:
                return current
            if now >= deadline:
                raise JsonInputError("offline boundary did not reach a quiet pre-release state")

    def assert_healthy(self, *, require_zero: bool = False) -> CounterSnapshot:
        self._assert_namespace_identity(
            self.identity.workload_namespace,
            self.identity.workload_namespace_device,
            self.identity.workload_namespace_inode,
        )
        self._assert_namespace_identity(
            self.identity.sink_namespace,
            self.identity.sink_namespace_device,
            self.identity.sink_namespace_inode,
        )
        workload_links = _namespace_links(self.identity.workload_namespace)
        sink_links = _namespace_links(self.identity.sink_namespace)
        if set(workload_links) != {"lo", self.identity.workload_interface}:
            raise JsonInputError("offline boundary workload links are invalid")
        if set(sink_links) != {"lo", self.identity.sink_interface}:
            raise JsonInputError("offline boundary sink links are invalid")
        if workload_links[self.identity.workload_interface] != self.identity.workload_interface_index:
            raise JsonInputError("offline boundary workload interface identity drifted")
        if sink_links[self.identity.sink_interface] != self.identity.sink_interface_index:
            raise JsonInputError("offline boundary sink interface identity drifted")
        if _default_route(self.identity.sink_namespace) or _default_route(self.identity.sink_namespace, "-6"):
            raise JsonInputError("offline boundary sink has an external route")
        if not _default_route(self.identity.workload_namespace) or not _default_route(self.identity.workload_namespace, "-6"):
            raise JsonInputError("offline boundary workload route is unavailable")
        counter = self.counter()
        if require_zero and (counter.packets or counter.bytes):
            raise JsonInputError("offline boundary counter was non-zero before release")
        return counter

    def receipt_metadata(self, *, address_family: str = "UNSPECIFIED") -> dict[str, str]:
        if address_family not in {"INET", "INET6", "UNSPECIFIED"}:
            raise JsonInputError("offline boundary address family is invalid")
        return {
            "address_family": address_family,
            "mode": "offline",
            "policy_sha256": self.identity.policy_sha256,
            "violation": "NON_LOOPBACK_EGRESS",
        }

    def teardown(self) -> dict[str, Any]:
        removed: list[str] = []
        errors: list[str] = []
        for namespace, device, inode in (
            (
                self.identity.workload_namespace,
                self.identity.workload_namespace_device,
                self.identity.workload_namespace_inode,
            ),
            (
                self.identity.sink_namespace,
                self.identity.sink_namespace_device,
                self.identity.sink_namespace_inode,
            ),
        ):
            path = _netns_path(namespace)
            if not path.exists() and not path.is_symlink():
                continue
            try:
                self._assert_namespace_identity(namespace, device, inode)
                _delete_namespace(namespace)
                if path.exists() or path.is_symlink():
                    raise JsonInputError("offline boundary namespace remained after teardown")
                removed.append(namespace)
            except (JsonInputError, OSError) as error:
                errors.append(str(error)[:160])
        if errors:
            raise JsonInputError("offline boundary teardown failed: " + "; ".join(errors))
        return {
            "removed": len(removed),
            "workload_namespace_removed": not (
                _netns_path(self.identity.workload_namespace).exists()
                or _netns_path(self.identity.workload_namespace).is_symlink()
            ),
            "sink_namespace_removed": not (
                _netns_path(self.identity.sink_namespace).exists()
                or _netns_path(self.identity.sink_namespace).is_symlink()
            ),
        }


class BoundaryObserver:
    """Bounded counter observer; the supervisor owns the kill decision."""

    def __init__(self, boundary: OfflineBoundary) -> None:
        self.boundary = boundary
        self.last = CounterSnapshot(0, 0)
        self.ready = False
        self.last_health_check = 0.0

    def arm(self) -> None:
        current = self.boundary.assert_healthy(require_zero=True)
        self.last = current
        self.last_health_check = time.monotonic()
        self.ready = True

    def poll(self) -> bool:
        if not self.ready:
            raise JsonInputError("offline boundary observer is not armed")
        now = time.monotonic()
        if now - self.last_health_check >= HEALTH_INTERVAL_SECONDS:
            current = self.boundary.assert_healthy()
            self.last_health_check = now
        else:
            current = self.boundary.counter()
        if current.packets < self.last.packets or current.bytes < self.last.bytes:
            raise JsonInputError("offline boundary counter regressed")
        changed = current.packets > self.last.packets
        self.last = current
        return changed


__all__ = [
    "HEALTH_INTERVAL_SECONDS",
    "POLL_INTERVAL_SECONDS",
    "BoundaryIdentity",
    "BoundaryNames",
    "BoundaryObserver",
    "CounterSnapshot",
    "OfflineBoundary",
    "names",
    "policy_digest",
    "primitives_available",
]
