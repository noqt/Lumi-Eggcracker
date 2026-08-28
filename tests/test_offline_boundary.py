from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.offline_boundary import (
    BoundaryIdentity,
    BoundaryObserver,
    CounterSnapshot,
    OfflineBoundary,
    _nft_program,
    names,
    policy_digest,
)


def identity_record() -> dict[str, object]:
    value = names("a" * 24)
    return {
        "control_counter": value.control_counter,
        "counter": value.counter,
        "input_chain": value.input_chain,
        "mode": "offline",
        "output_chain": value.output_chain,
        "policy_sha256": policy_digest(value.table),
        "run_id": value.run_id,
        "sink_interface": value.sink_interface,
        "sink_interface_index": 4,
        "sink_namespace": value.sink_namespace,
        "sink_namespace_device": 1,
        "sink_namespace_inode": 2,
        "table": value.table,
        "workload_interface": value.workload_interface,
        "workload_interface_index": 3,
        "workload_namespace": value.workload_namespace,
        "workload_namespace_device": 1,
        "workload_namespace_inode": 3,
    }


class OfflineBoundaryTests(unittest.TestCase):
    def test_names_are_run_id_owned_and_interface_safe(self) -> None:
        value = names("f" * 24)
        self.assertLessEqual(len(value.workload_interface), 15)
        self.assertLessEqual(len(value.sink_interface), 15)
        self.assertTrue(value.workload_namespace.startswith("lumi-eggcracker-w-"))
        self.assertTrue(value.sink_namespace.startswith("lumi-eggcracker-s-"))
        with self.assertRaises(JsonInputError):
            names("not-a-run-id")

    def test_identity_round_trip_rejects_drift_and_unknown_fields(self) -> None:
        value = identity_record()
        parsed = BoundaryIdentity.from_record(value)
        self.assertEqual(value, parsed.as_record())
        for key, replacement in (
            ("workload_interface", "eth0"),
            ("workload_interface_index", 0),
            ("policy_sha256", "0" * 64),
        ):
            changed = dict(value)
            changed[key] = replacement
            with self.assertRaises(JsonInputError):
                BoundaryIdentity.from_record(changed)
        changed = dict(value)
        changed["extra"] = True
        with self.assertRaises(JsonInputError):
            BoundaryIdentity.from_record(changed)

    def test_ruleset_contains_loopback_control_and_count_drop_rules(self) -> None:
        value = names("a" * 24)
        expected = {
            "nftables": [
                {"table": {"family": "inet", "name": value.table}},
                {
                    "counter": {
                        "family": "inet",
                        "name": value.counter,
                        "table": value.table,
                        "packets": 0,
                        "bytes": 0,
                    }
                },
                {
                    "counter": {
                        "family": "inet",
                        "name": value.control_counter,
                        "table": value.table,
                        "packets": 0,
                        "bytes": 0,
                    }
                },
                {
                    "chain": {
                        "family": "inet",
                        "name": value.input_chain,
                        "table": value.table,
                        "type": "filter",
                        "hook": "input",
                        "prio": 0,
                        "policy": "drop",
                    }
                },
                {
                    "chain": {
                        "family": "inet",
                        "name": value.output_chain,
                        "table": value.table,
                        "type": "filter",
                        "hook": "output",
                        "prio": 0,
                        "policy": "drop",
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": value.table,
                        "chain": value.input_chain,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "iifname"}},
                                    "right": "lo",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": value.table,
                        "chain": value.output_chain,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "oifname"}},
                                    "right": "lo",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": value.table,
                        "chain": value.output_chain,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {
                                            "field": "nexthdr",
                                            "protocol": "ip6",
                                        }
                                    },
                                    "right": "ipv6-icmp",
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {
                                            "field": "type",
                                            "protocol": "icmpv6",
                                        }
                                    },
                                    "right": {
                                        "set": [
                                            "mld-listener-query",
                                            "mld-listener-report",
                                            "mld-listener-done",
                                            "nd-router-solicit",
                                            "nd-router-advert",
                                            "nd-neighbor-solicit",
                                            "nd-neighbor-advert",
                                            "nd-redirect",
                                            "mld2-listener-report",
                                        ]
                                    },
                                }
                            },
                            {"counter": value.control_counter},
                            {"drop": None},
                        ],
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": value.table,
                        "chain": value.output_chain,
                        "expr": [
                            {"counter": value.counter},
                            {"drop": None},
                        ],
                    }
                },
            ]
        }
        boundary = OfflineBoundary(BoundaryIdentity.from_record(identity_record()))
        boundary._validate_ruleset(expected["nftables"])
        malformed = json.loads(json.dumps(expected))
        malformed["nftables"][-1]["rule"]["chain"] = value.input_chain
        with self.assertRaises(JsonInputError):
            boundary._validate_ruleset(malformed["nftables"])
        self.assertIn("counter name", _nft_program(value.table))

    def test_observer_arms_at_zero_and_reports_one_monotonic_transition(self) -> None:
        class FakeBoundary:
            def __init__(self) -> None:
                self.values = [
                    CounterSnapshot(0, 0),
                    CounterSnapshot(0, 0),
                    CounterSnapshot(1, 64),
                    CounterSnapshot(0, 0),
                ]

            def assert_healthy(self, *, require_zero: bool = False) -> CounterSnapshot:
                value = self.values.pop(0)
                if require_zero and value.packets:
                    raise JsonInputError("not zero")
                return value

            def counter(self) -> CounterSnapshot:
                return self.values.pop(0)

        fake = FakeBoundary()
        observer = BoundaryObserver(fake)  # type: ignore[arg-type]
        with patch("lumi_eggcracker.offline_boundary.time.monotonic", side_effect=[1.0, 1.01, 1.02]):
            observer.arm()
            self.assertFalse(observer.poll())
            self.assertTrue(observer.poll())
        with self.assertRaises(JsonInputError):
            observer.poll()

    def test_warmup_primes_and_waits_for_quiet_counter(self) -> None:
        boundary = OfflineBoundary(BoundaryIdentity.from_record(identity_record()))
        values = iter((CounterSnapshot(0, 0), CounterSnapshot(1, 96), CounterSnapshot(1, 96)))
        with (
            patch("lumi_eggcracker.offline_boundary._require") as require,
            patch.object(boundary, "counter", side_effect=lambda: next(values)),
            patch("lumi_eggcracker.offline_boundary.time.sleep"),
            patch("lumi_eggcracker.offline_boundary.time.monotonic", side_effect=(0.0, 0.0, 0.05, 1.60)),
        ):
            self.assertEqual(boundary.warmup(), CounterSnapshot(1, 96))
        require.assert_called_once()


if __name__ == "__main__":
    unittest.main()
