from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.brokered import BrokeredOperator, BrokeredStoreError
from lumi_eggcracker.brokered import operator as implementation


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class BrokeredOperatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=tempfile.gettempdir())
        self.addCleanup(self.temp.cleanup)
        self.state_dir = Path(self.temp.name) / "state"
        self.registrar, self.operator = BrokeredOperator.bootstrap(self.state_dir)

    def grant_and_client(self):
        grant = self.registrar.register_run()
        return grant, self.operator.client(grant)

    def test_allowed_effect_replay_and_state_reopen(self) -> None:
        grant, client = self.grant_and_client()
        queued = client.admit("operation-1")
        self.assertEqual(("admission", "QUEUED", "ADMITTED"), (queued.phase, queued.outcome, queued.code))
        self.assertNotIn("capability", queued.as_dict())
        self.assertLessEqual(len(queued.canonical_bytes()), implementation.MAX_RECEIPT_BYTES)

        applied = self.operator.dispatch(queued.queue_id)
        self.assertTrue(applied.effect_applied)
        self.assertEqual("APPLIED", applied.outcome)
        self.assertEqual("REPLAY", self.operator.dispatch(queued.queue_id).code)
        with self.assertRaises(TypeError):
            self.operator.dispatch(queued.queue_id, target="synthetic.other")
        self.assertEqual(
            implementation.WorldSnapshot(1, implementation.UNRELATED_CANARY_ALLOCATION),
            self.operator.world_snapshot(),
        )

        _, reopened = BrokeredOperator.open(self.state_dir)
        self.assertEqual(self.operator.world_snapshot(), reopened.world_snapshot())
        self.assertEqual("REPLAY", reopened.dispatch(queued.queue_id).code)
        self.assertEqual("operation-1", json.loads(client.request_bytes("operation-1"))["operation_id"])
        self.assertEqual(grant.run_id, applied.run_id)

    def test_parser_rejects_duplicate_unknown_boolean_malformed_oversized_and_noncanonical(self) -> None:
        _, client = self.grant_and_client()
        valid = client.request_bytes("strict-input")
        duplicate = valid.replace(b'"action":"increment",', b'"action":"increment","action":"increment",')
        unknown = json.loads(valid)
        unknown["label"] = "caller-controlled"
        boolean_generation = valid.replace(b'"generation":0', b'"generation":true')
        cases = (
            (duplicate, "MALFORMED_INPUT"),
            (canonical(unknown), "UNKNOWN_FIELDS"),
            (boolean_generation, "MALFORMED_INPUT"),
            (b'{"broken":', "MALFORMED_INPUT"),
            (b" " * (implementation.MAX_REQUEST_BYTES + 1), "MALFORMED_INPUT"),
            (valid.rstrip(b"\n"), "NON_CANONICAL_INPUT"),
        )
        for raw, code in cases:
            with self.subTest(code=code, size=len(raw)):
                result = self.operator.admit(raw)
                self.assertEqual(code, result.code)
                self.assertFalse(result.effect_applied)
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)

    def test_target_run_and_generation_relabelling_do_not_authorize(self) -> None:
        grant, client = self.grant_and_client()
        other = self.registrar.register_run()
        with self.assertRaises(PermissionError):
            implementation.TrustedRegistrar(self.operator)
        with self.assertRaises(TypeError):
            self.registrar.register_run(run_id="caller-selected")
        with self.assertRaisesRegex(ValueError, "labels"):
            self.operator.client(replace(grant, target="synthetic.other"))

        valid = json.loads(client.request_bytes("relabel-1"))
        valid["run_id"] = other.run_id
        self.assertEqual("CAPABILITY_INVALID", self.operator.admit(canonical(valid)).code)
        valid = json.loads(client.request_bytes("relabel-2"))
        valid["generation"] = 77
        self.assertEqual("CAPABILITY_INVALID", self.operator.admit(canonical(valid)).code)
        valid = json.loads(client.request_bytes("relabel-3"))
        valid["target"] = "synthetic.other"
        self.assertEqual("MALFORMED_INPUT", self.operator.admit(canonical(valid)).code)
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)

    def test_expiry_is_exact_at_the_capability_boundary(self) -> None:
        with patch.object(implementation.time, "time_ns", return_value=1_000_000_000):
            grant = self.registrar.register_run()
        client = self.operator.client(grant)
        with patch.object(
            implementation.time,
            "time_ns",
            return_value=grant.expires_at_ms * 1_000_000,
        ):
            self.assertEqual("EXPIRED", client.admit("at-expiry").code)
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)

    def test_per_run_and_aggregate_pending_budgets(self) -> None:
        _, first_client = self.grant_and_client()
        _, second_client = self.grant_and_client()
        first_request = first_client.request_bytes("budget-first")
        second_request = second_client.request_bytes("budget-other")
        self.assertEqual(len(first_request), len(second_request))
        with patch.object(
            implementation,
            "MAX_PENDING_BYTES",
            (len(first_request) * 2) - 1,
        ):
            first = self.operator.admit(first_request)
            self.assertEqual("QUEUED", first.outcome)
            self.assertEqual("GLOBAL_BUDGET_EXHAUSTED", self.operator.admit(second_request).code)
        self.assertTrue(self.operator.dispatch(first.queue_id).effect_applied)

        _, client = self.grant_and_client()
        for index in range(implementation.MAX_ACTIONS_PER_RUN):
            queued = client.admit(f"run-budget-{index}")
            self.assertEqual("QUEUED", queued.outcome)
            self.operator.dispatch(queued.queue_id)
        self.assertEqual("BUDGET_EXHAUSTED", client.admit("run-budget-overflow").code)
        self.assertEqual(
            implementation.MAX_ACTIONS_PER_RUN + 1,
            self.operator.world_snapshot().protected_effects,
        )

    def test_stop_request_fences_queued_and_future_actions_without_claiming_process_stop(self) -> None:
        grant, client = self.grant_and_client()
        queued = client.admit("before-stop")
        stop = self.operator.request_stop(grant.run_id)
        self.assertEqual(("revocation", "REVOKED", 1), (stop.phase, stop.outcome, stop.generation))
        self.assertEqual("UNSUPPORTED", stop.process_stop)
        self.assertEqual("STALE_GENERATION", self.operator.dispatch(queued.queue_id).code)
        self.assertEqual("CAPABILITY_REVOKED", client.admit("after-stop").code)
        self.assertEqual("UNSUPPORTED", self.operator.verified_process_stop(grant.run_id).outcome)
        self.assertEqual(0, self.operator.world_snapshot().protected_effects)
        self.assertEqual(implementation.UNRELATED_CANARY_ALLOCATION, self.operator.world_snapshot().unrelated_canary_allocation)

        _, reopened = BrokeredOperator.open(self.state_dir)
        self.assertEqual(1, reopened.revoke(grant.run_id).generation)
        self.assertEqual("ALREADY_REVOKED", reopened.request_stop(grant.run_id).outcome)
        self.assertEqual("ALREADY_FINAL", reopened.dispatch(queued.queue_id).code)

    def test_concurrent_dispatch_has_one_synthetic_effect(self) -> None:
        _, client = self.grant_and_client()
        queued = client.admit("concurrent-1")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.operator.dispatch, [queued.queue_id, queued.queue_id]))
        self.assertCountEqual(["EFFECT_APPLIED", "REPLAY"], [result.code for result in results])
        self.assertEqual(1, self.operator.world_snapshot().protected_effects)
        self.assertEqual(implementation.UNRELATED_CANARY_ALLOCATION, self.operator.world_snapshot().unrelated_canary_allocation)

    def test_full_replay_registry_does_not_evict_live_generation_fence(self) -> None:
        with patch.object(implementation, "MAX_REPLAY_KEYS", 1):
            first_grant, first_client = self.grant_and_client()
            first = first_client.admit("one-only-key")
            _, second_client = self.grant_and_client()
            self.assertEqual("REPLAY_CAPACITY_EXHAUSTED", second_client.admit("second-key").code)
            self.assertEqual(1, self.operator.request_stop(first_grant.run_id).generation)
            _, reopened = BrokeredOperator.open(self.state_dir)
            self.assertEqual("STALE_GENERATION", reopened.dispatch(first.queue_id).code)
            self.assertEqual("REPLAY_CAPACITY_EXHAUSTED", reopened.client(self.registrar.register_run()).admit("third-key").code)
            self.assertEqual(0, reopened.world_snapshot().protected_effects)

    def test_state_missing_malformed_or_replaced_fails_closed(self) -> None:
        journal = self.state_dir / implementation.JOURNAL_NAME
        with self.subTest(case="missing"):
            journal.unlink()
            with self.assertRaises(BrokeredStoreError):
                BrokeredOperator.open(self.state_dir)

        self.registrar, self.operator = BrokeredOperator.bootstrap(self.state_dir.parent / "malformed")
        malformed = self.state_dir.parent / "malformed"
        malformed_journal = malformed / implementation.JOURNAL_NAME
        content = malformed_journal.read_bytes()
        malformed_journal.write_bytes(b"X" + content[1:])
        with self.subTest(case="malformed"), self.assertRaises(BrokeredStoreError):
            BrokeredOperator.open(malformed)

        self.registrar, self.operator = BrokeredOperator.bootstrap(self.state_dir.parent / "replaced")
        replaced = self.state_dir.parent / "replaced"
        replaced_journal = replaced / implementation.JOURNAL_NAME
        replacement = replaced / "replacement.bin"
        replacement.write_bytes(replaced_journal.read_bytes())
        os.replace(replacement, replaced_journal)
        with self.subTest(case="replaced"), self.assertRaises(BrokeredStoreError):
            BrokeredOperator.open(replaced)

        self.registrar, self.operator = BrokeredOperator.bootstrap(self.state_dir.parent / "rollback")
        rollback = self.state_dir.parent / "rollback"
        rollback_journal = rollback / implementation.JOURNAL_NAME
        prior_journal = rollback_journal.read_bytes()
        self.registrar.register_run()
        rollback_journal.write_bytes(prior_journal)
        with self.subTest(case="valid-prefix-rollback"), self.assertRaises(BrokeredStoreError):
            BrokeredOperator.open(rollback)


if __name__ == "__main__":
    unittest.main()
