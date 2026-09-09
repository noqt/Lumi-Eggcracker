"""Development-only checks for the synthetic comparison; never unblind held-out data."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.counter_ai import detection, replay

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "experiments/counter_ai/replay.py"


class CounterAIReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    @staticmethod
    def recipe(**changes):
        row = {"id": "development-boundary", "harmful": True, "pattern": "d",
               "effect": "read", "effect_index": 2, "acl": True, "extra_delay": 0,
               "drop": []}
        row.update(changes)
        return row

    def one(self, recipe, arm="conventional-rules", name="run"):
        return replay.replay_one(recipe, 101, "fast", arm, self.root / name)

    def test_originating_development_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "development"
            with (
                patch.object(sys, "argv", [str(REPLAY), "--output", str(output),
                                          "--split", "development"]),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaises(SystemExit) as status,
            ):
                runpy.run_path(str(REPLAY), run_name="__main__")
            self.assertEqual(status.exception.code, 0)
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["evidence_class"], "SYNTHETIC_REPLAY_ONLY")
            self.assertEqual(result["split"], "development")
            self.assertTrue(result["positive_controls_pass"])

    def test_recipe_budget_pacing_and_no_observable_labels(self):
        recipe = self.recipe()
        events, effect, duration = replay.generate(recipe, 101, "fast")
        self.assertEqual(len(events), 16)
        self.assertLess(effect, duration)
        self.assertNotIn(recipe["id"], events[0].run_id)
        self.assertNotIn("harmful", vars(events[0]))
        self.assertNotIn("effect_tick", vars(events[0]))
        slow, _, _ = replay.generate(recipe, 101, "slow")
        self.assertEqual(len(slow), len(events))
        self.assertGreater(slow[-1].event_tick, events[-1].event_tick)

    def test_unavailable_event_refused(self):
        event = detection.Event("opaque", "A", 1, 1, "sensor", 0, 2,
                                "deny", "protected", "worker")
        with self.assertRaises(ValueError):
            detection.Detector("conventional-rules").accept(event, 1)

    def test_cross_run_events_cannot_form_correlation(self):
        detector = detection.Detector("correlation")
        first = detection.Event("run-one", "A", 1, 1, "sensor", 0, 0,
                                "deny", "ordinary", "worker")
        other = detection.Event("run-two", "A", 1, 2, "sensor", 1, 1,
                                "allow", "alternate", "other")
        self.assertIsNone(detector.accept(first, 0))
        with self.assertRaises(ValueError):
            detector.accept(other, 1)

    def test_gap_breaks_correlation_continuity_but_not_replay_history(self):
        detector = detection.Detector("correlation")
        rows = [(1, "deny", "ordinary"), (2, "gap", "ordinary"),
                (3, "allow", "alternate"), (1, "deny", "ordinary")]
        for tick, (event_id, action, resource) in enumerate(rows):
            event = detection.Event("opaque", "A", 1, event_id, "sensor", tick, tick,
                                    action, resource, "worker")
            self.assertIsNone(detector.accept(event, tick))
        self.assertIsNone(detector.denial)

    def test_seal_binds_actual_runtime_identity(self):
        identity = replay.seal_identity()
        self.assertIn("interpreter_sha256", identity)
        self.assertEqual(len(identity["interpreter_sha256"]), 64)
        self.assertEqual(identity["interpreter_path"], str(Path(sys.executable).resolve()))
        self.assertTrue(identity["platform"])

    def test_outcome_fields_match_frozen_protocol(self):
        row = self.one(self.recipe())
        protocol = json.loads((ROOT / "experiments/counter_ai/protocol.v1.json").read_text())
        for field in protocol["event_schema"]["outcome_log"]:
            self.assertIn(field, row)

    def test_rate_deduplicates_and_ignores_sensor_gaps(self):
        detector = detection.Detector("rate")
        for index in range(20):
            event = detection.Event("opaque", "A", 1, index + 1, "sensor", 0, 0,
                                    "gap", "ordinary", "worker")
            self.assertIsNone(detector.accept(event, 0))
        event = detection.Event("opaque", "A", 1, 100, "sensor", 0, 0,
                                "allow", "ordinary", "worker")
        for _ in range(20):
            self.assertIsNone(detector.accept(event, 0))
        self.assertEqual(len(detector.recent), 1)

    def test_causal_ties_and_one_tick_before(self):
        recipe = self.recipe()
        events, _, _ = replay.generate(recipe, 101, "fast")
        due = events[0].available_tick + 1
        offset = events[0].event_tick
        tied = self.one(self.recipe(effect_index=due - offset), name="tie")
        early = self.one(self.recipe(effect_index=due - offset + 1), name="early")
        self.assertTrue(tied["effect_reached"])
        self.assertEqual(tied["response_effect_tick"], tied["protected_effect_tick"])
        self.assertFalse(early["effect_reached"])
        self.assertEqual(early["prevention_cause"], "RESPONSE_BLOCKED")
        self.assertEqual(early["response_request_tick"] + 1, early["response_effect_tick"])

    def test_late_or_dropped_telemetry_never_erases_effect(self):
        for name, recipe in (("late", self.recipe(extra_delay=20)),
                             ("drop", self.recipe(drop=[0]))):
            row = self.one(recipe, name=name)
            self.assertTrue(row["effect_reached"])
            self.assertEqual(row["prevention_cause"], "EFFECT_REACHED")
        self.assertIsNone(row["first_observable_violation_tick"])
        self.assertIsNone(row["detection_tick"])

    def test_acl_shared_by_all_protected_arms(self):
        for arm in detection.ARMS:
            row = self.one(self.recipe(acl=False), arm, arm)
            if arm == "positive-control":
                self.assertTrue(row["effect_reached"])
            else:
                self.assertFalse(row["effect_reached"])
                self.assertEqual(row["prevention_cause"], "ACL_BLOCKED")
            self.assertTrue(row["unrelated_unchanged"])

    def test_automatic_and_alert_only_share_decision_not_delay(self):
        recipe = self.recipe(effect_index=15)
        automatic = self.one(recipe, "correlation", "automatic")
        delayed = self.one(recipe, "alert-only", "delayed")
        self.assertEqual(automatic["detection_tick"], delayed["detection_tick"])
        self.assertEqual(automatic["response_effect_tick"] - automatic["detection_tick"], 1)
        self.assertEqual(delayed["response_effect_tick"] - delayed["detection_tick"], 30)
        self.assertFalse(automatic["effect_reached"])
        self.assertTrue(delayed["effect_reached"])

    def test_spy_receives_only_events_and_available_time(self):
        seen = []
        original = detection.Detector.accept

        def spy(detector, event, now):
            seen.append((event, now))
            return original(detector, event, now)

        with patch.object(detection.Detector, "accept", spy):
            self.one(self.recipe())
        self.assertEqual(len(seen), 16)
        for event, now in seen:
            self.assertIsInstance(event, detection.Event)
            self.assertLessEqual(event.available_tick, now)
            self.assertEqual(set(vars(event)), {"run_id", "allocation", "generation",
                                              "event_id", "sensor", "event_tick",
                                              "available_tick", "action", "resource", "identity"})

    def test_sensitivity_arms_are_explicit_not_new_detectors(self):
        first = detection.Event("opaque", "A", 1, 1, "sensor", 0, 0,
                                "deny", "ordinary", "worker")
        later = detection.Event("opaque", "A", 1, 2, "sensor", 60, 60,
                                "allow", "alternate", "other")
        for arm in ("correlation", "remove-timing", "remove-sequence", "remove-identity"):
            detector = detection.Detector(arm)
            self.assertIsNone(detector.accept(first, 0))
            self.assertEqual(detector.accept(later, 60), 60 if arm == "remove-timing" else None)

    def test_adapter_failure_invalidates_not_prevents(self):
        with (
            patch.object(replay.model.Controller, "adapter", return_value=False),
            self.assertRaises(ValueError),
        ):
            self.one(self.recipe(effect_index=15))

    def test_benign_completion_can_precede_later_interruption(self):
        row = self.one(self.recipe(harmful=False, extra_delay=20))
        self.assertTrue(row["benign_completed"])
        self.assertTrue(row["interrupted"])
        self.assertFalse(row["interrupted_before_completion"])
        self.assertEqual(row["simulated_recovery_ticks"], 4)

    def test_seal_creation_does_not_evaluate_and_changes_refuse(self):
        frozen = self.root / "frozen"
        with patch.object(replay, "replay_one", side_effect=AssertionError("no evaluation")):
            self.assertTrue(replay.run(frozen, freeze=True)["frozen"])
        seal = frozen / "seal.json"
        identity = replay.seal_identity()
        for index, field in enumerate(("source_sha256", "base_revision", "python")):
            changed = copy.deepcopy(identity)
            changed[field] = {} if field == "source_sha256" else "different"
            with (
                patch.object(replay, "seal_identity", return_value=changed),
                self.assertRaises(ValueError),
            ):
                replay.run(self.root / f"rejected-{index}", "heldout", seal)
            self.assertFalse((self.root / f"rejected-{index}").exists())

    def test_heldout_requires_prior_seal_and_no_output_on_refusal(self):
        output = self.root / "unsealed"
        with self.assertRaises(ValueError):
            replay.run(output, "heldout")
        self.assertFalse(output.exists())

    def test_cluster_interval_uses_family_not_repetition_count(self):
        rows = [{"family": "a", "value": 0}, {"family": "b", "value": 1}]
        interval = replay.cluster_interval(rows, "value")
        self.assertEqual(interval, replay.cluster_interval(rows * 10, "value"))


if __name__ == "__main__":
    unittest.main()
