"""Originating CLI and state invariants for the inert human-stop experiment."""

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

from experiments.human_override import model

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "experiments/human_override/lab.py"


class HumanOverrideLabTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "controller.json"
        self.world = model.World()
        self.controller = model.Controller(self.path, self.world, create=True)

    def command(self, op, principal="human", allocation="A", **overrides):
        row = self.controller.allocations[allocation]
        event = {"op": op, "allocation": allocation, "generation": row.generation,
                 "epoch": row.epoch, "sequence": row.sequence[principal] + 1}
        event.update(overrides)
        return self.controller.command(principal, event)

    def start(self, allocation="A"):
        self.assertEqual(self.command("approve", allocation=allocation), "OK")
        self.assertEqual(self.command("start", allocation=allocation), "OK")

    def stopped(self):
        self.assertEqual(self.command("stop"), "OK")
        self.assertTrue(self.controller.adapter("A", cancel_remote=True))
        self.assertEqual(self.controller.observe("A"), "VERIFIED_STOPPED")

    def test_originating_cli_approved_stop_and_relaunch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "experiment"
            stream = io.StringIO()
            with (
                patch.object(sys, "argv", [str(LAB), "--output", str(output)]),
                contextlib.redirect_stdout(stream),
                self.assertRaises(SystemExit) as exit_status,
            ):
                runpy.run_path(str(LAB), run_name="__main__")
            self.assertEqual(exit_status.exception.code, 0)
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["result"], "PASS")
            self.assertEqual(result["evidence_class"], "SIMULATION_ONLY")
            self.assertTrue(result["approved_stop_relaunch"])
            self.assertEqual(len(result["cases"]), 5)
            self.assertTrue(all(case["pass"] for case in result["cases"]))

    def test_start_stop_orderings_and_new_approval(self):
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        self.assertTrue(self.world.allocations["A"].running)
        self.assertEqual(self.command("approve"), "DENIED")
        self.assertEqual(self.command("start", "scheduler"), "DENIED")
        self.assertTrue(self.controller.adapter("A", cancel_remote=True))
        self.assertFalse(self.world.allocations["A"].running)
        # Inverse ordering: stop before any launch.
        self.assertEqual(self.command("stop", allocation="B"), "OK")
        self.assertEqual(self.command("approve", allocation="B"), "DENIED")
        self.assertEqual(self.command("start", allocation="B"), "DENIED")
        self.assertEqual(self.world.allocations["B"].launches, 0)

    def test_duplicate_stop_replay_and_restart_persistence(self):
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        epoch = self.controller.allocations["A"].epoch
        self.assertEqual(self.command("stop"), "OK")
        self.assertEqual(self.controller.allocations["A"].epoch, epoch)
        self.assertEqual(self.command("start", epoch=0, sequence=1), "STALE_SCOPE")
        self.controller = model.Controller(self.path, self.world)
        self.assertEqual(self.controller.status("A")["stop"], "REQUESTED")
        self.assertEqual(self.command("stop", sequence=1), "REPLAY")
        self.assertEqual(self.command("approve"), "DENIED")
        self.assertEqual(self.command("start"), "DENIED")
        self.assertEqual(self.world.allocations["A"].launches, 1)

    def test_reset_never_launches_and_old_stop_cannot_relatch(self):
        self.start()
        self.stopped()
        self.assertEqual(self.command("reset", "guest"), "DENIED")
        self.assertEqual(self.command("reset", epoch=0), "STALE_SCOPE")
        self.assertEqual(self.command("reset"), "OK")
        self.assertFalse(self.world.allocations["A"].running)
        self.assertEqual(self.world.allocations["A"].launches, 1)
        self.assertEqual(self.command("stop", epoch=0), "STALE_SCOPE")
        self.assertEqual(self.command("start"), "DENIED")
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        self.assertEqual(self.controller.allocations["A"].epoch, 3)

    def test_generation_replacement_fences_all_old_commands(self):
        self.start()
        self.assertFalse(self.controller.replace_allocation("A"))
        self.stopped()
        self.assertFalse(self.controller.replace_allocation("A"))
        self.assertEqual(self.command("reset"), "OK")
        self.assertTrue(self.controller.replace_allocation("A"))
        before = copy.deepcopy(self.controller.allocations)
        for op in ("start", "stop", "reset", "approve"):
            self.assertEqual(self.command(op, generation=1), "STALE_SCOPE")
        self.assertEqual(before, self.controller.allocations)
        self.start()
        self.assertEqual(self.world.allocations["A"].generation, 2)

    def test_reset_fences_queued_commands_even_with_higher_sequence_after_reload(self):
        self.start()
        self.stopped()
        old_epoch = self.controller.allocations["A"].epoch
        self.assertEqual(self.command("reset"), "OK")
        self.controller = model.Controller(self.path, self.world)
        before = copy.deepcopy(self.controller.allocations)
        for op in ("stop", "approve", "start", "reset"):
            self.assertEqual(self.command(op, epoch=old_epoch, sequence=999), "STALE_SCOPE")
        self.assertEqual(before, self.controller.allocations)
        self.assertFalse(self.world.allocations["A"].running)
        self.assertEqual(self.world.allocations["A"].launches, 1)

    def test_reset_epoch_exhaustion_never_unlocks(self):
        self.stopped()
        self.controller.allocations["A"].epoch = model.MAX_INTEGER
        self.controller.observe("A")
        self.assertEqual(self.command("reset"), "EXHAUSTED")
        self.assertTrue(self.controller.allocations["A"].latched)

    def test_forged_claims_and_principal_cannot_change_state(self):
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        before = copy.deepcopy(self.controller.allocations)
        for op in ("start", "approve", "stop", "reset"):
            self.assertEqual(self.command(op, "guest"), "DENIED")
        for payload in ({"observed": "VERIFIED_STOPPED"}, {"principal": "human"},
                        {"approved": True}, {"reset": True}):
            self.assertEqual(self.controller.command("guest", payload), "INVALID")
        self.assertEqual(before, self.controller.allocations)
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")

    def test_remote_disconnection_and_unknown_observations(self):
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        self.assertTrue(self.controller.adapter("A"))
        self.assertTrue(self.world.allocations["A"].remote_running)
        self.assertEqual(self.controller.observe("A"), "RUNNING")
        self.assertEqual(self.command("reset"), "DENIED")
        self.assertTrue(self.controller.adapter("A", cancel_remote=True))
        self.assertEqual(self.controller.observe("A", fail=True), "UNKNOWN")
        self.assertEqual(self.command("reset"), "DENIED")
        self.assertEqual(self.controller.observe("A"), "VERIFIED_STOPPED")
        self.world.advance(model.OBSERVATION_TTL + 1)
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")
        self.assertEqual(self.command("reset"), "DENIED")

    def test_observation_generation_epoch_time_and_revision_fences(self):
        self.stopped()
        original = self.controller.observations["A"]
        bad = [(2, *original[1:]), (original[0], 0, *original[2:]),
               (*original[:2], self.world.tick + 1, *original[3:]),
               (*original[:3], original[3] + 1, original[4])]
        for observation in bad:
            self.controller.observations["A"] = observation
            self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")
        self.controller.observations["A"] = original
        self.controller = model.Controller(self.path, self.world)
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")

    def test_control_loss_inhibits_not_stops_and_is_persistent(self):
        self.start()
        self.assertTrue(self.controller.set_control("A", False))
        self.assertTrue(self.world.allocations["A"].running)
        self.assertEqual(self.controller.observe("A"), "UNKNOWN")
        self.assertEqual(self.command("stop"), "OK")
        self.assertFalse(self.controller.adapter("A", cancel_remote=True))
        self.controller = model.Controller(self.path, self.world)
        self.assertEqual(self.controller.status("A")["admission"], "INHIBITED")
        self.assertEqual(self.command("start"), "DENIED")

    def test_unrelated_allocation_and_bounded_audit_flood(self):
        self.start("B")
        before = copy.deepcopy((self.controller.allocations["B"], self.world.allocations["B"]))
        self.assertEqual(self.command("stop"), "OK")
        for _ in range(150):
            self.assertEqual(self.command("approve"), "DENIED")
            self.assertEqual(self.command("reset", "guest"), "DENIED")
        self.assertEqual(before, (self.controller.allocations["B"], self.world.allocations["B"]))
        row = self.controller.allocations["A"]
        self.assertEqual(len(row.audit), model.AUDIT_LIMIT)
        self.assertEqual(row.dropped, 151 - model.AUDIT_LIMIT)
        self.assertTrue(row.latched)
        self.assertLess(self.path.stat().st_size, model.MAX_BYTES)
        self.assertTrue(self.controller.adapter("A", cancel_remote=True))

    def test_malformed_inputs_have_no_mutation(self):
        before = copy.deepcopy(self.controller.allocations)
        valid = {"op": "stop", "allocation": "A", "generation": 1, "sequence": 1, "epoch": 0}
        for key in valid:
            for value in (None, [], {}, True, -1, 10**100, "x" * 10000):
                bad = dict(valid, **{key: value})
                self.assertEqual(self.controller.command("human", bad), "INVALID")
        self.assertEqual(before, self.controller.allocations)

    def test_strict_json_limits(self):
        bad = [b'{"x":1,"x":2}', b'NaN', b'Infinity', b'1.5', b'"\xff"',
               b'[' * 20 + b'0' + b']' * 20, b'1' * 5000,
               b'"' + b'x' * 257 + b'"', b' ' * (model.MAX_BYTES + 1)]
        for raw in bad:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                model.bounded_json(raw)

    def test_persistence_failure_never_launches_or_claims_stop(self):
        self.assertEqual(self.command("approve"), "OK")
        with patch.object(self.controller, "_persist", side_effect=OSError("synthetic I/O")):
            self.assertEqual(self.command("start"), "STORAGE_UNKNOWN")
        self.assertEqual(self.world.allocations["A"].launches, 0)
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")
        self.assertEqual(self.controller.status("A")["admission"], "INHIBITED")

    def test_durable_stop_exists_before_adapter_and_crash_reload(self):
        self.start()
        self.assertEqual(self.command("stop"), "OK")
        # Crash after persisted latch, before adapter: World is still running.
        self.controller = model.Controller(self.path, self.world)
        self.assertTrue(self.world.allocations["A"].running)
        self.assertEqual(self.command("start"), "DENIED")
        self.assertTrue(self.controller.adapter("A", cancel_remote=True))
        self.controller = model.Controller(self.path, self.world)
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")
        self.assertEqual(self.controller.observe("A"), "VERIFIED_STOPPED")

    def test_atomic_replace_failure_retains_old_state_and_fail_closed(self):
        self.start()
        previous = self.path.read_bytes()
        with patch.object(model.os, "replace", side_effect=OSError("synthetic replace")):
            self.assertEqual(self.command("stop"), "STORAGE_UNKNOWN")
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertTrue(self.path.with_suffix(".pending").exists())
        self.assertFalse(self.controller.adapter("A", cancel_remote=True))
        self.assertEqual(self.controller.status("A")["observed"], "UNKNOWN")
        self.controller = model.Controller(self.path, self.world)
        self.assertFalse(self.controller.storage_ok)
        self.assertEqual(self.controller.status("A")["admission"], "INHIBITED")
        self.assertEqual(self.command("start"), "STORAGE_UNKNOWN")

    def test_missing_and_corrupt_storage_are_unknown(self):
        missing = model.Controller(self.path.parent / "absent.json", self.world)
        self.assertFalse(missing.storage_ok)
        with patch.object(Path, "open", return_value=io.BytesIO(b'{"schema":"wrong"}')):
            corrupt = model.Controller(self.path, self.world)
        self.assertFalse(corrupt.storage_ok)
        self.assertEqual(corrupt.status("A")["admission"], "INHIBITED")
        self.assertEqual(corrupt.observe("A"), "UNKNOWN")

    def test_protected_effect_positive_controls_and_late_stop(self):
        self.start()
        kinds = ("read", "export", "child", "restart", "lateral", "tamper")
        for kind in kinds:
            self.assertTrue(self.world.effect("A", kind))
        self.stopped()
        for kind in kinds:
            self.assertFalse(self.world.effect("A", kind))
        self.assertEqual(len(self.world.allocations["A"].effects), len(kinds))

    def test_cli_refuses_existing_output_without_overwrite(self):
        stream = io.StringIO()
        with (
            patch.object(sys, "argv", [str(LAB), "--output", self.directory.name]),
            contextlib.redirect_stderr(stream),
            self.assertRaises(SystemExit) as status,
        ):
            runpy.run_path(str(LAB), run_name="__main__")
        self.assertEqual(status.exception.code, 2)
        self.assertTrue(self.path.is_file())


if __name__ == "__main__":
    unittest.main()
