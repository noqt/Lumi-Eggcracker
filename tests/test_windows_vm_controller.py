"""Mock-only contract tests: no native Windows process or job calls."""

import ast
import contextlib
import io
import json
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.human_override.windows_vm_controller import (
    Controller,
    MockJob,
    MockKernel,
    MockQueryHandle,
)
from experiments.human_override.windows_vm_lab import MockJudge, run

ROOT = Path(__file__).resolve().parents[1]


class WindowsVMControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.json"
        self.kernel = MockKernel()
        self.controller = Controller(self.path, self.kernel, create=True)

    def command(self, operation, **changes):
        row = self.controller.state
        fields = {"allocation": "A", "generation": row["generation"],
                  "epoch": row["epoch"], "sequence": row["sequence"] + 1}
        fields.update(changes)
        return self.controller.command("human", operation, **fields)

    def running(self):
        self.assertEqual(self.command("approve"), "OK")
        self.assertEqual(self.command("start"), "MOCK_RUNNING")
        judge = MockJudge(self.kernel.duplicate_for_judge(self.controller.process))
        self.assertEqual(judge.observe(self.controller.state["identity"]), "MOCK_RUNNING")
        return judge

    def test_stop_dispatch_is_not_observed_exit(self):
        judge = self.running()
        self.assertEqual(self.command("stop"), "MOCK_STOP_DISPATCHED")
        self.assertEqual(self.controller.observed(judge), "MOCK_RUNNING")
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.controller.observed(judge), "MOCK_VERIFIED_PRIMARY_EXIT")

    def test_controller_crash_stops_mock_job_and_inhibits_restart(self):
        judge = self.running()
        self.controller.crash()
        self.controller = Controller(self.path, self.kernel)
        self.assertEqual(self.command("start"), "DENIED")
        self.assertEqual(self.controller.observed(judge), "MOCK_VERIFIED_PRIMARY_EXIT")

    def test_reset_never_launches(self):
        judge = self.running()
        self.command("stop")
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.command("reset", judge=judge), "OK")
        self.assertEqual(self.kernel.resumes, 1)
        self.assertEqual(self.command("start"), "DENIED")

    def test_atomic_suspended_identity_persistence_precedes_resume(self):
        self.running()
        events = self.kernel.events
        self.assertLess(events.index("persist:START_INTENT"), events.index("spawn_suspended"))
        self.assertLess(events.index("spawn_suspended"), events.index("persist:IDENTIFIED_SUSPENDED"))
        self.assertLess(events.index("persist:IDENTIFIED_SUSPENDED"), events.index("resume"))
        self.assertFalse(self.controller.job.inherited)
        self.assertFalse(self.controller.job.breakaway)
        self.assertEqual(self.controller.job.active_process_limit, 1)

    def test_unsupported_atomic_job_properties_never_resume(self):
        for key, value in (("inherited", True), ("breakaway", True),
                           ("kill_on_close", False), ("active_process_limit", 2)):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                kernel = MockKernel()
                controller = Controller(Path(directory) / "state.json", kernel, create=True)
                controller.state["approved"] = True
                job = MockJob()
                setattr(job, key, value)
                with patch.object(kernel, "create_job", return_value=job):
                    self.assertEqual(controller._start(), "UNKNOWN")
                self.assertEqual(kernel.resumes, 0)
                self.assertTrue(controller.state["latched"])

    def test_each_start_api_failure_inhibits(self):
        for action in ("verify_artifacts", "create_job", "spawn_suspended", "validate_handle", "resume"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                kernel = MockKernel()
                controller = Controller(Path(directory) / "state.json", kernel, create=True)
                controller.state["approved"] = True
                kernel.fail_at.add(action)
                self.assertEqual(controller._start(), "UNKNOWN")
                self.assertEqual(kernel.resumes, 0)
                self.assertTrue(controller.state["latched"])
                if controller.process is not None:
                    self.assertFalse(controller.process.alive)

    def test_stop_persist_failure_still_dispatches_but_cannot_reset(self):
        judge = self.running()
        with patch("experiments.human_override.windows_vm_controller.os.replace", side_effect=OSError):
            self.assertEqual(self.command("stop"), "MOCK_STOP_DISPATCHED_DURABILITY_UNCONFIRMED")
        self.assertEqual(self.kernel.terminations, 1)
        self.assertFalse(self.controller.storage_ok)
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.command("reset", judge=judge), "DENIED_DURABILITY_UNCONFIRMED")
        recovered = Controller(self.path, self.kernel)
        self.assertTrue(recovered.state["latched"])
        self.assertFalse(recovered.state["approved"])

    def test_latch_precedes_stop_dispatch(self):
        self.running()
        self.command("stop")
        events = self.kernel.events
        self.assertLess(events.index("persist:STOP_REQUESTED"), events.index("terminate"))

    def test_pending_identity_write_failure_prevents_resume(self):
        self.command("approve")
        original = self.controller._save

        def fail_identified():
            if self.controller.state["phase"] == "IDENTIFIED_SUSPENDED":
                self.controller._storage_failure()
                return False
            return original()

        with patch.object(self.controller, "_save", side_effect=fail_identified):
            self.assertEqual(self.command("start"), "UNKNOWN")
        self.assertEqual(self.kernel.resumes, 0)
        self.assertFalse(self.controller.process.alive)

    def test_stop_wins_injected_before_resume_interleaving(self):
        self.command("approve")
        original = self.kernel.validate

        def stop_before_resume(process, identity):
            with patch.object(self.kernel, "validate", side_effect=original):
                self.assertEqual(self.command("stop"), "MOCK_STOP_DISPATCHED")
            return original(process, identity)

        with patch.object(self.kernel, "validate", side_effect=stop_before_resume):
            self.assertEqual(self.command("start"), "UNKNOWN")
        self.assertEqual(self.kernel.resumes, 0)
        self.assertTrue(self.controller.state["latched"])

    def test_changed_creation_identity_does_not_terminate(self):
        self.running()
        self.controller.process.identity["creation_time"] += 1
        self.assertEqual(self.command("stop"), "UNKNOWN")
        self.assertEqual(self.kernel.terminations, 0)

    def test_no_retained_handle_is_not_reacquired_by_pid(self):
        self.running()
        self.controller.process = None
        self.assertEqual(self.command("stop"), "UNKNOWN")
        self.assertEqual(self.kernel.terminations, 0)
        self.assertFalse(hasattr(self.kernel, "open_pid"))

    def test_dispatch_failure_or_missing_judge_is_unknown(self):
        judge = self.running()
        self.kernel.fail_at.add("terminate")
        self.assertEqual(self.command("stop"), "UNKNOWN")
        self.assertEqual(self.controller.observed(None), "UNKNOWN")
        judge.lost = True
        self.assertEqual(self.controller.observed(judge), "UNKNOWN")

    def test_judge_requires_prior_liveness_and_query_only_rights(self):
        self.running()
        handle = self.kernel.duplicate_for_judge(self.controller.process)
        judge = MockJudge(handle)
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.controller.observed(judge), "UNKNOWN")
        with self.assertRaises(ValueError):
            MockJudge(MockQueryHandle(handle.process, frozenset({"terminate", "query"})))
        self.assertFalse(hasattr(handle, "job"))

    def test_stale_forged_out_of_scope_commands_do_not_dispatch(self):
        self.running()
        for fields in ({"allocation": "B"}, {"generation": 0}, {"epoch": 99},
                       {"sequence": 0}, {"generation": True}):
            self.assertEqual(self.command("stop", **fields), "DENIED")
        row = self.controller.state
        self.assertEqual(self.controller.command("guest", "stop", allocation="A",
                         generation=row["generation"], epoch=row["epoch"], sequence=99), "DENIED")
        self.assertEqual(self.kernel.terminations, 0)

    def test_reset_fences_old_epoch_and_next_start_advances_generation(self):
        judge = self.running()
        self.command("stop")
        old_epoch = self.controller.state["epoch"]
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.command("reset", judge=judge), "OK")
        self.assertEqual(self.command("approve", epoch=old_epoch, sequence=999), "DENIED")
        self.command("approve")
        self.assertEqual(self.command("start"), "MOCK_RUNNING")
        self.assertEqual(self.controller.state["generation"], 2)
        self.assertEqual(self.controller.observed(judge), "UNKNOWN")

    def test_corrupt_missing_and_pending_state_inhibit(self):
        for name, content in (("missing", None), ("corrupt", "{"),
                               ("duplicate", '{"schema":1,"schema":2}'),
                               ("oversize", "x" * 65537)):
            path = self.path.parent / (name + ".json")
            if content is not None:
                path.write_text(content)
            recovered = Controller(path, self.kernel)
            self.assertFalse(recovered.storage_ok)
            self.assertTrue(recovered.state["latched"])
        self.path.with_suffix(".pending").write_text("partial")
        recovered = Controller(self.path, self.kernel)
        self.assertFalse(recovered.storage_ok)
        self.assertTrue(recovered.state["latched"])

    def test_non_mock_adapter_is_refused_before_any_call(self):
        with self.assertRaises(TypeError):
            Controller(self.path, object())

    def test_forged_judge_cannot_reset_a_live_target(self):
        class ForgedJudge:
            def observe(self, identity):
                return "MOCK_VERIFIED_PRIMARY_EXIT"

        self.running()
        self.command("stop")
        self.assertEqual(self.controller.observed(ForgedJudge()), "UNKNOWN")
        self.assertEqual(self.command("reset", judge=ForgedJudge()), "DENIED")
        self.assertTrue(self.controller.process.alive)
        self.assertEqual(self.command("approve"), "DENIED")
        self.assertEqual(self.command("start"), "DENIED")

    def test_unregistered_query_handle_cannot_authorize_reset(self):
        self.running()
        forged = MockJudge(MockQueryHandle(self.controller.process))
        forged.observe(self.controller.state["identity"])
        self.command("stop")
        self.kernel.complete_exit(self.controller.process)
        self.assertEqual(self.controller.observed(forged), "UNKNOWN")
        self.assertEqual(self.command("reset", judge=forged), "DENIED")

    def test_instance_observe_override_cannot_forge_exit(self):
        judge = self.running()
        judge.observe = lambda identity: "MOCK_VERIFIED_PRIMARY_EXIT"
        self.command("stop")
        self.assertEqual(self.command("reset", judge=judge), "DENIED")
        self.assertEqual(self.kernel.resumes, 1)

    def test_originating_canary_has_distinct_allocation(self):
        allocations = []
        original = MockKernel.spawn_suspended

        def capture(kernel, *args, **kwargs):
            process = original(kernel, *args, **kwargs)
            allocations.append(process.identity["allocation"])
            return process

        with patch.object(MockKernel, "spawn_suspended", capture):
            run(self.path.parent / "distinct-canary")
        self.assertEqual(allocations.count("B"), 2)

    def test_target_stop_cannot_affect_kernel_owned_b_job(self):
        self.running()
        other_job = self.kernel.create_job()
        other = self.kernel.spawn_suspended(other_job, 1, self.controller.config_hash,
                                             atomic_job=True, inherit=False, allocation="B")
        self.kernel.resume(other)
        self.assertEqual(self.command("stop", allocation="B"), "DENIED")
        self.command("stop")
        self.controller.crash()
        self.assertTrue(other.alive)
        self.assertFalse(other.suspended)
        self.assertFalse(other_job.closed)

    def test_equality_impostor_cannot_supply_human_principal(self):
        class Impostor:
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        self.running()
        row = self.controller.state
        self.assertEqual(self.controller.command(Impostor(), "stop", allocation="A",
                         generation=row["generation"], epoch=row["epoch"],
                         sequence=row["sequence"] + 1), "DENIED")
        self.assertEqual(self.kernel.terminations, 0)

    def test_malformed_strings_rejected_before_comparison_or_hash(self):
        class Explosive:
            def __eq__(self, other):
                raise AssertionError("untrusted equality invoked")

            def __hash__(self):
                raise AssertionError("untrusted hash invoked")

        class StringSubclass(str):
            pass

        self.running()
        for field in ("principal", "operation", "allocation"):
            for invalid in (Explosive(), [], {}, StringSubclass("human"), "x" * 1000, None):
                row = self.controller.state
                args = {"principal": "human", "operation": "stop", "allocation": "A",
                        "generation": row["generation"], "epoch": row["epoch"],
                        "sequence": row["sequence"] + 1}
                args[field] = invalid
                self.assertEqual(self.controller.command(**args), "DENIED")
        self.assertEqual(self.kernel.terminations, 0)

    def test_imports_and_journey_have_no_native_execution_or_optimizable_assertions(self):
        for name in ("windows_vm_controller.py", "windows_vm_lab.py"):
            tree = ast.parse((ROOT / "experiments/human_override" / name).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse({alias.name for alias in node.names} & {
                        "ctypes", "subprocess", "socket", "multiprocessing"})
                if isinstance(node, ast.ImportFrom):
                    self.assertNotIn(node.module, {"ctypes", "subprocess", "socket", "multiprocessing"})
                self.assertNotIsInstance(node, ast.Assert)

    def test_originating_cli_and_existing_output_refusal(self):
        lab = ROOT / "experiments/human_override/windows_vm_lab.py"
        output = self.path.parent / "journey"
        with (
            patch.object(sys, "argv", [str(lab), "--output", str(output)]),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as status,
        ):
            runpy.run_path(str(lab), run_name="__main__")
        self.assertEqual(status.exception.code, 0)
        result = json.loads((output / "result.json").read_text())
        self.assertEqual(result["evidence_class"], "MOCK_ONLY")
        self.assertFalse(result["native_adapter"])
        self.assertTrue(all(case["canary_unchanged_and_running"] for case in result["cases"]))
        with (
            patch.object(sys, "argv", [str(lab), "--output", str(output)]),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as status,
        ):
            runpy.run_path(str(lab), run_name="__main__")
        self.assertEqual(status.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
