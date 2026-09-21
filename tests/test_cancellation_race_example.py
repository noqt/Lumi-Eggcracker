from __future__ import annotations

import importlib.util
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cancellation_race_example.py"
SPEC = importlib.util.spec_from_file_location("cancellation_race_example", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
example = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = example
SPEC.loader.exec_module(example)


class CancellationRaceExampleTests(unittest.TestCase):
    def _early_stack(self, stack: ExitStack) -> None:
        stack.enter_context(patch.object(example.probe, "_host_preflight"))
        stack.enter_context(patch.object(example, "_check_no_active_service"))
        stack.enter_context(
            patch.object(
                example,
                "_source_identity",
                return_value=("a" * 40, "b" * 64, "c" * 40, "d" * 64),
            )
        )
        stack.enter_context(patch.object(example.probe.secrets, "token_hex", return_value="e" * 32))
        stack.enter_context(patch.object(example.probe, "_assert_owner_available"))

    def test_worker_has_one_bounded_post_cancel_fork(self) -> None:
        compile(example.CANCELLATION_TARGET_CODE, "<cancellation-race-target>", "exec")
        self.assertEqual(1, example.CANCELLATION_TARGET_CODE.count("os.fork()"))
        self.assertIn("CANCEL_STARTED", example.CANCELLATION_TARGET_CODE)
        self.assertIn("os.read(fork_gate, 1) != b'F'", example.CANCELLATION_TARGET_CODE)
        self.assertEqual(1, example.MAX_CHILDREN)

    def test_outer_runtime_and_task_limits_are_fixed(self) -> None:
        self.assertEqual(3, example.OWNER_TASK_LIMIT)
        self.assertLessEqual(example.RUN_TIMEOUT_SECONDS + example.CLEANUP_TIMEOUT_SECONDS, 30.0)
        self.assertEqual(30, example.OWNER_RUNTIME_CEILING_SECONDS)

    def test_all_controller_signals_cleanup_and_return_non_success(self) -> None:
        selected_signals = [example.signal.SIGINT, example.signal.SIGTERM]
        if hasattr(example.signal, "SIGHUP"):
            selected_signals.append(example.signal.SIGHUP)
        for selected in selected_signals:
            with self.subTest(signal=selected), ExitStack() as stack:
                self._early_stack(stack)
                handlers: dict[int, object] = {}

                def fake_signal(
                    signum: int, handler: object, *, _handlers: dict[int, object] = handlers
                ) -> object:
                    previous = _handlers.get(signum, object())
                    _handlers[signum] = handler
                    return previous

                def interrupt_owner(
                    _unit: str,
                    *,
                    _handlers: dict[int, object] = handlers,
                    _selected: int = selected,
                ) -> None:
                    handler = _handlers[_selected]
                    assert callable(handler)
                    handler(_selected, None)

                stack.enter_context(patch.object(example.signal, "signal", side_effect=fake_signal))
                stack.enter_context(patch.object(example, "_start_owner", side_effect=interrupt_owner))
                cleanup = stack.enter_context(patch.object(example.probe, "_cleanup", return_value=True))
                with self.assertRaisesRegex(example.probe.ProbeError, "INTERRUPTED"):
                    example.run_example(acknowledged=True)
                cleanup.assert_called_once()

    def test_signal_during_handler_installation_blocks_first_host_mutation(self) -> None:
        with ExitStack() as stack:
            self._early_stack(stack)
            fired = False

            def interrupt_during_install(signum: int, handler: object) -> object:
                nonlocal fired
                if not fired:
                    fired = True
                    assert callable(handler)
                    handler(signum, None)
                return object()

            stack.enter_context(
                patch.object(example.signal, "signal", side_effect=interrupt_during_install)
            )
            start_owner = stack.enter_context(patch.object(example, "_start_owner"))
            cleanup = stack.enter_context(patch.object(example.probe, "_cleanup", return_value=True))
            with self.assertRaisesRegex(example.probe.ProbeError, "INTERRUPTED"):
                example.run_example(acknowledged=True)
        start_owner.assert_not_called()
        cleanup.assert_called_once()

    def test_migration_check_is_bound_to_owner_membership_path(self) -> None:
        unit = f"lumi-eggcracker-probe-{'a' * 32}.service"
        owner = example.probe.ProbeCgroupIdentity(
            unit=unit,
            invocation_id="b" * 32,
            control_group=f"/system.slice/{unit}",
            parent_device=1,
            parent_inode=2,
            target_device=1,
            target_inode=3,
            boot="c" * 36,
        )
        self.assertEqual(owner.parent_path / "cgroup.procs", example._parent_membership_path(owner))
        self.assertNotEqual(owner.target_path / "cgroup.procs", example._parent_membership_path(owner))
        self.assertIn("parent_procs = sys.argv[5]", example.CANCELLATION_TARGET_CODE)

    def test_action_timeout_reserves_cleanup_time(self) -> None:
        with ExitStack() as stack:
            self._early_stack(stack)
            stack.enter_context(patch.object(example.signal, "signal", return_value=object()))
            stack.enter_context(
                patch.object(
                    example,
                    "_start_owner",
                    side_effect=example.probe.ProbeError("UNIT_START_FAILED"),
                )
            )
            stack.enter_context(patch.object(example.time, "monotonic", side_effect=[100.0, 122.0]))
            cleanup = stack.enter_context(patch.object(example.probe, "_cleanup", return_value=True))
            with self.assertRaisesRegex(example.probe.ProbeError, "UNIT_START_FAILED"):
                example.run_example(acknowledged=True)
        self.assertEqual(127.0, cleanup.call_args.kwargs["deadline"])

    def test_imported_json_failure_is_redacted_after_cleanup(self) -> None:
        with ExitStack() as stack:
            self._early_stack(stack)
            stack.enter_context(patch.object(example.signal, "signal", return_value=object()))
            stack.enter_context(patch.object(example, "_start_owner"))
            stack.enter_context(
                patch.object(
                    example.probe,
                    "_capture_owner",
                    side_effect=example.JsonInputError("private detail"),
                )
            )
            cleanup = stack.enter_context(patch.object(example.probe, "_cleanup", return_value=True))
            with self.assertRaisesRegex(example.probe.ProbeError, "RACE_STAGE_FAILED") as raised:
                example.run_example(acknowledged=True)
        cleanup.assert_called_once()
        self.assertNotIn("private detail", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
