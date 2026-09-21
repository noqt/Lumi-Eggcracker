from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cancellation_race_example.py"
SPEC = importlib.util.spec_from_file_location("cancellation_race_example", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)


class CancellationRaceExampleTests(unittest.TestCase):
    def test_worker_has_one_bounded_post_cancel_fork(self) -> None:
        compile(example.TARGET_CODE, "<cancellation-race-target>", "exec")
        self.assertEqual(1, example.TARGET_CODE.count("os.fork()"))
        self.assertIn("CANCEL_STARTED", example.TARGET_CODE)
        self.assertIn("os.read(barrier_fd, 1) != b'F'", example.TARGET_CODE)
        self.assertEqual(1, example.MAX_CHILDREN)
        self.assertEqual(30, example.WORKER_LIFETIME_SECONDS)

    def test_controller_ceiling_and_task_limit_are_fixed(self) -> None:
        self.assertEqual(20.0, example.TOTAL_TIMEOUT_SECONDS)
        self.assertEqual(3, example.OWNER_TASK_LIMIT)
        self.assertLessEqual(example.TOTAL_TIMEOUT_SECONDS, 30.0)


if __name__ == "__main__":
    unittest.main()
