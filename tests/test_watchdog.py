from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.watchdog import _kill_target


class WatchdogTests(unittest.TestCase):
    def test_collection_after_kill_write_is_successful_empty_containment(self) -> None:
        path = Path("/definitely-absent-eggcracker-cgroup")
        with patch("lumi_eggcracker.watchdog._write") as write, patch(
            "lumi_eggcracker.watchdog._events",
            side_effect=JsonInputError("cannot inspect watchdog cgroup"),
        ):
            result = _kill_target(path)
        write.assert_called_once_with(path, "cgroup.kill", b"1\n")
        self.assertEqual(0, result["populated"])
        self.assertTrue(result["collected"])

