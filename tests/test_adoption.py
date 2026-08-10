from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import adoption
from lumi_eggcracker.adoption import children, descendants
from lumi_eggcracker.discovery import ProcessIdentity


def stat(pid: int, parent: int, start: int) -> str:
    return f"{pid} (fixture) S {parent} " + "0 " * 17 + f"{start}\n"


class AdoptionTests(unittest.TestCase):
    def test_open_pidfd_revalidates_before_returning_descriptor(self) -> None:
        value = ProcessIdentity(10, 100)
        with patch.object(adoption, "pidfd_available", return_value=True), patch.object(adoption, "_same", return_value=True), patch.object(adoption.os, "pidfd_open", return_value=17, create=True), patch.object(adoption.os, "close") as close:
            self.assertEqual(17, adoption.open_pidfd(value))
            close.assert_not_called()

    def test_open_pidfd_closes_descriptor_when_identity_changes(self) -> None:
        value = ProcessIdentity(10, 100)
        with patch.object(adoption, "pidfd_available", return_value=True), patch.object(adoption, "_same", side_effect=[True, False]), patch.object(adoption.os, "pidfd_open", return_value=17, create=True), patch.object(adoption.os, "close") as close:
            with self.assertRaises(ProcessLookupError):
                adoption.open_pidfd(value)
            close.assert_called_once_with(17)

    def test_stop_pidfd_uses_the_held_identity_descriptor(self) -> None:
        value = ProcessIdentity(10, 100)
        with patch.object(adoption, "pidfd_available", return_value=True), patch.object(adoption, "_same", side_effect=AssertionError("held pidfd must be used")), patch.object(adoption.signal, "pidfd_send_signal", create=True) as send, patch.object(adoption.signal, "SIGSTOP", 19, create=True), patch.object(adoption.time, "monotonic_ns", return_value=42):
            self.assertEqual(42, adoption.stop_pidfd(value, 17))
        send.assert_called_once_with(17, 19)

    def test_contain_closes_held_pidfd_when_identity_vanishes(self) -> None:
        value = ProcessIdentity(10, 100)
        with tempfile.TemporaryDirectory() as raw, patch.object(adoption, "stop_pidfd", side_effect=ProcessLookupError("vanished")), patch.object(adoption, "_kill"), patch.object(adoption.os, "close") as close, self.assertRaises(ProcessLookupError):
            adoption.contain(value, Path(raw), "a" * 24, pidfd=17)
        close.assert_called_once_with(17)

    def test_descendant_walk_reads_every_task_children_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            for pid, parent, start in ((10, 1, 100), (11, 10, 101), (12, 10, 102)):
                entry = proc / str(pid); (entry / "task" / str(pid)).mkdir(parents=True)
                (entry / "stat").write_text(stat(pid, parent, start), encoding="ascii")
            (proc / "10" / "task" / "10" / "children").write_text("11 12\n", encoding="ascii")
            (proc / "11" / "task" / "11" / "children").write_text("", encoding="ascii")
            (proc / "12" / "task" / "12" / "children").write_text("", encoding="ascii")
            root = ProcessIdentity(10, 100)
            self.assertEqual({ProcessIdentity(11, 101), ProcessIdentity(12, 102)}, children(root, proc=proc))
            self.assertEqual({root, ProcessIdentity(11, 101), ProcessIdentity(12, 102)}, descendants({root}, proc=proc))
