from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.adoption import children, descendants
from lumi_eggcracker.discovery import ProcessIdentity


def stat(pid: int, parent: int, start: int) -> str:
    return f"{pid} (fixture) S {parent} " + "0 " * 17 + f"{start}\n"


class AdoptionTests(unittest.TestCase):
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
