from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import containment
from lumi_eggcracker.jsonio import JsonInputError


class ContainmentTests(unittest.TestCase):
    def _root(self, temporary: Path) -> tuple[Path, str, str, str]:
        run_id = "a" * 24
        unit = f"lumi-eggcracker-workload-{run_id}.service"
        cgroup = f"/system.slice/{unit}"
        path = temporary / "system.slice" / unit
        path.mkdir(parents=True)
        (path / "cgroup.kill").write_text("", encoding="ascii")
        (path / "cgroup.events").write_text("populated 0\nfrozen 0\n", encoding="ascii")
        (path / "cgroup.procs").write_text("", encoding="ascii")
        (path / "pids.events").write_text("max 0\n", encoding="ascii")
        (path / "pids.max").write_text("8\n", encoding="ascii")
        return path, cgroup, run_id, unit

    def test_capture_kill_and_empty_proof(self) -> None:
        with tempfile.TemporaryDirectory() as raw, patch.object(containment, "boot_id", return_value="a" * 36):
            path, cgroup, run_id, unit = self._root(Path(raw))
            identity = containment.capture_identity(cgroup, run_id, unit, root=Path(raw))
            containment.kill(identity, root=Path(raw))
            _, proof = containment.verify_empty(identity, root=Path(raw))
            self.assertTrue(proof.complete)
            self.assertEqual("1\n", (path / "cgroup.kill").read_text(encoding="ascii"))

    def test_rejects_cgroup_outside_owned_namespace(self) -> None:
        with self.assertRaises(JsonInputError):
            containment.capture_identity("/user.slice/anything", "a" * 24, "bad", root=Path("."))

    def test_reapplies_direct_kill_when_a_fork_race_keeps_cgroup_populated(self) -> None:
        with tempfile.TemporaryDirectory() as raw, patch.object(containment, "boot_id", return_value="a" * 36):
            path, cgroup, run_id, unit = self._root(Path(raw))
            identity = containment.capture_identity(cgroup, run_id, unit, root=Path(raw))
            (path / "cgroup.events").write_text("populated 1\n", encoding="ascii")

            def reapplied(_: Path) -> tuple[int, int]:
                (path / "cgroup.events").write_text("populated 0\n", encoding="ascii")
                return 1, 2

            with patch.object(containment, "kill_path", side_effect=reapplied) as direct:
                _, proof = containment.verify_empty(identity, root=Path(raw))
            self.assertTrue(direct.called)
            self.assertTrue(proof.complete)

    def test_collected_cgroup_wrapped_as_json_error_is_still_an_empty_proof(self) -> None:
        with tempfile.TemporaryDirectory() as raw, patch.object(containment, "boot_id", return_value="a" * 36):
            _, cgroup, run_id, unit = self._root(Path(raw))
            identity = containment.capture_identity(cgroup, run_id, unit, root=Path(raw))
            with patch.object(containment, "_events", side_effect=JsonInputError("cannot read cgroup.events: No such file")):
                _, proof = containment.verify_empty(identity, root=Path(raw))
            self.assertTrue(proof.complete)
