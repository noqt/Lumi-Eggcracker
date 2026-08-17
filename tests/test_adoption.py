from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import adoption
from lumi_eggcracker.adoption import QuarantineIdentity, children, contain_many, descendants
from lumi_eggcracker.discovery import ProcessIdentity
from lumi_eggcracker.jsonio import JsonInputError


def stat(pid: int, parent: int, start: int) -> str:
    return f"{pid} (fixture) S {parent} " + "0 " * 17 + f"{start}\n"


class AdoptionTests(unittest.TestCase):
    def test_missing_delegated_quarantine_root_is_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw) / "lumi-eggcracker.service"
            parent.mkdir()
            for name in ("cgroup.events", "cgroup.kill", "cgroup.procs"):
                (parent / name).touch()
            root = parent / "quarantine"
            event_id = "a" * 24

            original_mkdir = Path.mkdir

            def materialize_controls(path: Path, *args: object, **kwargs: object) -> None:
                original_mkdir(path, *args, **kwargs)
                if path == root or path == root / event_id:
                    for name in ("cgroup.events", "cgroup.kill", "cgroup.procs"):
                        (path / name).touch()

            with patch.object(Path, "mkdir", autospec=True, side_effect=materialize_controls):
                identity_value = adoption.create_quarantine(root, event_id)

            self.assertTrue(root.is_dir())
            self.assertEqual(root / event_id, identity_value.path)

    def test_quarantine_root_recovery_rejects_an_arbitrary_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "quarantine"
            with self.assertRaisesRegex(JsonInputError, "parent is invalid"):
                adoption._ensure_quarantine_root(root)

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
                entry = proc / str(pid)
                (entry / "task" / str(pid)).mkdir(parents=True)
                (entry / "stat").write_text(stat(pid, parent, start), encoding="ascii")
            (proc / "10" / "task" / "10" / "children").write_text("11 12\n", encoding="ascii")
            (proc / "11" / "task" / "11" / "children").write_text("", encoding="ascii")
            (proc / "12" / "task" / "12" / "children").write_text("", encoding="ascii")
            root = ProcessIdentity(10, 100)
            self.assertEqual({ProcessIdentity(11, 101), ProcessIdentity(12, 102)}, children(root, proc=proc))
            self.assertEqual({root, ProcessIdentity(11, 101), ProcessIdentity(12, 102)}, descendants({root}, proc=proc))

    def test_contain_many_binds_all_evidence_roots_before_kill(self) -> None:
        first = ProcessIdentity(10, 100)
        second = ProcessIdentity(11, 101)
        roots = {first, second}
        identity = QuarantineIdentity(Path("/quarantine/aa"), 1, 2, "a" * 24)
        proof = adoption.EmptyProof(True, 1, 0, [])
        with patch.object(adoption, "open_pidfd", side_effect=[17, 18]) as opened, patch.object(adoption, "stop_pidfd", side_effect=[20, 21]) as stopped, patch.object(adoption, "stop"), patch.object(adoption, "descendants", side_effect=[roots, roots, roots, roots]), patch.object(adoption, "_move"), patch.object(adoption, "create_quarantine", return_value=identity), patch.object(adoption, "_validate", return_value=identity.path), patch.object(adoption, "kill_path", return_value=(30, 31)), patch.object(adoption, "verify_empty", return_value=(32, proof)), patch.object(adoption, "_remove"), patch.object(adoption.os, "close") as close:
            result = contain_many(roots, Path("/quarantine"), "a" * 24)
        self.assertEqual(roots, set(result.roots))
        self.assertEqual(2, opened.call_count)
        self.assertEqual(2, stopped.call_count)
        self.assertEqual({17, 18}, {call.args[0] for call in close.call_args_list})

    def test_containment_faults_cannot_return_a_success_result(self) -> None:
        target = ProcessIdentity(10, 100)
        identity = QuarantineIdentity(Path("/quarantine/aa"), 1, 2, "a" * 24)
        proof = adoption.EmptyProof(False, 1, 1, [10])

        def invoke(*, kill_error: bool, empty: adoption.EmptyProof | None = None):
            with ExitStack() as stack:
                for current in (
                    patch.object(adoption, "open_pidfd", return_value=17),
                    patch.object(adoption, "stop_pidfd", return_value=20),
                    patch.object(adoption, "stop"),
                    patch.object(adoption, "descendants", return_value={target}),
                    patch.object(adoption, "_move", return_value=True),
                    patch.object(adoption, "create_quarantine", return_value=identity),
                    patch.object(adoption, "_validate", return_value=identity.path),
                    patch.object(adoption, "_remove"),
                    patch.object(adoption, "_kill"),
                    patch.object(adoption.os, "close"),
                ):
                    stack.enter_context(current)
                stack.enter_context(
                    patch.object(
                        adoption,
                        "kill_path",
                        side_effect=OSError("cgroup.kill failed")
                        if kill_error
                        else None,
                        return_value=None if kill_error else (30, 31),
                    )
                )
                if empty is not None:
                    stack.enter_context(
                        patch.object(adoption, "verify_empty", return_value=(32, empty))
                    )
                return contain_many({target}, Path("/quarantine"), "a" * 24)

        with self.assertRaises(OSError):
            invoke(kill_error=True)
        with self.assertRaisesRegex(JsonInputError, "did not become empty"):
            invoke(kill_error=False, empty=proof)
