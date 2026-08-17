from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.discovery import (
    ProcessIdentity,
    _map_paths,
    argv_digest,
    executable_digest_for_identity,
    identity,
    parse_stat,
    snapshot,
)
from lumi_eggcracker.jsonio import JsonInputError


class DiscoveryTests(unittest.TestCase):
    def _proc_entry(self, proc: Path, command: bytes) -> ProcessIdentity:
        entry = proc / "42"
        entry.mkdir()
        (entry / "stat").write_text(
            "42 (runner) S 1 " + "0 " * 17 + "100\n", encoding="utf-8"
        )
        (entry / "cgroup").write_text("0::/user.slice/test\n", encoding="utf-8")
        (entry / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n", encoding="utf-8")
        (entry / "cmdline").write_bytes(command)
        (entry / "fd").mkdir()
        (entry / "map_files").mkdir()
        return ProcessIdentity(42, 100)

    def test_stat_parser_handles_spaces_in_command_name(self) -> None:
        raw = "77 (worker with spaces) S 4 " + "0 " * 17 + "901\n"
        self.assertEqual((4, 901), parse_stat(raw))

    def test_stat_parser_rejects_incomplete_record(self) -> None:
        with self.assertRaises(JsonInputError):
            parse_stat("1 (bad) S 2")

    def test_argv_digest_does_not_retain_arguments(self) -> None:
        digest = argv_digest(("/usr/bin/python3", "--token", "secret"))
        self.assertEqual(64, len(digest))
        self.assertNotIn("secret", digest)

    def test_pid_identity_includes_start_time(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            entry = proc / "42"
            entry.mkdir()
            (entry / "stat").write_text("42 (x) S 1 " + "0 " * 17 + "100\n", encoding="utf-8")
            self.assertEqual(ProcessIdentity(42, 100), identity(42, proc=proc))
            (entry / "stat").write_text("42 (x) S 1 " + "0 " * 17 + "101\n", encoding="utf-8")
            self.assertEqual(ProcessIdentity(42, 101), identity(42, proc=proc))

    def test_long_maps_file_keeps_bounded_first_entries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "maps"
            path.write_text(
                "".join(
                    f"7b{i:08x}-7b{i + 1:08x} r-xp 00000000 08:30 1 /opt/runtime/{i:04d}-" + "x" * 150 + "\n"
                    for i in range(700)
                ),
                encoding="utf-8",
            )
            values = _map_paths(path)
            self.assertEqual(512, len(values))
            self.assertTrue(values[0].startswith("/opt/runtime/"))

    def test_oversized_maps_file_is_localized_to_one_empty_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "maps"
            path.write_bytes(b"x" * 64)
            with patch("lumi_eggcracker.discovery.MAX_MAP_BYTES", 16):
                self.assertEqual((), _map_paths(path))

    def test_invalid_utf8_argv_does_not_erase_process_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            value = self._proc_entry(proc, b"/usr/bin/python3\0bad\xffarg\0")
            with patch(
                "lumi_eggcracker.discovery.os.readlink", return_value="/usr/bin/python3"
            ):
                current = snapshot(value, proc=proc)
            self.assertIsNotNone(current)
            assert current is not None
            self.assertTrue(current.argv_complete)
            self.assertEqual(2, len(current.argv))
            self.assertEqual(64, len(argv_digest(current.argv)))

    def test_oversized_argv_is_unapprovable_not_invisible(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            value = self._proc_entry(proc, b"/usr/bin/python3\0" + b"x" * 64)
            with patch("lumi_eggcracker.discovery.MAX_CMDLINE_BYTES", 16), patch(
                "lumi_eggcracker.discovery.os.readlink", return_value="/usr/bin/python3"
            ):
                current = snapshot(value, proc=proc)
            self.assertIsNotNone(current)
            assert current is not None
            self.assertFalse(current.argv_complete)
            self.assertEqual((), current.argv)

    def test_process_executable_is_hashed_from_bound_proc_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc = Path(raw)
            entry = proc / "42"
            entry.mkdir()
            (entry / "stat").write_text(
                "42 (runner) S 1 " + "0 " * 17 + "100\n", encoding="utf-8"
            )
            (entry / "exe").write_bytes(b"live executable")
            digest, metadata = executable_digest_for_identity(
                ProcessIdentity(42, 100), proc=proc
            )
            self.assertEqual(64, len(digest))
            self.assertGreater(metadata.st_size, 0)
