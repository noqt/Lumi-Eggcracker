from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from lumi_eggcracker.artifacts import from_argv_paths
from lumi_eggcracker.discovery import identity
from lumi_eggcracker.jsonio import JsonInputError
from lumi_eggcracker.procfd import open_process_fd


@unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "requires POSIX FIFOs")
class ProcessDescriptorTests(unittest.TestCase):
    def test_fifo_argv_path_cannot_block_discovery(self) -> None:
        """An untrusted absolute argv path must be opened nonblocking."""
        with tempfile.TemporaryDirectory() as raw:
            fifo = Path(raw) / "hostile-argv"
            os.mkfifo(fifo, mode=0o600)
            keeper = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            target_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            os.close(keeper)
            snapshot = type("Snapshot", (), {"argv": (str(fifo),)})()
            outcome: dict[str, object] = {}

            def probe() -> None:
                try:
                    outcome["evidence"] = from_argv_paths(snapshot)
                except (JsonInputError, OSError) as error:
                    outcome["error"] = error

            worker = threading.Thread(target=probe, daemon=True)
            writer = -1
            worker.start()
            worker.join(timeout=0.5)
            blocked = worker.is_alive()
            if blocked:
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                worker.join(timeout=1.0)
            try:
                self.assertFalse(blocked, "opening an argv FIFO blocked discovery")
                self.assertEqual((), outcome.get("evidence"))
                self.assertNotIn("error", outcome)
            finally:
                if writer >= 0:
                    os.close(writer)
                os.close(target_fd)

    def test_fifo_descriptor_reopen_cannot_block_discovery(self) -> None:
        """A hostile FIFO descriptor must not stop autonomous scan progress."""
        with tempfile.TemporaryDirectory() as raw:
            fifo = Path(raw) / "hostile-fd"
            os.mkfifo(fifo, mode=0o600)
            keeper = os.open(fifo, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
            target_fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            os.close(keeper)
            process = identity(os.getpid())
            self.assertIsNotNone(process)
            assert process is not None

            outcome: dict[str, object] = {}

            def probe() -> None:
                try:
                    outcome["descriptor"] = open_process_fd(process, target_fd)[0]
                except (JsonInputError, OSError) as error:
                    outcome["error"] = error

            worker = threading.Thread(target=probe, daemon=True)
            writer = -1
            worker.start()
            worker.join(timeout=0.5)
            blocked = worker.is_alive()
            if blocked:
                # Unblock an unfixed implementation so this regression cannot
                # strand the test process after reporting the failure.
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                worker.join(timeout=1.0)
            try:
                self.assertFalse(blocked, "reopening a FIFO descriptor blocked discovery")
                self.assertNotIn("error", outcome)
            finally:
                descriptor = outcome.get("descriptor")
                if isinstance(descriptor, int):
                    os.close(descriptor)
                if writer >= 0:
                    os.close(writer)
                os.close(target_fd)


if __name__ == "__main__":
    unittest.main()
