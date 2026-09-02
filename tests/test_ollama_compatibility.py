from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lumi_eggcracker import elfmarkers
from lumi_eggcracker.elfmarkers import (
    OLLAMA_LAUNCHER_EVIDENCE_ID,
    OLLAMA_RUNNER_EVIDENCE_ID,
    RuntimeEvidence,
)

SPEC = importlib.util.spec_from_file_location(
    "check_ollama_compatibility",
    ROOT / "scripts" / "check_ollama_compatibility.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Ollama compatibility script")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def build_id_elf(identifier: bytes) -> bytes:
    note = struct.pack("<III", 4, len(identifier), 3) + b"GNU\0" + identifier
    note += b"\0" * ((4 - len(identifier) % 4) % 4)
    note_offset = 192
    body = bytearray(note_offset + len(note))
    body[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body[16:64] = struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        2,
        0,
        0,
        0,
    )
    body[64:120] = struct.pack(
        "<IIQQQQQQ", 1, 5, 0, 0, 0, len(body), len(body), 0x1000
    )
    body[120:176] = struct.pack(
        "<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(note), len(note), 4
    )
    body[note_offset:] = note
    return bytes(body)


def evidence(evidence_id: str) -> RuntimeEvidence:
    return RuntimeEvidence(evidence_id, "Ollama", "SHA256", ())


class OllamaCompatibilityTests(unittest.TestCase):
    def test_exact_launcher_and_runner_pair_is_supported_without_path_disclosure(self) -> None:
        launcher_id = bytes.fromhex("11" * 20)
        runner_id = bytes.fromhex("22" * 20)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            launcher = root / "renamed-a"
            runner = root / "renamed-b"
            launcher.write_bytes(build_id_elf(launcher_id))
            runner.write_bytes(build_id_elf(runner_id))
            with (
                mock.patch.object(
                    elfmarkers, "PINNED_OLLAMA_LAUNCHER_BUILD_IDS", {launcher_id.hex()}
                ),
                mock.patch.object(
                    elfmarkers,
                    "PINNED_OLLAMA_LAUNCHER_FILES",
                    {
                        launcher_id.hex(): (
                            launcher.stat().st_size,
                            hashlib.sha256(launcher.read_bytes()).hexdigest(),
                        )
                    },
                ),
                mock.patch.object(
                    elfmarkers, "PINNED_OLLAMA_RUNNER_BUILD_IDS", {runner_id.hex()}
                ),
                mock.patch.object(
                    elfmarkers,
                    "PINNED_OLLAMA_RUNNER_FILES",
                    {
                        runner_id.hex(): (
                            runner.stat().st_size,
                            hashlib.sha256(runner.read_bytes()).hexdigest(),
                        )
                    },
                ),
            ):
                result = checker.compatibility(launcher, runner)
                runner.write_bytes(build_id_elf(runner_id) + b"tampered")
                tampered = checker.compatibility(launcher, runner)
        self.assertEqual("SUPPORTED", result["result"])
        self.assertEqual("content.gguf-ollama", result["target_profile"])
        self.assertEqual(
            {
                "checks",
                "limitations",
                "result",
                "schema_version",
                "target_profile",
                "version",
            },
            set(result),
        )
        self.assertNotIn(str(launcher), json.dumps(result))
        self.assertNotIn(str(runner), json.dumps(result))
        self.assertEqual("UNSUPPORTED", tampered["result"])

    def test_partial_or_role_swapped_pair_is_unsupported(self) -> None:
        launcher = Path("/opt/ollama/launcher")
        runner = Path("/opt/ollama/runner")
        values = {
            launcher: evidence(OLLAMA_RUNNER_EVIDENCE_ID),
            runner: evidence(OLLAMA_LAUNCHER_EVIDENCE_ID),
        }
        with mock.patch.object(checker, "_inspect_regular_path", side_effect=values.get):
            result = checker.compatibility(launcher, runner)
        self.assertEqual("UNSUPPORTED", result["result"])
        self.assertEqual("UNSUPPORTED", result["checks"]["launcher_identity"])
        self.assertEqual("UNSUPPORTED", result["checks"]["runner_identity"])

    def test_name_only_files_are_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            launcher = root / "ollama"
            runner = root / "ollama-runner"
            launcher.write_bytes(b"not an authenticated ELF")
            runner.write_bytes(b"not an authenticated ELF")
            result = checker.compatibility(launcher, runner)
        self.assertEqual("UNSUPPORTED", result["result"])

    def test_non_regular_inputs_are_rejected_before_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            regular = root / "regular"
            regular.write_bytes(b"ordinary")
            missing = root / "missing"
            directory = root / "directory"
            directory.mkdir()
            symlink = root / "symlink"
            try:
                symlink.symlink_to(regular)
            except OSError:
                symlink = None
            paths = [missing, directory]
            if symlink is not None:
                paths.append(symlink)
            with mock.patch.object(checker, "inspect_ollama_descriptor") as inspect:
                for path in paths:
                    with self.subTest(path=path.name):
                        self.assertIsNone(checker._inspect_regular_path(path))
                inspect.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_fifo_is_rejected_without_opening_for_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fifo = Path(raw) / "hostile-fifo"
            try:
                os.mkfifo(fifo, mode=0o600)
            except OSError as error:
                self.skipTest(f"temporary filesystem cannot create FIFOs: {error}")
            with mock.patch.object(checker, "inspect_ollama_descriptor") as inspect:
                self.assertIsNone(checker._inspect_regular_path(fifo))
                inspect.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "device nodes require POSIX")
    def test_device_is_rejected_without_opening_for_authentication(self) -> None:
        device = Path("/dev/null")
        with mock.patch.object(checker, "inspect_ollama_descriptor") as inspect:
            self.assertIsNone(checker._inspect_regular_path(device))
            inspect.assert_not_called()

    def test_main_returns_bounded_json_and_nonzero_for_unsupported_pair(self) -> None:
        result = {
            "checks": {
                "launcher_identity": "UNSUPPORTED",
                "runner_identity": "UNSUPPORTED",
            },
            "limitations": ["BINARY_IDENTITY_ONLY"],
            "result": "UNSUPPORTED",
            "schema_version": checker.SCHEMA,
            "target_profile": checker.PROFILE,
            "version": "1.0.10",
        }
        for state, expected in (("SUPPORTED", 0), ("UNSUPPORTED", 2)):
            with self.subTest(state=state):
                output = io.StringIO()
                value = {**result, "result": state}
                with (
                    mock.patch.object(checker, "compatibility", return_value=value),
                    contextlib.redirect_stdout(output),
                ):
                    return_code = checker.main(
                        [
                            "--launcher",
                            str(ROOT / "launcher"),
                            "--runner",
                            str(ROOT / "runner"),
                        ]
                    )
                self.assertEqual(expected, return_code)
                self.assertEqual(state, json.loads(output.getvalue())["result"])

    def test_documented_isolated_entrypoint_is_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            launcher = root / "private-launcher-name"
            runner = root / "private-runner-name"
            launcher.write_bytes(b"not an authenticated ELF")
            runner.write_bytes(b"not an authenticated ELF")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    "-S",
                    str(ROOT / "scripts" / "check_ollama_compatibility.py"),
                    "--launcher",
                    str(launcher),
                    "--runner",
                    str(runner),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(2, completed.returncode)
            value = json.loads(completed.stdout)
            self.assertEqual("UNSUPPORTED", value["result"])
            self.assertEqual(
                {
                    "checks",
                    "limitations",
                    "result",
                    "schema_version",
                    "target_profile",
                    "version",
                },
                set(value),
            )
            self.assertEqual("", completed.stderr)
            combined = completed.stdout + completed.stderr
            self.assertNotIn(str(launcher), combined)
            self.assertNotIn(str(runner), combined)

    def test_documented_entrypoint_rejects_relative_paths(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-S",
                str(ROOT / "scripts" / "check_ollama_compatibility.py"),
                "--launcher",
                "relative-private-launcher",
                "--runner",
                str(ROOT / "runner"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn("Ollama binary paths must be absolute", completed.stderr)
        self.assertNotIn("relative-private-launcher", completed.stderr)


if __name__ == "__main__":
    unittest.main()
