from __future__ import annotations

import ast
import builtins
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Self
from unittest.mock import patch

from lumi_eggcracker import observe_first

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "examples" / "observe-first"


def _input() -> dict[str, object]:
    return {
        "schema_version": observe_first.SCHEMA,
        "synthetic": True,
        "quiescent": True,
        "offline": True,
        "snapshot": {
            "exe_basename": "synthetic-runtime",
            "argv": ["synthetic-runtime"],
            "fd_paths": [],
            "map_basenames": [],
        },
        "evidence": {
            "MODEL_CONTENT": ["gguf-v3"],
            "MODEL_RUNTIME": ["llama-elf"],
            "MODEL_TOPOLOGY": [],
        },
    }


class ObserveFirstTests(unittest.TestCase):
    def test_parser_requires_exact_schema_and_explicit_flags(self) -> None:
        value = _input()
        self.assertEqual("content.gguf-llama", observe_first.evaluate(observe_first.parse_input(value))["match"]["profile"])  # type: ignore[index]
        for flag in ("synthetic", "quiescent", "offline"):
            invalid = _input()
            invalid[flag] = False
            with self.subTest(flag=flag), self.assertRaises(observe_first.ObserveFirstInputError):
                observe_first.parse_input(invalid)
        invalid = _input()
        invalid["unexpected"] = True
        with self.assertRaises(observe_first.ObserveFirstInputError):
            observe_first.parse_input(invalid)

    def test_parser_rejects_bounds_and_duplicate_arrays(self) -> None:
        invalid = _input()
        invalid["snapshot"] = {
            "exe_basename": "synthetic-runtime",
            "argv": ["synthetic-runtime"] * (observe_first.MAX_ARRAY_ITEMS + 1),
            "fd_paths": [],
            "map_basenames": [],
        }
        with self.assertRaises(observe_first.ObserveFirstInputError):
            observe_first.parse_input(invalid)
        invalid = _input()
        invalid["evidence"] = {
            "MODEL_CONTENT": ["gguf-v3", "gguf-v3"],
            "MODEL_RUNTIME": ["llama-elf"],
            "MODEL_TOPOLOGY": [],
        }
        with self.assertRaises(observe_first.ObserveFirstInputError):
            observe_first.parse_input(invalid)
        invalid = _input()
        invalid["snapshot"] = {
            "exe_basename": "../unsafe",
            "argv": ["synthetic-runtime"],
            "fd_paths": [],
            "map_basenames": [],
        }
        with self.assertRaises(observe_first.ObserveFirstInputError):
            observe_first.parse_input(invalid)

    def test_evaluate_rejects_unknown_and_wrong_group_evidence(self) -> None:
        cases = (
            {
                "MODEL_CONTENT": ["unknown-evidence"],
                "MODEL_RUNTIME": ["llama-elf"],
                "MODEL_TOPOLOGY": [],
            },
            {
                "MODEL_CONTENT": ["gguf-v3"],
                "MODEL_RUNTIME": ["gguf-v3"],
                "MODEL_TOPOLOGY": [],
            },
        )
        for evidence in cases:
            with self.subTest(evidence=evidence):
                value = _input()
                value["evidence"] = evidence
                observation = observe_first.parse_input(value)
                with self.assertRaises(observe_first.ObserveFirstInputError):
                    observe_first.evaluate(observation)

    def test_duplicate_keys_and_oversized_input_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":"lumi-eggcracker.observe-first.v1",'
                '"schema_version":"private-value"}',
                encoding="utf-8",
            )
            with self.assertRaises(observe_first.ObserveFirstInputError):
                observe_first.load_input(duplicate)
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (observe_first.MAX_INPUT_BYTES + 1))
            with self.assertRaises(observe_first.ObserveFirstInputError):
                observe_first.load_input(oversized)

    def test_bounded_read_rejects_growth_and_post_read_metadata_drift(self) -> None:
        class BoundedReader:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.limit: int | None = None

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, limit: int) -> bytes:
                self.limit = limit
                return self.payload[:limit]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "input.json"
            target.write_text(json.dumps(_input()), encoding="utf-8")
            metadata = target.lstat()
            oversized_reader = BoundedReader(b"{" + b"x" * observe_first.MAX_INPUT_BYTES)
            with (
                patch.object(Path, "open", return_value=oversized_reader),
                patch.object(Path, "lstat", side_effect=[metadata, metadata]),
                self.assertRaises(observe_first.ObserveFirstInputError),
            ):
                observe_first.load_input(target)
            self.assertEqual(observe_first.MAX_INPUT_BYTES + 1, oversized_reader.limit)

            replacement = root / "replacement.json"
            replacement.write_text(json.dumps(_input()), encoding="utf-8")
            drift_reader = BoundedReader(target.read_bytes())
            with (
                patch.object(Path, "open", return_value=drift_reader),
                patch.object(Path, "lstat", side_effect=[metadata, replacement.lstat()]),
                self.assertRaises(observe_first.ObserveFirstInputError),
            ):
                observe_first.load_input(target)

            changed_times = list(metadata)
            changed_times[8] += 1
            changed_times[9] += 1
            same_size_drift = os.stat_result(changed_times)
            metadata_reader = BoundedReader(target.read_bytes())
            with (
                patch.object(Path, "open", return_value=metadata_reader),
                patch.object(Path, "lstat", side_effect=[metadata, same_size_drift]),
                self.assertRaises(observe_first.ObserveFirstInputError),
            ):
                observe_first.load_input(target)

    def test_only_regular_non_symlink_files_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "folder"
            folder.mkdir()
            with self.assertRaises(observe_first.ObserveFirstInputError):
                observe_first.load_input(folder)
            target = root / "target.json"
            target.write_text(json.dumps(_input()), encoding="utf-8")
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this host")
            with self.assertRaises(observe_first.ObserveFirstInputError):
                observe_first.load_input(link)
            self.assertTrue(stat.S_ISREG(target.lstat().st_mode))

    def test_results_are_deterministic_and_always_inert(self) -> None:
        observation = observe_first.parse_input(_input())
        first = observe_first.evaluate(observation)
        second = observe_first.evaluate(observation)
        self.assertEqual(first, second)
        self.assertEqual("WOULD_ACT", first["result"])
        self.assertTrue(first["simulation_only"])
        self.assertTrue(first["offline_only"])
        self.assertFalse(first["actuation_performed"])
        self.assertTrue(first["non_match_not_safety"])
        self.assertIn("No live observation", first["limitations"][0])  # type: ignore[index]

        incomplete = _input()
        incomplete["evidence"] = {
            "MODEL_CONTENT": ["gguf-v3"],
            "MODEL_RUNTIME": [],
            "MODEL_TOPOLOGY": [],
        }
        no_match = observe_first.evaluate(observe_first.parse_input(incomplete))
        self.assertEqual("NO_COMPLETE_MATCH", no_match["result"])
        self.assertIsNone(no_match["match"])

    def test_fixture_commands_emit_expected_results_without_output_files(self) -> None:
        environment = os.environ.copy()
        # Mirrors the documented ``PYTHONPATH=src`` source-checkout command.
        environment["PYTHONPATH"] = "src"
        output_before = {path for path in FIXTURE_DIR.iterdir()}
        for filename, expected in (
            ("benign.json", "NO_COMPLETE_MATCH"),
            ("complete-match.json", "WOULD_ACT"),
        ):
            with self.subTest(filename=filename):
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "lumi_eggcracker.observe_first",
                        str(FIXTURE_DIR / filename),
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(expected, json.loads(completed.stdout)["result"])
                self.assertEqual("", completed.stderr)
        output_after = {path for path in FIXTURE_DIR.iterdir()}
        self.assertEqual(output_before, output_after)

    def test_cli_rejects_deep_json_without_traceback(self) -> None:
        depth = (observe_first.MAX_INPUT_BYTES - 1) // 2
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "deep.json"
            target.write_text("[" * depth + "0" + "]" * depth, encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = "src"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lumi_eggcracker.observe_first",
                    str(target),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertTrue(completed.stderr.startswith("observe-first input rejected"))
        self.assertNotIn("Traceback", completed.stderr)
        self.assertLessEqual(len(completed.stderr), 256)

    def test_real_evaluation_stays_inert_with_scoped_guards(self) -> None:
        real_import = builtins.__import__
        forbidden_modules = {"os", "socket", "signal", "subprocess", "ctypes", "multiprocessing"}

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.partition(".")[0] in forbidden_modules:
                raise AssertionError(f"forbidden import attempted: {name}")
            return real_import(name, globals, locals, fromlist, level)

        def deny(*_args, **_kwargs):
            raise AssertionError("forbidden side effect attempted")

        real_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise AssertionError("filesystem mutation attempted")
            return real_open(file, mode, *args, **kwargs)

        # These are scoped Python-level guards, not a claim about indirect imports,
        # native code, or a security audit.
        with ExitStack() as stack:
            for name in (
                "kill",
                "killpg",
                "system",
                "popen",
                "remove",
                "unlink",
                "rename",
                "replace",
                "mkdir",
                "makedirs",
                "rmdir",
                "link",
                "symlink",
                "chmod",
                "utime",
                "execv",
                "execve",
                "execvp",
                "execvpe",
            ):
                stack.enter_context(patch.object(os, name, side_effect=deny, create=True))
            for name in ("socket", "create_connection", "create_server", "socketpair", "fromfd"):
                stack.enter_context(patch.object(socket, name, side_effect=deny, create=True))
            for name in ("signal", "raise_signal", "pthread_kill", "setitimer", "alarm"):
                stack.enter_context(patch.object(signal, name, side_effect=deny, create=True))
            for name in ("Popen", "run", "call", "check_call", "check_output"):
                stack.enter_context(patch.object(subprocess, name, side_effect=deny, create=True))
            for name in (
                "write_text",
                "write_bytes",
                "mkdir",
                "unlink",
                "rename",
                "replace",
                "rmdir",
                "touch",
                "symlink_to",
                "hardlink_to",
                "chmod",
                "lchmod",
            ):
                stack.enter_context(patch.object(Path, name, side_effect=deny, create=True))
            stack.enter_context(patch.object(builtins, "open", side_effect=guarded_open))
            stack.enter_context(patch.object(builtins, "__import__", side_effect=guarded_import))
            observation = observe_first.load_input(FIXTURE_DIR / "complete-match.json")
            result = observe_first.evaluate(observation)

        self.assertEqual("WOULD_ACT", result["result"])
        self.assertEqual("content.gguf-llama", result["match"]["profile"])  # type: ignore[index]

    def test_module_ast_has_no_process_or_enforcement_route(self) -> None:
        source_path = ROOT / "src" / "lumi_eggcracker" / "observe_first.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden = {"os", "socket", "signal", "subprocess", "ctypes", "multiprocessing"}
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(forbidden.isdisjoint(imported))
        self.assertNotIn("lumi_eggcracker", {name for name in imported if name != "detectors"})
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"kill", "terminate", "send", "connect", "write_text", "write_bytes"})


if __name__ == "__main__":
    unittest.main()
