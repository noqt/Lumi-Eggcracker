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
    PYTORCH_ATEN_EVIDENCE_ID,
    PYTORCH_BRIDGE_EVIDENCE_ID,
    VLLM_EXTENSION_EVIDENCE_ID,
    VLLM_PYTHON_EVIDENCE_ID,
    RuntimeEvidence,
)

SPEC = importlib.util.spec_from_file_location(
    "check_vllm_compatibility",
    ROOT / "scripts" / "check_vllm_compatibility.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load vLLM compatibility script")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

RESULT_KEYS = {
    "checks",
    "limitations",
    "result",
    "schema_version",
    "target_profile",
    "version",
}
SUPPORTED_CHECKS = {
    "pytorch_bridge_identity": "SUPPORTED",
    "pytorch_aten_identity": "SUPPORTED",
    "vllm_python_identity": "SUPPORTED",
    "vllm_extension_identity": "SUPPORTED",
}
LIMITATIONS = {
    "BINARY_IDENTITY_ONLY",
    "SAFETENSORS_MODEL_NOT_INSPECTED",
    "LIVE_TOPOLOGY_NOT_PROVEN",
    "EXECUTION_CONTEXT_NOT_QUALIFIED",
    "COMPATIBILITY_CHECK_NOT_CONTAINMENT_EVIDENCE",
    "COMPATIBILITY_CHECK_NOT_ADOPTION_EVIDENCE",
}


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
    return RuntimeEvidence(evidence_id, "vLLM/PyTorch", "SHA256", ())


class VllmCompatibilityTests(unittest.TestCase):
    def test_vllm_0_28_cpu_pins_extend_prior_supported_set(self) -> None:
        expected = {
            "bridge": {
                "0ba50bfa63eb5fd0dd19cabca2ee1de77c4c1398": (
                    26_113_896,
                    "b576248e3a0f6ff37de11baa3beac0e53ca1500208b9cf4974db2f3b67cfc8c5",
                ),
                "85d09b66000780cd7339d28d952751229cb33bc7": (
                    30_616_304,
                    "247efcbc423fb65aa64640b96cd51672d4863413472ed2ddded6ad57a8647c67",
                ),
            },
            "aten": {
                "ad9ab6eeec3b28a0ec3f12f266627610de90813b": (
                    433_155_401,
                    "dacb42735f5a59a8b2abbf06fe7fdeba359849a08f418ad830a84ffadc316802",
                ),
                "8ec08ec8f71de04ee2baa46c0dbe262858b1e27c": (
                    434_184_800,
                    "ae0f4bc33ffe73f4eb85b2fd03b036c68cf5ab6139995f6a2345f5962c1bbb81",
                ),
            },
            "extension": {
                "0b81145998cd6a2a1162b3ca47c1029e55061449": (
                    17_766_528,
                    "56510a6c504707d8f986a76f87225ce8026de498672aceae4fc7642bf1aa1edc",
                ),
                "d86c8add9ec525f83ff66448174bf20b7d065772": (
                    82_113_712,
                    "46c04a0e0b245d5438181e9e8335cf5a5445f00c1615962a4b414f844c74dd31",
                ),
            },
        }
        for role, build_ids, files in (
            (
                "bridge",
                elfmarkers.PINNED_PYTORCH_BRIDGE_BUILD_IDS,
                elfmarkers.PINNED_PYTORCH_BRIDGE_FILES,
            ),
            (
                "aten",
                elfmarkers.PINNED_PYTORCH_ATEN_BUILD_IDS,
                elfmarkers.PINNED_PYTORCH_ATEN_FILES,
            ),
            (
                "extension",
                elfmarkers.PINNED_VLLM_EXTENSION_BUILD_IDS,
                elfmarkers.PINNED_VLLM_EXTENSION_FILES,
            ),
        ):
            with self.subTest(role=role):
                self.assertLessEqual(expected[role].keys(), build_ids)
                for build_id, identity in expected[role].items():
                    self.assertEqual(identity, files[build_id])

    def test_exact_four_role_set_is_supported_and_tamper_fails_closed(self) -> None:
        identities = {
            "pytorch_bridge": bytes.fromhex("11" * 20),
            "pytorch_aten": bytes.fromhex("22" * 20),
            "vllm_python": bytes.fromhex("33" * 20),
            "vllm_extension": bytes.fromhex("44" * 20),
        }
        pin_names = {
            "pytorch_bridge": (
                "PINNED_PYTORCH_BRIDGE_BUILD_IDS",
                "PINNED_PYTORCH_BRIDGE_FILES",
            ),
            "pytorch_aten": (
                "PINNED_PYTORCH_ATEN_BUILD_IDS",
                "PINNED_PYTORCH_ATEN_FILES",
            ),
            "vllm_python": (
                "PINNED_VLLM_PYTHON_BUILD_IDS",
                "PINNED_VLLM_PYTHON_FILES",
            ),
            "vllm_extension": (
                "PINNED_VLLM_EXTENSION_BUILD_IDS",
                "PINNED_VLLM_EXTENSION_FILES",
            ),
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {role: root / f"renamed-{index}" for index, role in enumerate(identities)}
            for role, path in paths.items():
                path.write_bytes(build_id_elf(identities[role]))
            with contextlib.ExitStack() as stack:
                for role, (build_ids_name, files_name) in pin_names.items():
                    identifier = identities[role].hex()
                    path = paths[role]
                    stack.enter_context(
                        mock.patch.object(elfmarkers, build_ids_name, {identifier})
                    )
                    stack.enter_context(
                        mock.patch.object(
                            elfmarkers,
                            files_name,
                            {
                                identifier: (
                                    path.stat().st_size,
                                    hashlib.sha256(path.read_bytes()).hexdigest(),
                                )
                            },
                        )
                    )
                result = checker.compatibility(**paths)
                paths["vllm_extension"].write_bytes(
                    build_id_elf(identities["vllm_extension"]) + b"tampered"
                )
                tampered = checker.compatibility(**paths)
        self.assertEqual("SUPPORTED", result["result"])
        self.assertEqual("content.safetensors-vllm", result["target_profile"])
        self.assertEqual(RESULT_KEYS, set(result))
        self.assertEqual(SUPPORTED_CHECKS, result["checks"])
        self.assertEqual(LIMITATIONS, set(result["limitations"]))
        for path in paths.values():
            self.assertNotIn(str(path), json.dumps(result))
        self.assertEqual("UNSUPPORTED", tampered["result"])
        self.assertEqual(
            "UNSUPPORTED", tampered["checks"]["vllm_extension_identity"]
        )

    def test_role_swapped_set_is_unsupported(self) -> None:
        paths = {
            "pytorch_bridge": Path("/opt/vllm/bridge"),
            "pytorch_aten": Path("/opt/vllm/aten"),
            "vllm_python": Path("/opt/vllm/python"),
            "vllm_extension": Path("/opt/vllm/extension"),
        }
        swapped = {
            paths["pytorch_bridge"]: evidence(PYTORCH_ATEN_EVIDENCE_ID),
            paths["pytorch_aten"]: evidence(PYTORCH_BRIDGE_EVIDENCE_ID),
            paths["vllm_python"]: evidence(VLLM_EXTENSION_EVIDENCE_ID),
            paths["vllm_extension"]: evidence(VLLM_PYTHON_EVIDENCE_ID),
        }
        with mock.patch.object(
            checker,
            "_inspect_regular_path",
            side_effect=lambda path, _inspector: swapped[path],
        ):
            result = checker.compatibility(**paths)
        self.assertEqual("UNSUPPORTED", result["result"])
        self.assertTrue(
            all(value == "UNSUPPORTED" for value in result["checks"].values())
        )

    def test_each_of_the_four_roles_is_individually_mandatory(self) -> None:
        paths = {
            "pytorch_bridge": Path("/opt/vllm/bridge"),
            "pytorch_aten": Path("/opt/vllm/aten"),
            "vllm_python": Path("/opt/vllm/python"),
            "vllm_extension": Path("/opt/vllm/extension"),
        }
        correct = {
            paths["pytorch_bridge"]: evidence(PYTORCH_BRIDGE_EVIDENCE_ID),
            paths["pytorch_aten"]: evidence(PYTORCH_ATEN_EVIDENCE_ID),
            paths["vllm_python"]: evidence(VLLM_PYTHON_EVIDENCE_ID),
            paths["vllm_extension"]: evidence(VLLM_EXTENSION_EVIDENCE_ID),
        }
        for role, missing_path in paths.items():
            with self.subTest(missing_role=role):
                values = {**correct, missing_path: None}
                with mock.patch.object(
                    checker,
                    "_inspect_regular_path",
                    side_effect=lambda path, _inspector, values=values: values[path],
                ):
                    result = checker.compatibility(**paths)
                self.assertEqual("UNSUPPORTED", result["result"])
                check = f"{role}_identity"
                self.assertEqual("UNSUPPORTED", result["checks"][check])
                self.assertEqual(
                    {
                        key: "UNSUPPORTED" if key == check else "SUPPORTED"
                        for key in SUPPORTED_CHECKS
                    },
                    result["checks"],
                )

    def test_name_only_files_are_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = {
                "pytorch_bridge": root / "libtorch_python.so",
                "pytorch_aten": root / "libtorch_cpu.so",
                "vllm_python": root / "python",
                "vllm_extension": root / "_C.abi3.so",
            }
            for path in paths.values():
                path.write_bytes(b"not an authenticated ELF")
            result = checker.compatibility(**paths)
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
            inspector = mock.Mock()
            for path in paths:
                with self.subTest(path=path.name):
                    self.assertIsNone(checker._inspect_regular_path(path, inspector))
            inspector.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_fifo_is_rejected_without_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fifo = Path(raw) / "hostile-fifo"
            try:
                os.mkfifo(fifo, mode=0o600)
            except OSError as error:
                self.skipTest(f"temporary filesystem cannot create FIFOs: {error}")
            inspector = mock.Mock()
            self.assertIsNone(checker._inspect_regular_path(fifo, inspector))
            inspector.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "device nodes require POSIX")
    def test_device_is_rejected_without_authentication(self) -> None:
        inspector = mock.Mock()
        self.assertIsNone(checker._inspect_regular_path(Path("/dev/null"), inspector))
        inspector.assert_not_called()

    def test_main_has_fixed_supported_and_unsupported_exit_semantics(self) -> None:
        result = {
            "checks": {},
            "limitations": ["BINARY_IDENTITY_ONLY"],
            "result": "UNSUPPORTED",
            "schema_version": checker.SCHEMA,
            "target_profile": checker.PROFILE,
            "version": "1.0.10",
        }
        arguments = [
            "--pytorch-bridge",
            str(ROOT / "bridge"),
            "--pytorch-aten",
            str(ROOT / "aten"),
            "--vllm-python",
            str(ROOT / "python"),
            "--vllm-extension",
            str(ROOT / "extension"),
        ]
        for state, expected in (("SUPPORTED", 0), ("UNSUPPORTED", 2)):
            with self.subTest(state=state):
                output = io.StringIO()
                with (
                    mock.patch.object(
                        checker, "compatibility", return_value={**result, "result": state}
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    return_code = checker.main(arguments)
                self.assertEqual(expected, return_code)
                self.assertEqual(state, json.loads(output.getvalue())["result"])

    def test_documented_isolated_entrypoint_is_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = [root / f"private-{index}" for index in range(4)]
            for path in paths:
                path.write_bytes(b"not an authenticated ELF")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-I",
                    "-S",
                    str(ROOT / "scripts" / "check_vllm_compatibility.py"),
                    "--pytorch-bridge",
                    str(paths[0]),
                    "--pytorch-aten",
                    str(paths[1]),
                    "--vllm-python",
                    str(paths[2]),
                    "--vllm-extension",
                    str(paths[3]),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(2, completed.returncode)
            value = json.loads(completed.stdout)
            self.assertEqual("UNSUPPORTED", value["result"])
            self.assertEqual(RESULT_KEYS, set(value))
            self.assertEqual("", completed.stderr)
            combined = completed.stdout + completed.stderr
            for path in paths:
                self.assertNotIn(str(path), combined)

    def test_documented_entrypoint_rejects_relative_paths(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                "-I",
                "-S",
                str(ROOT / "scripts" / "check_vllm_compatibility.py"),
                "--pytorch-bridge",
                "relative-private-bridge",
                "--pytorch-aten",
                str(ROOT / "aten"),
                "--vllm-python",
                str(ROOT / "python"),
                "--vllm-extension",
                str(ROOT / "extension"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)
        self.assertIn(
            "vLLM and PyTorch binary paths must be absolute", completed.stderr
        )
        self.assertNotIn("relative-private-bridge", completed.stderr)


if __name__ == "__main__":
    unittest.main()
