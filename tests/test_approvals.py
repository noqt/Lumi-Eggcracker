from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lumi_eggcracker.approvals import (
    LEGACY_SCHEMA,
    _root_controlled_reference,
    create,
    load_all,
    load_installation_epoch,
    match_launch,
    public,
    revoke,
    stage_launch,
)
from lumi_eggcracker.discovery import argv_digest
from lumi_eggcracker.jsonio import JsonInputError

EPOCH = "e" * 64
OTHER_EPOCH = "f" * 64


class ApprovalTests(unittest.TestCase):
    def test_installation_epoch_requires_root_private_regular_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manifest = Path(raw) / "install-manifest.json"
            manifest.write_text(
                json.dumps({"installation_epoch": EPOCH}), encoding="utf-8"
            )
            trusted = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_nlink=1,
                st_uid=0,
            )
            with patch.object(Path, "lstat", autospec=True, return_value=trusted):
                self.assertEqual(EPOCH, load_installation_epoch(manifest))
            untrusted = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o644,
                st_nlink=1,
                st_uid=0,
            )
            with (
                patch.object(Path, "lstat", autospec=True, return_value=untrusted),
                self.assertRaisesRegex(JsonInputError, "root-private"),
            ):
                load_installation_epoch(manifest)

    def test_root_owned_interpreter_symlink_uses_parent_and_target_controls(self) -> None:
        link = Path("/opt/root-venv/bin/python")

        def root_owned(path: Path):
            mode = stat.S_IFLNK | 0o777 if path == link else stat.S_IFDIR | 0o755
            return SimpleNamespace(st_mode=mode, st_uid=0)

        with patch.object(Path, "lstat", autospec=True, side_effect=root_owned):
            self.assertTrue(_root_controlled_reference(link))

        def untrusted_link(path: Path):
            metadata = root_owned(path)
            if path == link:
                metadata.st_uid = 1000
            return metadata

        with patch.object(Path, "lstat", autospec=True, side_effect=untrusted_link):
            self.assertFalse(_root_controlled_reference(link))

    def test_exact_approval_matches_only_trusted_preexec_uid_and_argv(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"#!/bin/true\n")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
            with patch(
                "lumi_eggcracker.approvals._classify",
                return_value=(
                    "NATIVE_LLAMA",
                    [
                        {
                            "argument_index": 2,
                            "device": 1,
                            "inode": 1,
                            "kind": "MODEL_ARTIFACT",
                            "sha256": "a" * 64,
                            "size": 1,
                        }
                    ],
                ),
            ), patch(
                "lumi_eggcracker.approvals._root_controlled_reference",
                return_value=True,
            ):
                record = create(
                    root,
                    name="qwen",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
            with patch(
                "lumi_eggcracker.approvals._root_controlled_reference",
                return_value=True,
            ):
                values = load_all(root, installation_epoch=EPOCH)
                self.assertEqual(
                    record, match_launch(uid=1001, argv=argv, approvals=values)
                )
                self.assertIsNone(match_launch(uid=1002, argv=argv, approvals=values))
                self.assertIsNone(
                    match_launch(
                        uid=1001,
                        argv=[str(binary), "-m", "/models/other.gguf"],
                        approvals=values,
                    )
                )
                self.assertIsNone(
                    match_launch(
                        uid=1001,
                        argv=argv,
                        approvals=values,
                        max_pids=65,
                    )
                )
            self.assertNotIn("/models/qwen.gguf", record.values())
            self.assertEqual(argv_digest(argv), record["argv_sha256"])
            self.assertEqual(64, record["max_pids"])
            self.assertEqual(2048, record["max_memory_mib"])
            self.assertEqual(400, record["cpu_quota_percent"])

    def test_revoke_removes_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"x")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
            with patch(
                "lumi_eggcracker.approvals._classify",
                return_value=(
                    "NATIVE_LLAMA",
                    [
                        {
                            "argument_index": 2,
                            "device": 1,
                            "inode": 1,
                            "kind": "MODEL_ARTIFACT",
                            "sha256": "a" * 64,
                            "size": 1,
                        }
                    ],
                ),
            ), patch(
                "lumi_eggcracker.approvals._root_controlled_reference",
                return_value=True,
            ):
                create(
                    root,
                    name="qwen",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
            self.assertEqual(
                "REVOKED",
                revoke(root, "qwen", installation_epoch=EPOCH)["result"],
            )
            self.assertEqual([], load_all(root, installation_epoch=EPOCH))

    def test_pre_epoch_approval_is_rejected_after_install_transition(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"x")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
            with (
                patch(
                    "lumi_eggcracker.approvals._classify",
                    return_value=(
                        "NATIVE_LLAMA",
                        [
                            {
                                "argument_index": 2,
                                "device": 1,
                                "inode": 1,
                                "kind": "MODEL_ARTIFACT",
                                "sha256": "a" * 64,
                                "size": 1,
                            }
                        ],
                    ),
                ),
                patch(
                    "lumi_eggcracker.approvals._root_controlled_reference",
                    return_value=True,
                ),
            ):
                record = create(
                    root,
                    name="legacy",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
            record["schema_version"] = LEGACY_SCHEMA
            record.pop("installation_epoch")
            for key in ("cpu_quota_percent", "max_memory_mib", "max_pids"):
                record.pop(key)
            (root / "legacy.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
            self.assertIsNone(public(record)["resource_limits"])
            with self.assertRaisesRegex(JsonInputError, "installation epoch"):
                load_all(root, installation_epoch=EPOCH)
            with self.assertRaisesRegex(JsonInputError, "installation epoch"):
                revoke(root, "legacy", installation_epoch=EPOCH)

    def test_epoch_bound_approval_cannot_be_loaded_in_another_install(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "approvals"
            binary = Path(raw) / "runner"
            binary.write_bytes(b"x")
            binary.chmod(0o755)
            argv = [str(binary), "-m", "/models/qwen.gguf"]
            with (
                patch(
                    "lumi_eggcracker.approvals._classify",
                    return_value=(
                        "NATIVE_LLAMA",
                        [
                            {
                                "argument_index": 2,
                                "device": 1,
                                "inode": 1,
                                "kind": "MODEL_ARTIFACT",
                                "sha256": "a" * 64,
                                "size": 1,
                            }
                        ],
                    ),
                ),
                patch(
                    "lumi_eggcracker.approvals._root_controlled_reference",
                    return_value=True,
                ),
            ):
                create(
                    root,
                    name="epoch-a",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
            with self.assertRaisesRegex(JsonInputError, "does not match"):
                load_all(root, installation_epoch=OTHER_EPOCH)

    def test_python_script_is_staged_from_bound_bytes_and_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            approvals = base / "approvals"
            executable = base / "python3"
            executable.write_bytes(b"python-runtime")
            executable.chmod(0o555)
            script = base / "worker.py"
            script.write_text("print('approved')\n", encoding="utf-8")
            argv = [str(executable), str(script), "safe-mode"]
            with (
                patch("lumi_eggcracker.approvals.inspect_path", return_value=None),
                patch("lumi_eggcracker.approvals._is_cpython", return_value=True),
                patch(
                    "lumi_eggcracker.approvals._runtime_is_root_controlled",
                    return_value=True,
                ),
                patch(
                    "lumi_eggcracker.approvals._root_controlled_reference",
                    return_value=True,
                ),
            ):
                record = create(
                    approvals,
                    name="python-safe",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
            self.assertEqual("PYTHON_SCRIPT", record["launch_kind"])
            self.assertEqual(1, len(record["bound_inputs"]))

            stage_root = base / "staged"
            stage_root.mkdir()
            with patch("lumi_eggcracker.approvals.os.chown", create=True):
                effective = stage_launch(record, argv, stage_root / ("a" * 24))
            self.assertNotEqual(argv[1], effective[1])
            self.assertEqual("-I", effective[1])
            self.assertEqual(script.read_bytes(), Path(effective[2]).read_bytes())

            script.write_text("print('hostile')\n", encoding="utf-8")
            with (
                patch("lumi_eggcracker.approvals.os.chown", create=True),
                self.assertRaises(JsonInputError),
            ):
                stage_launch(record, argv, stage_root / ("b" * 24))

    def test_native_model_material_drift_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            approvals = base / "approvals"
            executable = base / "llama"
            executable.write_bytes(b"qualified-runtime")
            executable.chmod(0o555)
            model = base / "model.gguf"
            model.write_bytes(b"GGUF" + b"\0" * 64)
            argv = [str(executable), "-m", str(model)]

            def open_material(path_text: str):
                descriptor = os.open(path_text, os.O_RDONLY)
                return descriptor, os.fstat(descriptor)

            with (
                patch("lumi_eggcracker.approvals.inspect_path", return_value=object()),
                patch(
                    "lumi_eggcracker.approvals.validate_gguf_fd",
                    return_value=object(),
                ),
                patch(
                    "lumi_eggcracker.approvals._runtime_is_root_controlled",
                    return_value=True,
                ),
                patch(
                    "lumi_eggcracker.approvals._root_controlled_reference",
                    return_value=True,
                ),
                patch(
                    "lumi_eggcracker.approvals._open_root_controlled_material",
                    side_effect=open_material,
                ),
            ):
                record = create(
                    approvals,
                    name="native-bound",
                    uid=1001,
                    argv=argv,
                    administrator_uid=0,
                    installation_epoch=EPOCH,
                )
                self.assertEqual(argv, stage_launch(record, argv, base / "unused"))
                replacement = base / "replacement.gguf"
                replacement.write_bytes(b"GGUF" + b"hostile" * 16)
                replacement.replace(model)
                with self.assertRaises(JsonInputError):
                    stage_launch(record, argv, base / "unused")

    def test_python_module_and_command_forms_are_not_approvable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            executable = base / "python3"
            executable.write_bytes(b"python-runtime")
            executable.chmod(0o555)
            for index, suffix in enumerate((["-m", "module"], ["-c", "print(1)"])):
                with (
                    patch("lumi_eggcracker.approvals.inspect_path", return_value=None),
                    patch("lumi_eggcracker.approvals._is_cpython", return_value=True),
                    patch(
                        "lumi_eggcracker.approvals._runtime_is_root_controlled",
                        return_value=True,
                    ),
                    patch(
                        "lumi_eggcracker.approvals._root_controlled_reference",
                        return_value=True,
                    ),
                    self.assertRaises(JsonInputError),
                ):
                    create(
                        base / "approvals",
                        name=f"python-unsupported-{index}",
                        uid=1001,
                        argv=[str(executable), *suffix],
                        administrator_uid=0,
                        installation_epoch=EPOCH,
                    )
