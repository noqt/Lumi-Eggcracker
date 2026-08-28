from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from lumi_eggcracker.execution_policy import (
    SCHEMA,
    create,
    ephemeral,
    public,
    validate,
)
from lumi_eggcracker.jsonio import JsonInputError, canonical_bytes


class ExecutionPolicyTests(unittest.TestCase):
    def test_public_policy_contains_no_executable_paths(self) -> None:
        entry = {
            "device": 1,
            "inode": 2,
            "mode": 0o755,
            "path": "/root/private/runner",
            "sha256": "a" * 64,
            "size": 10,
            "uid": 0,
        }
        value = {
            "created_monotonic_ns": 1,
            "creator_uid": 0,
            "digest": "0" * 64,
            "executables": [entry],
            "generation": 1,
            "name": "demo",
            "policy_id": "b" * 24,
            "revoked": False,
            "schema_version": SCHEMA,
        }
        value["digest"] = hashlib.sha256(
            canonical_bytes({key: value[key] for key in value if key != "digest"})
        ).hexdigest()
        checked = validate(value)
        result = public(checked)
        self.assertNotIn("path", result)
        self.assertEqual(1, result["executable_count"])

    def test_duplicate_executable_identities_are_rejected(self) -> None:
        entry = {
            "device": 1,
            "inode": 2,
            "mode": 0o755,
            "path": "/bin/true",
            "sha256": "a" * 64,
            "size": 10,
            "uid": 0,
        }
        value = {
            "created_monotonic_ns": 1,
            "creator_uid": 0,
            "digest": "0" * 64,
            "executables": [entry, dict(entry, path="/usr/bin/true")],
            "generation": 1,
            "name": "demo",
            "policy_id": "b" * 24,
            "revoked": False,
            "schema_version": SCHEMA,
        }
        value["digest"] = hashlib.sha256(
            canonical_bytes({key: value[key] for key in value if key != "digest"})
        ).hexdigest()
        with self.assertRaises(JsonInputError):
            validate(value)

    @unittest.skipIf(__import__("os").name != "posix", "native executable identity is Linux-only")
    def test_create_and_ephemeral_bind_root_controlled_binary(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            value = create(Path(raw), name="shell", paths=["/bin/sh"])
            self.assertEqual(1, public(value)["executable_count"])
        self.assertEqual("a" * 24, ephemeral("/bin/sh", "a" * 24)["policy_id"])
