from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker.discovery import ProcessIdentity, ProcessSnapshot
from lumi_eggcracker.launches import authorizes, create, load_all


class LaunchProvenanceTests(unittest.TestCase):
    def test_trusted_preexec_identity_does_not_depend_on_mutable_cmdline(self) -> None:
        run_id = "a" * 24
        cgroup = f"/system.slice/lumi-eggcracker-workload-{run_id}.service"
        process = ProcessIdentity(42, 100)
        run = {
            "boot_id": "boot",
            "cgroup": cgroup,
            "cgroup_device": 7,
            "cgroup_inode": 8,
            "run_id": run_id,
        }
        approval = {
            "bound_inputs": [],
            "created_monotonic_ns": 1,
            "name": "approved",
            "argv_count": 2,
            "argv_sha256": "a" * 64,
            "executable": "/usr/bin/python3",
            "executable_device": 9,
            "executable_inode": 10,
            "executable_sha256": "b" * 64,
            "launch_kind": "NATIVE_LLAMA",
            "uid": 1001,
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            provenance = create(
                root, run=run, process=process, approval=approval
            )
            self.assertEqual([provenance], load_all(root))
            forged_view = ProcessSnapshot(
                process,
                1001,
                "/usr/bin/python3",
                "python3",
                ("python3", "attacker-rewrote-this"),
                ("0::" + cgroup,),
                (),
                (),
            )
            with patch("lumi_eggcracker.launches.validate_identity"):
                self.assertTrue(
                    authorizes(forged_view, "b" * 64, (9, 10), provenance)
                )
                replacement = ProcessSnapshot(
                    ProcessIdentity(43, 101),
                    1001,
                    "/usr/bin/python3",
                    "python3",
                    forged_view.argv,
                    forged_view.cgroups,
                    (),
                    (),
                )
                self.assertFalse(
                    authorizes(replacement, "b" * 64, (9, 10), provenance)
                )
