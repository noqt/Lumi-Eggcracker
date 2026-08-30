from __future__ import annotations

import importlib.util
import os
import pwd
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
UPGRADER = ROOT / "scripts" / "upgrade.py"


@unittest.skipUnless(
    os.name == "posix" and Path("/usr/bin/python3").is_file(),
    "Linux only",
)
class UpgradeIdentityTests(unittest.TestCase):
    @staticmethod
    def load_upgrader():
        specification = importlib.util.spec_from_file_location(
            "eggcracker_upgrade_identity_test",
            UPGRADER,
        )
        if specification is None or specification.loader is None:
            raise RuntimeError("cannot load the privileged upgrader")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module

    @staticmethod
    def account() -> pwd.struct_passwd:
        return pwd.struct_passwd(
            (
                "lumi-eggcracker-workload",
                "x",
                999,
                988,
                "",
                "/nonexistent",
                "/usr/sbin/nologin",
            )
        )

    @staticmethod
    def operator() -> pwd.struct_passwd:
        return pwd.struct_passwd(
            ("operator", "x", 1000, 1000, "", "/home/operator", "/bin/sh")
        )

    def test_legacy_manifest_resolves_live_gid_instead_of_using_uid(self) -> None:
        upgrader = self.load_upgrader()
        manifest = {
            "workload_group": "lumi-eggcracker-workload",
            "workload_uid": 999,
            "workload_user": "lumi-eggcracker-workload",
        }
        group = type("Group", (), {"gr_name": "lumi-eggcracker-workload"})()
        with (
            mock.patch.object(upgrader.pwd, "getpwnam", return_value=self.account()),
            mock.patch.object(upgrader.grp, "getgrgid", return_value=group),
            mock.patch.object(upgrader, "digest", return_value="d" * 64),
        ):
            policy = upgrader.new_policy(
                {"source_commit": "c" * 40, "version": "1.0.0"},
                self.operator(),
                manifest,
            )
        self.assertEqual(999, policy["workload_uid"])
        self.assertEqual(988, policy["workload_gid"])

    def test_recorded_gid_must_match_live_dedicated_account(self) -> None:
        upgrader = self.load_upgrader()
        manifest = {
            "workload_gid": 999,
            "workload_group": "lumi-eggcracker-workload",
            "workload_uid": 999,
            "workload_user": "lumi-eggcracker-workload",
        }
        with mock.patch.object(
            upgrader.pwd,
            "getpwnam",
            return_value=self.account(),
        ), self.assertRaisesRegex(RuntimeError, "no longer meets the contract"):
            upgrader.installed_workload_account(manifest)

    def test_installer_persists_workload_gid(self) -> None:
        installer = (ROOT / "scripts" / "install.py").read_text(encoding="utf-8")
        self.assertIn('"workload_gid": account.pw_gid', installer)


if __name__ == "__main__":
    unittest.main()
