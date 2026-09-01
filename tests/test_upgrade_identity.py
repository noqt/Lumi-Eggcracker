from __future__ import annotations

import importlib.util
import os
import pwd
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
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
        flag_values = {
            name: getattr(sys.flags, name)
            for name in dir(sys.flags)
            if not name.startswith("_")
        }
        flag_values.update({"isolated": 1, "no_site": 1})
        with mock.patch.object(
            sys,
            "flags",
            SimpleNamespace(**flag_values),
        ):
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

    def test_current_candidate_accepts_prior_1_0_candidates_as_upgrade_sources(self) -> None:
        upgrader = self.load_upgrader()
        self.assertIn("1.0.0", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.1", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.2", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.3", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.4", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.5", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.6", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.7", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.8", upgrader.SUPPORTED_SOURCES)
        self.assertIn("1.0.9", upgrader.SUPPORTED_SOURCES)

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
        self.assertIn('"installation_epoch": secrets.token_hex(32)', installer)

    def test_transitional_health_accepts_only_the_live_upgrade_journal(self) -> None:
        upgrader = self.load_upgrader()
        value = {
            "autonomous_discovery": False,
            "cgroup_v2": True,
            "discovery": {"healthy": True},
            "execution_boundary": {"supported": True},
            "incidents": {"healthy": True},
            "installation": {
                "files_match": False,
                "journal": True,
                "state": "RECOVERY_REQUIRED",
            },
            "network": {
                "cleanup_healthy": True,
                "primitives": {"supported": True},
            },
            "pidfd": True,
            "result": "UNSUPPORTED",
            "workload_identity": {"healthy": True},
        }
        self.assertTrue(upgrader.transitional_doctor_ready(value))
        value["workload_identity"] = {"healthy": False}
        self.assertFalse(upgrader.transitional_doctor_ready(value))
        value["workload_identity"] = {"healthy": True}
        value["installation"] = {
            "files_match": True,
            "journal": False,
            "state": "HEALTHY",
        }
        self.assertFalse(upgrader.transitional_doctor_ready(value))


if __name__ == "__main__":
    unittest.main()
