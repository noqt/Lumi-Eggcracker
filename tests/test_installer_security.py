from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.py"
UNINSTALLER = ROOT / "scripts" / "uninstall.py"


@unittest.skipUnless(os.name == "posix" and Path("/usr/bin/python3").is_file(), "Linux only")
class InstallerSecurityTests(unittest.TestCase):
    def test_documented_isolated_invocation_ignores_shadow_modules_and_startup_hooks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            marker = root / "imported"
            (root / "argparse.py").write_text(
                f"open({str(marker)!r}, 'w').write('argparse')\nraise RuntimeError('shadowed')\n",
                encoding="utf-8",
            )
            (root / "sitecustomize.py").write_text(
                f"open({str(marker)!r}, 'w').write('sitecustomize')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root)
            result = subprocess.run(
                ["/usr/bin/python3", "-I", "-S", str(INSTALLER)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(marker.exists())

    def test_symlinked_privileged_installer_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            link = Path(raw) / "install-link.py"
            link.symlink_to(INSTALLER)
            result = subprocess.run(
                ["/usr/bin/python3", "-I", "-S", str(link)],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("symlinked privileged installer", result.stderr)

    def test_uninstaller_help_is_non_destructive(self) -> None:
        result = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", str(UNINSTALLER), "--help"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("usage:", result.stdout)
        self.assertIn("manifest-verified", result.stdout)
        self.assertNotIn("UNINSTALLED", result.stdout)

    def test_privileged_scripts_require_isolated_no_site_python(self) -> None:
        for name in ("install.py", "uninstall.py", "verify_uninstalled.py"):
            value = (ROOT / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn("flags.isolated", value)
            self.assertIn("flags.no_site", value)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--expected-sha256", installer)
        self.assertIn("/proc/self/fd/{artifact_descriptor}", installer)
        self.assertIn("read_stable_regular", installer)
        self.assertIn("artifact_source_commit", installer)
        self.assertIn("INSTALL_JOURNAL_SCHEMA", installer)
        self.assertIn("recover_interrupted_install", installer)
        self.assertIn("acquire_lifecycle_lock", installer)
        self.assertIn("release_lifecycle_lock", installer)
        for name in ("upgrade.py", "uninstall.py"):
            lifecycle = (ROOT / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn("acquire_lifecycle_lock", lifecycle)
            self.assertIn("release_lifecycle_lock", lifecycle)
        uninstaller = UNINSTALLER.read_text(encoding="utf-8")
        self.assertIn("UNINSTALL_JOURNAL_SCHEMA", uninstaller)
        self.assertIn("recover_uninstall", uninstaller)

    def test_install_tracks_cold_boot_network_namespace_runtime(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        upgrader = (ROOT / "scripts" / "upgrade.py").read_text(encoding="utf-8")
        uninstaller = UNINSTALLER.read_text(encoding="utf-8")
        verifier = (ROOT / "scripts" / "verify_uninstalled.py").read_text(
            encoding="utf-8"
        )

        for value in (installer, uninstaller, verifier):
            self.assertIn("/etc/tmpfiles.d/lumi-eggcracker.conf", value)
        self.assertIn("d /run/netns 0755 root root -", installer)
        self.assertIn("ensure_netns_runtime()", installer)
        self.assertIn("installer.TMPFILES", upgrader)
        self.assertIn("installer.ensure_netns_runtime()", upgrader)
