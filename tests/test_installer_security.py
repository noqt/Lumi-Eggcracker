from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install.py"


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
