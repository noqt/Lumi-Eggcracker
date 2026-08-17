from __future__ import annotations

import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix", "POSIX metadata test")
class EvidenceArchiveTests(unittest.TestCase):
    def test_archive_preserves_links_and_verifies_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            payload = evidence / "payload.bin"
            payload.write_bytes(b"sealed evidence\n")
            os.link(payload, evidence / "payload-hardlink.bin")
            (evidence / "payload-link.bin").symlink_to("payload.bin")
            archive = root / "evidence.tar.gz"
            packaged = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "scripts" / "package_evidence.py"),
                    "--evidence",
                    str(evidence),
                    "--output",
                    str(archive),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(0, packaged.returncode, packaged.stderr)
            with tarfile.open(archive, "r:gz") as bundle:
                members = bundle.getmembers()
            self.assertEqual(1, sum(item.issym() for item in members))
            self.assertEqual(1, sum(item.islnk() for item in members))

            manifest = Path(str(archive) + ".manifest.json")
            expected = json.loads(manifest.read_text(encoding="utf-8"))["archive_sha256"]
            verified = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "scripts" / "verify_evidence_archive.py"),
                    "--archive",
                    str(archive),
                    "--manifest",
                    str(manifest),
                    "--require-sha256",
                    expected,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertEqual("PASS", json.loads(verified.stdout)["result"])

    def test_archive_digest_rejects_post_package_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "result.json").write_text("{}\n", encoding="utf-8")
            archive = root / "evidence.tar.gz"
            subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "scripts" / "package_evidence.py"),
                    "--evidence",
                    str(evidence),
                    "--output",
                    str(archive),
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            with archive.open("ab") as handle:
                handle.write(b"tampered")
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    str(ROOT / "scripts" / "verify_evidence_archive.py"),
                    "--archive",
                    str(archive),
                    "--manifest",
                    str(Path(str(archive) + ".manifest.json")),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("identity is invalid", result.stderr)

