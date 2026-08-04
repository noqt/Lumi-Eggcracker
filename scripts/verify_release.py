"""Reject public artifacts with version, source-tree, or forbidden-release leaks."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

VERSION = "0.3.0"
PREFIX = f"lumi-eggcracker-{VERSION}/"
FORBIDDEN = (
    "/mnt/" + "f/", "f" + ":\\", "network" + "-deny", "network" + "_rule",
    "nft" + "ables", "/usr/sbin/" + "nft", "b" + "20", "brief" + " 1",
    "brief" + "-", "root" + "less", "skylark" + " sentinel",
    "skylark" + "-sentinel",
)


def text_from_zip(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        return "\n".join(archive.read(name).decode("utf-8", errors="ignore").lower() for name in archive.namelist() if name.endswith((".py", ".md", ".toml", ".txt")))


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--release-bundle", required=True, type=Path)
    args = parser.parse_args()
    if not all(path.is_file() for path in (args.artifact, args.source_archive, args.release_bundle)):
        raise SystemExit("release artifacts are missing")
    for path in (args.artifact, args.source_archive, args.release_bundle):
        leaks = [item for item in FORBIDDEN if item in text_from_zip(path)]
        if leaks:
            raise SystemExit(f"forbidden public artifact content in {path.name}: {leaks}")
    result = subprocess.run([sys.executable, str(args.artifact), "version"], capture_output=True, text=True, check=False)
    if result.returncode or result.stdout.strip() != VERSION:
        raise SystemExit("artifact version is inconsistent")
    manifest = json.loads((args.artifact.parent / "release-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != VERSION or manifest.get("artifact") != args.artifact.name:
        raise SystemExit("release manifest is inconsistent")
    expected = {PREFIX + name for name in (args.artifact.name, args.source_archive.name, "release-manifest.json", "SHA256SUMS", "README.md", "LICENSE", "LIMITATIONS.md", "SECURITY.md", "SECURITY_MODEL.md", "QUALIFICATION.md", "RELEASE_NOTES.md", "scripts/install.py", "scripts/uninstall.py", "scripts/verify_uninstalled.py", "scripts/prepare_ai_smoke.py", "scripts/ai_smoke_worker.py", "scripts/smoke_local_ai.py", "scripts/smoke_autonomous_ai.py", "scripts/smoke_content_ai.py", "scripts/run_autonomous_matrix.py")}
    with zipfile.ZipFile(args.release_bundle) as archive:
        if set(archive.namelist()) != expected:
            raise SystemExit("release bundle contents are inconsistent")
        if digest_bytes(archive.read(PREFIX + args.artifact.name)) != manifest["sha256"] or digest_bytes(archive.read(PREFIX + args.source_archive.name)) != manifest["source_archive_sha256"]:
            raise SystemExit("bundled artifact digest is inconsistent")
    sums = (args.artifact.parent / "SHA256SUMS").read_text(encoding="utf-8")
    if args.artifact.name not in sums or args.source_archive.name not in sums or args.release_bundle.name not in sums:
        raise SystemExit("checksums do not cover every release asset")
    print(json.dumps({"result": "PASS", "version": VERSION}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
