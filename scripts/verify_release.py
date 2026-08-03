"""Reject public artifacts with version, source-tree, or forbidden-release leaks."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path


FORBIDDEN = ("/mnt/f/", "f:\\", "network-deny", "network_rule", "nftables", "/usr/sbin/nft", "b20", "brief 1", "brief-", "rootless", "skylark sentinel", "skylark-sentinel", "/usr/local/bin/lumi-nutcracker")


def text_from_zip(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        values: list[str] = []
        for name in archive.namelist():
            if name.endswith("scripts/verify_release.py"):
                continue
            if name.endswith((".py", ".md", ".toml", ".txt")):
                values.append(archive.read(name).decode("utf-8", errors="ignore").lower())
        return "\n".join(values)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--release-bundle", required=True, type=Path)
    args = parser.parse_args()
    if not args.artifact.is_file() or not args.source_archive.is_file() or not args.release_bundle.is_file():
        raise SystemExit("release artifacts are missing")
    for path in (args.artifact, args.source_archive, args.release_bundle):
        value = text_from_zip(path)
        leaks = [item for item in FORBIDDEN if item in value]
        if leaks:
            raise SystemExit(f"forbidden public artifact content in {path.name}: {leaks}")
    result = subprocess.run([sys.executable, str(args.artifact), "version"], capture_output=True, text=True, check=False)
    if result.returncode or result.stdout.strip() != "0.1.0":
        raise SystemExit("artifact version is inconsistent")
    manifest = json.loads((args.artifact.parent / "release-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "0.1.0" or manifest.get("artifact") != args.artifact.name:
        raise SystemExit("release manifest is inconsistent")
    prefix = "lumi-nutcracker-0.1.0/"
    expected = {
        prefix + args.artifact.name,
        prefix + args.source_archive.name,
        prefix + "release-manifest.json",
        prefix + "SHA256SUMS",
        prefix + "README.md",
        prefix + "LICENSE",
        prefix + "LIMITATIONS.md",
        prefix + "SECURITY.md",
        prefix + "RELEASE_NOTES.md",
        prefix + "scripts/install.py",
        prefix + "scripts/uninstall.py",
        prefix + "scripts/verify_uninstalled.py",
        prefix + "scripts/smoke_local_ai.py",
    }
    with zipfile.ZipFile(args.release_bundle) as archive:
        if set(archive.namelist()) != expected:
            raise SystemExit("release bundle contents are inconsistent")
        if digest_bytes(archive.read(prefix + args.artifact.name)) != manifest["sha256"]:
            raise SystemExit("bundled artifact digest is inconsistent")
        if digest_bytes(archive.read(prefix + args.source_archive.name)) != manifest["source_archive_sha256"]:
            raise SystemExit("bundled source digest is inconsistent")
    print(json.dumps({"result": "PASS", "version": "0.1.0"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
