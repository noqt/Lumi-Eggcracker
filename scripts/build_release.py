"""Build a clean Lumi Eggcracker zipapp, source archive, and checksums."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import tempfile
import zipapp
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def version() -> str:
    value = (ROOT / "src" / "lumi_eggcracker" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([0-9]+\.[0-9]+\.[0-9]+)"', value)
    if not match:
        raise RuntimeError("cannot determine public version")
    return match.group(1)


def command(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.allow_dirty and command(["git", "-C", str(ROOT), "status", "--porcelain"]):
        raise SystemExit("refusing to build a release from a dirty tree")
    release_version = version()
    commit = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    args.output.mkdir(parents=True, exist_ok=True)
    artifact = args.output / f"lumi-eggcracker-{release_version}.pyz"
    source = args.output / f"lumi-eggcracker-{release_version}-source.zip"
    bundle = args.output / f"lumi-eggcracker-{release_version}-linux.zip"
    with tempfile.TemporaryDirectory(prefix="lumi-eggcracker-build-") as raw:
        stage = Path(raw) / "src"
        shutil.copytree(
            ROOT / "src", stage, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info")
        )
        (stage / "__main__.py").write_text(
            "from lumi_eggcracker.cli import main\nraise SystemExit(main())\n", encoding="utf-8"
        )
        (stage / "lumi_eggcracker" / "build_info.py").write_text(
            f'SOURCE_COMMIT = "{commit}"\n', encoding="utf-8"
        )
        zipapp.create_archive(stage, target=artifact, interpreter="/usr/bin/env python3")
    command(
        [
            "git",
            "-C",
            str(ROOT),
            "archive",
            "--format=zip",
            f"--prefix=lumi-eggcracker-{release_version}/",
            "-o",
            str(source),
            "HEAD",
        ]
    )
    manifest = {
        "artifact": artifact.name,
        "sha256": digest(artifact),
        "source_archive": source.name,
        "source_archive_sha256": digest(source),
        "source_commit": commit,
        "version": release_version,
    }
    (args.output / "release-manifest.json").write_text(
        __import__("json").dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output / "SHA256SUMS").write_text(
        f"{manifest['sha256']}  {artifact.name}\n{manifest['source_archive_sha256']}  {source.name}\n",
        encoding="utf-8",
    )
    prefix = f"lumi-eggcracker-{release_version}"
    release_files = {
        artifact: artifact.name,
        source: source.name,
        args.output / "release-manifest.json": "release-manifest.json",
        args.output / "SHA256SUMS": "SHA256SUMS",
        ROOT / "README.md": "README.md",
        ROOT / "LICENSE": "LICENSE",
        ROOT / "LIMITATIONS.md": "LIMITATIONS.md",
        ROOT / "SECURITY.md": "SECURITY.md",
        ROOT / "SECURITY_MODEL.md": "SECURITY_MODEL.md",
        ROOT / "QUALIFICATION.md": "QUALIFICATION.md",
        ROOT / "RELEASE_NOTES.md": "RELEASE_NOTES.md",
        ROOT / "scripts" / "install.py": "scripts/install.py",
        ROOT / "scripts" / "uninstall.py": "scripts/uninstall.py",
        ROOT / "scripts" / "verify_uninstalled.py": "scripts/verify_uninstalled.py",
        ROOT / "scripts" / "prepare_ai_smoke.py": "scripts/prepare_ai_smoke.py",
        ROOT / "scripts" / "ai_smoke_worker.py": "scripts/ai_smoke_worker.py",
        ROOT / "scripts" / "smoke_local_ai.py": "scripts/smoke_local_ai.py",
        ROOT / "scripts" / "smoke_autonomous_ai.py": "scripts/smoke_autonomous_ai.py",
        ROOT / "scripts" / "smoke_content_ai.py": "scripts/smoke_content_ai.py",
        ROOT / "scripts" / "run_content_matrix.py": "scripts/run_content_matrix.py",
        ROOT / "scripts" / "run_content_benign_matrix.py": "scripts/run_content_benign_matrix.py",
        ROOT / "scripts" / "run_content_adversarial_matrix.py": "scripts/run_content_adversarial_matrix.py",
        ROOT / "scripts" / "self_validate.py": "scripts/self_validate.py",
        ROOT / "scripts" / "run_autonomous_matrix.py": "scripts/run_autonomous_matrix.py",
    }
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, name in release_files.items():
            archive.write(path, f"{prefix}/{name}")
    # The bundle cannot contain a checksum of itself without recursion.  The
    # detached checksum file intentionally covers all published binary assets.
    (args.output / "SHA256SUMS").write_text(
        f"{manifest['sha256']}  {artifact.name}\n{manifest['source_archive_sha256']}  {source.name}\n{digest(bundle)}  {bundle.name}\n",
        encoding="utf-8",
    )
    print(bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
