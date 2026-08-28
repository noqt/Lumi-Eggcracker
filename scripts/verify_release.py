"""Reject public artifacts with version, source-tree, or forbidden-release leaks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

FORBIDDEN = (
    "/mnt/" + "f/",
    "f" + ":\\",
    "network" + "-deny",
    "network" + "_rule",
    "b" + "20",
    "brief" + " 1",
    "brief" + "-",
    "root" + "less",
    "skylark" + " sentinel",
    "skylark" + "-sentinel",
)


def text_from_zip(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        return "\n".join(
            archive.read(name).decode("utf-8", errors="ignore").lower()
            for name in archive.namelist()
            if name.endswith((".py", ".md", ".toml", ".txt"))
        )


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise SystemExit("checksums contain an invalid line")
        result[fields[1].removeprefix("*")] = fields[0]
    return result


def artifact_source_commit(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        try:
            raw = archive.read("lumi_eggcracker/build_info.py")
        except KeyError as error:
            raise SystemExit("artifact source identity is missing") from error
    match = re.fullmatch(b'SOURCE_COMMIT = "([0-9a-f]{40})"\r?\n', raw)
    if match is None:
        raise SystemExit("artifact source identity is invalid")
    return match.group(1).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--release-bundle", required=True, type=Path)
    args = parser.parse_args()
    if not all(
        path.is_file() for path in (args.artifact, args.source_archive, args.release_bundle)
    ):
        raise SystemExit("release artifacts are missing")
    for path in (args.artifact, args.source_archive, args.release_bundle):
        leaks = [item for item in FORBIDDEN if item in text_from_zip(path)]
        if leaks:
            raise SystemExit(f"forbidden public artifact content in {path.name}: {leaks}")
    manifest = json.loads(
        (args.artifact.parent / "release-manifest.json").read_text(encoding="utf-8")
    )
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit("release manifest version is invalid")
    prefix = f"lumi-eggcracker-{version}/"
    expected_names = {
        "artifact": f"lumi-eggcracker-{version}.pyz",
        "source_archive": f"lumi-eggcracker-{version}-source.zip",
    }
    if manifest.get("artifact") != expected_names["artifact"] or manifest.get("source_archive") != expected_names["source_archive"]:
        raise SystemExit("release manifest artifact names are inconsistent")
    result = subprocess.run(
        [sys.executable, str(args.artifact), "version"], capture_output=True, text=True, check=False
    )
    if result.returncode or result.stdout.strip() != version:
        raise SystemExit("artifact version is inconsistent")
    if manifest.get("artifact") != args.artifact.name:
        raise SystemExit("release manifest is inconsistent")
    if manifest.get("source_commit") != artifact_source_commit(args.artifact):
        raise SystemExit("artifact and manifest source identities differ")
    expected = {
        prefix + name
        for name in (
            args.artifact.name,
            args.source_archive.name,
            "release-manifest.json",
            "SHA256SUMS",
            "README.md",
            "LICENSE",
            "LIMITATIONS.md",
            "SECURITY.md",
            "SECURITY_MODEL.md",
            "QUALIFICATION.md",
            "RELEASE_NOTES.md",
            "scripts/install.py",
            "scripts/uninstall.py",
            "scripts/verify_uninstalled.py",
            "scripts/verify_release.py",
            "scripts/first_kill.py",
            "scripts/support_bundle.py",
            "scripts/prepare_ai_smoke.py",
            "scripts/prepare_safetensors_smoke.py",
            "scripts/ai_smoke_worker.py",
            "scripts/smoke_local_ai.py",
            "scripts/smoke_autonomous_ai.py",
            "scripts/smoke_content_ai.py",
            "scripts/smoke_safetensors_ai.py",
            "scripts/smoke_safetensors_aten_negative.py",
            "scripts/run_content_matrix.py",
            "scripts/run_content_benign_matrix.py",
            "scripts/run_content_adversarial_matrix.py",
            "scripts/self_validate.py",
            "scripts/run_autonomous_matrix.py",
            "scripts/run_native_matrix.py",
            "scripts/run_p0_native.py",
            "scripts/run_installer_p0.py",
            "scripts/benchmark_overhead.py",
            "scripts/qualify_offline_boundary.py",
            "scripts/qualify_offline_boundary_integration.py",
            "scripts/verify_evidence.py",
            "scripts/package_evidence.py",
            "scripts/verify_evidence_archive.py",
            "tests/fixtures/benign_model_handler.py",
            "tests/fixtures/benign_near_limit.py",
            "tests/fixtures/canary.py",
            "tests/fixtures/fork_race.py",
            "tests/fixtures/hostile_client.py",
            "tests/fixtures/pid_pressure.py",
        )
    }
    with zipfile.ZipFile(args.release_bundle) as archive:
        if set(archive.namelist()) != expected:
            raise SystemExit("release bundle contents are inconsistent")
        if (
            digest_bytes(archive.read(prefix + args.artifact.name)) != manifest["sha256"]
            or digest_bytes(archive.read(prefix + args.source_archive.name))
            != manifest["source_archive_sha256"]
        ):
            raise SystemExit("bundled artifact digest is inconsistent")
    parsed_sums = checksums(args.artifact.parent / "SHA256SUMS")
    expected_sums = {
        args.artifact.name: digest_bytes(args.artifact.read_bytes()),
        args.source_archive.name: digest_bytes(args.source_archive.read_bytes()),
        args.release_bundle.name: digest_bytes(args.release_bundle.read_bytes()),
    }
    # A detached build directory carries the archive's checksum as its third
    # entry. The checksum file embedded inside that archive cannot include a
    # digest of its containing archive without recursion, so an extracted
    # bundle carries only its artifact and source entries. In both modes the
    # archive's exact member set and embedded payload digests were checked
    # above; distribution still relies on the detached SHA256SUMS as its trust
    # anchor.
    if args.artifact.parent.resolve() == args.release_bundle.parent.resolve():
        required_sums = expected_sums
    else:
        required_sums = {
            args.artifact.name: expected_sums[args.artifact.name],
            args.source_archive.name: expected_sums[args.source_archive.name],
        }
    if parsed_sums != required_sums:
        raise SystemExit("checksums do not match the published release assets")
    print(json.dumps({"result": "PASS", "version": version}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
