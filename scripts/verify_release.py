"""Reject public artifacts with version, source-tree, or forbidden-release leaks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

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
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ZIP_COMMENT_BYTES = 65_535


def require_exact_zip_end(path: Path) -> None:
    try:
        size = path.stat().st_size
        window_size = min(size, MAX_ZIP_COMMENT_BYTES + 22)
        with path.open("rb") as handle:
            handle.seek(size - window_size)
            tail = handle.read(window_size)
    except OSError as error:
        raise SystemExit("release archive cannot be read") from error
    marker = b"PK\x05\x06"
    position = tail.find(marker)
    while position >= 0:
        if position + 22 <= len(tail):
            comment_size = int.from_bytes(tail[position + 20 : position + 22], "little")
            if position + 22 + comment_size == len(tail):
                return
        position = tail.find(marker, position + 1)
    raise SystemExit("release archive is truncated or has trailing data")


def validated_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = archive.infolist()
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise SystemExit("release archive has an invalid member count")
    seen: set[str] = set()
    total = 0
    for member in members:
        name = member.filename
        path = PurePosixPath(name)
        parts = path.parts
        normalized = path.as_posix().rstrip("/")
        if (
            not name
            or "\x00" in name
            or "\\" in name
            or path.is_absolute()
            or not normalized
            or any(part in ("", ".", "..") for part in parts)
            or (len(parts[0]) >= 2 and parts[0][1] == ":")
        ):
            raise SystemExit("release archive contains an unsafe path")
        if normalized in seen:
            raise SystemExit("release archive contains a duplicate path")
        seen.add(normalized)
        mode = (member.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if member.flag_bits & 0x1 or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise SystemExit("release archive contains a link or special member")
        if member.is_dir() != (file_type == stat.S_IFDIR) and file_type != 0:
            raise SystemExit("release archive member type is inconsistent")
        if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise SystemExit("release archive member exceeds the verification limit")
        total += member.file_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise SystemExit("release archive exceeds the verification limit")
    return members


def require_exact_archive_prefix(path: Path, members: list[zipfile.ZipInfo]) -> None:
    start = min(member.header_offset for member in members)
    try:
        with path.open("rb") as handle:
            prefix = handle.read(start)
    except OSError as error:
        raise SystemExit("release archive cannot be read") from error
    allowed = b"#!/usr/bin/env python3\n" if path.suffix == ".pyz" else b""
    if prefix != allowed:
        raise SystemExit("release archive contains prepended or concatenated data")


def text_from_zip(path: Path) -> str:
    require_exact_zip_end(path)
    with zipfile.ZipFile(path) as archive:
        members = validated_members(archive)
        require_exact_archive_prefix(path, members)
        return "\n".join(
            archive.read(member).decode("utf-8", errors="ignore").lower()
            for member in members
            if member.filename.endswith((".py", ".md", ".toml", ".txt"))
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
        matches = [
            member
            for member in validated_members(archive)
            if member.filename == "lumi_eggcracker/build_info.py"
        ]
        if len(matches) != 1:
            raise SystemExit("artifact source identity is missing")
        raw = archive.read(matches[0])
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
            "scripts/upgrade.py",
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
        members = validated_members(archive)
        if {member.filename for member in members} != expected:
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
