#!/usr/bin/env python3
"""Verify a generated Hub surface against the exact commit returned by upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
MARKER_SCHEMA = "noqt.huggingface_sync.v1"
MANIFEST_SCHEMA = "noqt.huggingface_manifest.v1"
UPLOAD_SCHEMA = "noqt.huggingface_upload.v1"
VERIFY_SCHEMA = "noqt.huggingface_remote_verification.v1"


class VerificationError(RuntimeError):
    """Raised when remote readback cannot prove exact parity."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} is unreadable") from error
    if not isinstance(value, dict):
        raise VerificationError(f"{label} is not an object")
    return value


def _write_once(path: Path, value: dict[str, Any]) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise VerificationError(f"verification report already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_remote_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or path.as_posix() != value
    ):
        raise VerificationError("remote tree contains an unsafe path")
    return value


def _local_file_set(staging: Path) -> set[str]:
    paths: set[str] = set()
    for path in staging.rglob("*"):
        if path.is_symlink():
            raise VerificationError("staging surface contains a symlink")
        if path.is_file():
            paths.add(path.relative_to(staging).as_posix())
    return paths


def verify_surface(
    *,
    repo_id: str,
    repo_type: str,
    staging: Path,
    upload_record: Path,
    source_revision: str,
    readback: Path,
    report: Path,
) -> dict[str, Any]:
    staging = Path(staging).resolve(strict=True)
    if not staging.is_dir() or staging.is_symlink():
        raise VerificationError("staging surface must be a regular directory")
    marker = _read_json(staging / "HUGGINGFACE_SYNC.json", "staging marker")
    manifest = _read_json(staging / "HUGGINGFACE_MANIFEST.json", "staging manifest")
    upload = _read_json(Path(upload_record), "upload record")
    if marker.get("schema") != MARKER_SCHEMA or manifest.get("schema") != MANIFEST_SCHEMA:
        raise VerificationError("staging metadata schema is invalid")
    if upload.get("schema") != UPLOAD_SCHEMA:
        raise VerificationError("upload record schema is invalid")
    if marker.get("source_revision") != source_revision or manifest.get("source_revision") != source_revision:
        raise VerificationError("staging source revision is not the requested commit")
    if upload.get("source_revision") != source_revision or upload.get("repository") != repo_id or upload.get("repo_type") != repo_type:
        raise VerificationError("upload record is not bound to this source and repository")
    upload_commit = upload.get("upload_commit")
    parent_commit = upload.get("parent_commit")
    if not isinstance(upload_commit, str) or not COMMIT_PATTERN.fullmatch(upload_commit):
        raise VerificationError("upload record has no exact upload commit")
    if not isinstance(parent_commit, str) or not COMMIT_PATTERN.fullmatch(parent_commit):
        raise VerificationError("upload record has no exact parent commit")
    if upload.get("branch") != "main":
        raise VerificationError("upload record is not bound to the main branch")
    if upload.get("manifest_sha256") != _sha256(staging / "HUGGINGFACE_MANIFEST.json"):
        raise VerificationError("upload record manifest digest differs from staging")
    records = manifest.get("files")
    if not isinstance(records, dict) or any(
        not isinstance(path, str) or not isinstance(value, dict) or not SHA256_PATTERN.fullmatch(str(value.get("sha256", "")))
        for path, value in records.items()
    ):
        raise VerificationError("staging manifest file records are invalid")
    expected_files = set(records) | {"HUGGINGFACE_SYNC.json", "HUGGINGFACE_MANIFEST.json"}
    if _local_file_set(staging) != expected_files:
        raise VerificationError("staging files do not equal the generated manifest")
    for relative in sorted(records):
        if _safe_remote_path(relative) != relative:
            raise VerificationError("staging manifest contains an unsafe path")
        local_path = staging.joinpath(*PurePosixPath(relative).parts)
        if _sha256(local_path) != records[relative]["sha256"]:
            raise VerificationError(f"staging digest differs from manifest: {relative}")
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise VerificationError("HF_TOKEN is missing; distribution remains INCOMPLETE")
    readback = Path(readback).resolve()
    if readback.exists() or readback.is_symlink():
        raise VerificationError("readback directory must be fresh")
    try:
        from huggingface_hub import HfApi, RepoFile

        api = HfApi(token=token)
        info = api.repo_info(repo_id=repo_id, repo_type=repo_type, revision=upload_commit)
        if getattr(info, "sha", None) != upload_commit:
            raise VerificationError("remote revision does not resolve to the returned upload commit")
        remote_files = {
            _safe_remote_path(item.path)
            for item in api.list_repo_tree(repo_id=repo_id, repo_type=repo_type, revision=upload_commit, recursive=True)
            if isinstance(item, RepoFile)
        }
        if remote_files != expected_files:
            missing = sorted(expected_files - remote_files)
            extra = sorted(remote_files - expected_files)
            raise VerificationError(f"remote file set differs (missing={missing}, extra={extra})")
        readback.mkdir(parents=True)
        for relative in sorted(expected_files):
            downloaded = Path(
                api.hf_hub_download(
                    repo_id=repo_id,
                    filename=relative,
                    repo_type=repo_type,
                    revision=upload_commit,
                    local_dir=readback,
                    token=token,
                )
            ).resolve()
            try:
                downloaded.relative_to(readback)
            except ValueError as error:
                raise VerificationError("Hub download escaped the readback directory") from error
            if downloaded.is_symlink() or not downloaded.is_file():
                raise VerificationError(f"Hub readback is not a regular file: {relative}")
            expected_digest = _sha256(staging / relative)
            if _sha256(downloaded) != expected_digest:
                raise VerificationError(f"Hub readback digest differs: {relative}")
    except VerificationError:
        raise
    except Exception as error:  # pragma: no cover - exercised by the remote service
        raise VerificationError(f"Hub readback failed ({type(error).__name__}); distribution remains INCOMPLETE") from error
    result = {
        "schema": VERIFY_SCHEMA,
        "status": "VERIFIED",
        "repository": repo_id,
        "repo_type": repo_type,
        "source_revision": source_revision,
        "source_url": f"https://github.com/noqt/Lumi-Eggcracker/commit/{source_revision}",
        "parent_commit": parent_commit,
        "upload_commit": upload_commit,
        "remote_file_count": len(remote_files),
        "manifest_sha256": _sha256(staging / "HUGGINGFACE_MANIFEST.json"),
    }
    _write_once(Path(report), result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--repo-type", required=True)
    parser.add_argument("--staging", required=True, type=Path)
    parser.add_argument("--upload-record", required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--readback", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = verify_surface(
            repo_id=args.repo_id,
            repo_type=args.repo_type,
            staging=args.staging,
            upload_record=args.upload_record,
            source_revision=args.source_revision,
            readback=args.readback,
            report=args.report,
        )
    except VerificationError as error:
        print(f"HUGGINGFACE_SYNC_INCOMPLETE: {error}", file=sys.stderr)
        return 2
    print(json.dumps({key: result[key] for key in ("status", "source_revision", "upload_commit", "remote_file_count", "manifest_sha256")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
