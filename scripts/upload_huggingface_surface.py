#!/usr/bin/env python3
"""Upload one prepared Hub surface and record its compare-and-swap commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
MARKER_SCHEMA = "noqt.huggingface_sync.v1"
UPLOAD_SCHEMA = "noqt.huggingface_upload.v1"
REMOTE_MARKER = "HUGGINGFACE_SYNC.json"


class UploadError(RuntimeError):
    """Raised when a Hub upload cannot be bound safely."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_once(path: Path, value: dict[str, Any]) -> None:
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise UploadError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _remote_source_revision(api: Any, repo_id: str, repo_type: str, parent: str, token: str) -> str:
    try:
        marker_path = Path(
            api.hf_hub_download(
                repo_id=repo_id,
                filename=REMOTE_MARKER,
                repo_type=repo_type,
                revision=parent,
                token=token,
            )
        )
        if marker_path.is_symlink() or not marker_path.is_file():
            raise UploadError("remote source marker is not a regular file")
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except UploadError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UploadError("remote source marker is unreadable; distribution remains INCOMPLETE") from error
    if not isinstance(marker, dict):
        raise UploadError("remote source marker is not an object; distribution remains INCOMPLETE")
    source_revision = marker.get("source_revision")
    if marker.get("schema") != MARKER_SCHEMA or not isinstance(source_revision, str) or not COMMIT_PATTERN.fullmatch(source_revision):
        raise UploadError("remote source marker has no exact source commit; distribution remains INCOMPLETE")
    return source_revision


def _require_source_ancestry(source_root: Path, ancestor: str, descendant: str) -> None:
    source_root = Path(source_root)
    if source_root.is_symlink():
        raise UploadError("source root must not be a symlink")
    try:
        source_root = source_root.resolve(strict=True)
    except OSError as error:
        raise UploadError("source root is unavailable; distribution remains INCOMPLETE") from error
    if not source_root.is_dir():
        raise UploadError("source root is not a directory; distribution remains INCOMPLETE")
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "merge-base", "--is-ancestor", ancestor, descendant],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise UploadError("cannot verify remote source ancestry; distribution remains INCOMPLETE") from error
    if result.returncode != 0:
        raise UploadError("remote source is not an ancestor of the candidate; distribution remains INCOMPLETE")


def upload_surface(
    *,
    repo_id: str,
    repo_type: str,
    folder: Path,
    revision: str,
    source_revision: str,
    output: Path,
    source_root: Path = Path("."),
) -> dict[str, Any]:
    if repo_type != "space":
        raise UploadError("only the configured Space repository type is supported")
    if not COMMIT_PATTERN.fullmatch(source_revision):
        raise UploadError("source revision must be an exact 40-character commit")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise UploadError(f"output already exists: {output}")
    folder = Path(folder)
    if folder.is_symlink():
        raise UploadError("upload folder must not be a symlink")
    folder = folder.resolve(strict=True)
    if not folder.is_dir() or folder.is_symlink():
        raise UploadError("upload folder must be a regular directory")
    marker_path = folder / "HUGGINGFACE_SYNC.json"
    manifest_path = folder / "HUGGINGFACE_MANIFEST.json"
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UploadError("prepared surface metadata is unreadable") from error
    if (
        marker.get("schema") != MARKER_SCHEMA
        or marker.get("source_revision") != source_revision
        or manifest.get("source_revision") != source_revision
        or marker.get("manifest_sha256") != _sha256(manifest_path)
    ):
        raise UploadError("prepared surface is not bound to the requested source revision")
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise UploadError("HF_TOKEN is missing; distribution remains INCOMPLETE")
    try:
        from huggingface_hub import HfApi

        api = HfApi(token=token)
        parent = api.repo_info(repo_id=repo_id, repo_type=repo_type, revision=revision).sha
        if not isinstance(parent, str) or not COMMIT_PATTERN.fullmatch(parent):
            raise UploadError("remote parent revision is not an exact commit")
        remote_source_revision = _remote_source_revision(api, repo_id, repo_type, parent, token)
        _require_source_ancestry(source_root, remote_source_revision, source_revision)
        commit = api.upload_folder(
            repo_id=repo_id,
            repo_type=repo_type,
            folder_path=folder,
            path_in_repo=".",
            revision=revision,
            parent_commit=parent,
            commit_message=f"Sync GitHub source {source_revision}",
            commit_description=(
                "Canonical source: "
                f"https://github.com/noqt/Lumi-Eggcracker/commit/{source_revision}"
            ),
            delete_patterns=["*"],
            token=token,
        )
    except UploadError:
        raise
    except Exception as error:  # pragma: no cover - exercised by the remote service
        raise UploadError(f"Hub upload failed ({type(error).__name__}); distribution remains INCOMPLETE") from error
    upload_commit = getattr(commit, "oid", None)
    commit_url = getattr(commit, "commit_url", None)
    if not isinstance(upload_commit, str) or not COMMIT_PATTERN.fullmatch(upload_commit):
        raise UploadError("Hub upload returned no exact commit; distribution remains INCOMPLETE")
    if not isinstance(commit_url, str) or not commit_url.startswith("https://huggingface.co/"):
        raise UploadError("Hub upload returned no canonical commit link")
    result = {
        "schema": UPLOAD_SCHEMA,
        "repository": repo_id,
        "repo_type": repo_type,
        "branch": revision,
        "source_revision": source_revision,
        "source_url": f"https://github.com/noqt/Lumi-Eggcracker/commit/{source_revision}",
        "parent_commit": parent,
        "upload_commit": upload_commit,
        "commit_url": commit_url,
        "manifest_sha256": marker["manifest_sha256"],
    }
    _write_once(Path(output), result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-id", required=True)
    parser.add_argument("--repo-type", required=True)
    parser.add_argument("--folder", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, default=Path("."))
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = upload_surface(
            repo_id=args.repo_id,
            repo_type=args.repo_type,
            folder=args.folder,
            revision=args.revision,
            source_revision=args.source_revision,
            output=args.output,
            source_root=args.source_root,
        )
    except UploadError as error:
        print(f"HUGGINGFACE_SYNC_INCOMPLETE: {error}", file=sys.stderr)
        return 2
    print(json.dumps({key: result[key] for key in ("source_revision", "parent_commit", "upload_commit", "manifest_sha256")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
