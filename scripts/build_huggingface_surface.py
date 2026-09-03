#!/usr/bin/env python3
"""Build the deterministic Hugging Face distribution snapshot from GitHub source."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
POLICY_SCHEMA = "noqt.huggingface_distribution.v1"
MANIFEST_SCHEMA = "noqt.huggingface_manifest.v1"
MARKER_SCHEMA = "noqt.huggingface_sync.v1"
WINDOWS_RESERVED_NAMES = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
RETIRED_PUBLIC_REFERENCE_PARTS = ("scadastrangelove/", "awesome-ai-security-tools")


class SurfaceBuildError(RuntimeError):
    """Raised when a distribution snapshot cannot be built safely."""


def _load_policy(payload: bytes) -> dict[str, Any]:
    try:
        policy = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SurfaceBuildError("cannot read committed sync policy") from exc
    if policy.get("schema") != POLICY_SCHEMA:
        raise SurfaceBuildError("unsupported Hugging Face sync policy schema")
    return policy


def _git(source_root: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SurfaceBuildError("cannot read the requested Git source commit") from exc
    return result.stdout


def _portable_path(value: str, label: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    if (
        not value
        or relative.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ".." in relative.parts
        or "\\" in value
        or relative.as_posix() != value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise SurfaceBuildError(f"{label} is unsafe or non-portable")
    for component in relative.parts:
        if (
            component.endswith((" ", "."))
            or any(ord(character) < 32 or character in '<>:"\\|?*' for character in component)
            or component.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES
        ):
            raise SurfaceBuildError(f"{label} is unsafe or non-portable")
    return relative


def _tree_path(raw_path: bytes) -> PurePosixPath:
    try:
        decoded_path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SurfaceBuildError("Git tree path is not valid UTF-8") from exc
    return _portable_path(decoded_path, "Git tree path")


def _portable_key(path: PurePosixPath) -> str:
    return unicodedata.normalize("NFC", path.as_posix()).casefold()


def _require_unique_paths(paths: list[PurePosixPath], label: str) -> None:
    seen: set[str] = set()
    for path in paths:
        key = _portable_key(path)
        if key in seen:
            raise SurfaceBuildError(f"{label} contains a portable path collision")
        seen.add(key)


def _policy_root_file(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str):
        raise SurfaceBuildError(f"{label} must be a root filename")
    path = _portable_path(value, label)
    if len(path.parts) != 1:
        raise SurfaceBuildError(f"{label} must be a root filename")
    return path


def _destination(output: Path, relative: PurePosixPath) -> Path:
    destination = output.joinpath(*relative.parts).resolve()
    try:
        destination.relative_to(output)
    except ValueError as exc:
        raise SurfaceBuildError(f"committed path escapes output directory: {relative}") from exc
    return destination


def _committed_files(source_root: Path, source_revision: str) -> dict[PurePosixPath, tuple[str, bytes]]:
    resolved = _git(source_root, "rev-parse", "--verify", f"{source_revision}^{{commit}}")
    try:
        resolved_revision = resolved.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise SurfaceBuildError("Git returned an invalid source revision") from exc
    if resolved_revision != source_revision:
        raise SurfaceBuildError("source revision does not identify the requested exact commit")

    committed: dict[PurePosixPath, tuple[str, bytes]] = {}
    for raw_entry in _git(source_root, "ls-tree", "-r", "-z", "--full-tree", source_revision).split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            raw_mode, raw_type, raw_object_id = metadata.split(b" ")
            mode = raw_mode.decode("ascii")
            relative = _tree_path(raw_path)
            object_type = raw_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise SurfaceBuildError("Git tree contains an invalid entry") from exc
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise SurfaceBuildError(f"unsupported committed entry: {relative}")
        committed[relative] = (mode, _git(source_root, "cat-file", "blob", object_id))
    if not committed:
        raise SurfaceBuildError("Git source commit contains no files")
    _require_unique_paths(list(committed), "Git source commit")
    return committed


def _is_excluded(path: PurePosixPath, excluded_prefixes: list[str]) -> bool:
    value = path.as_posix()
    return any(value == prefix.rstrip("/") or value.startswith(prefix) for prefix in excluded_prefixes)


def _render(template: str, values: dict[str, str], label: str) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    if "{{SOURCE_" in rendered:
        raise SurfaceBuildError(f"unresolved source token in {label}")
    return rendered


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> bytes:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return payload


def build_surface(source_root: Path, output: Path, source_revision: str) -> dict[str, Any]:
    """Build one immutable candidate snapshot and return its bounded summary."""

    source_root = source_root.resolve(strict=True)
    output = output.resolve()
    if not REVISION_PATTERN.fullmatch(source_revision):
        raise SurfaceBuildError("source revision must be one lowercase 40-character Git SHA")
    if output == source_root:
        raise SurfaceBuildError("output directory cannot be the source repository")
    if output.exists():
        raise SurfaceBuildError("output directory already exists; use a fresh task path")

    committed_files = _committed_files(source_root, source_revision)
    try:
        policy = _load_policy(committed_files[PurePosixPath("huggingface-sync-policy.json")][1])
    except KeyError as exc:
        raise SurfaceBuildError("source commit has no Hugging Face sync policy") from exc
    excluded = policy.get("excluded_prefixes")
    if not isinstance(excluded, list) or not all(isinstance(item, str) for item in excluded):
        raise SurfaceBuildError("sync policy excluded_prefixes must be a string list")
    marker_relative = _policy_root_file(policy.get("source_marker"), "source_marker")
    manifest_relative = _policy_root_file(policy.get("manifest"), "manifest")
    _require_unique_paths([marker_relative, manifest_relative], "sync policy outputs")

    copied_paths = [relative for relative in committed_files if not _is_excluded(relative, excluded)]
    copied_keys = {
        *(_portable_key(relative) for relative in copied_paths),
        _portable_key(PurePosixPath("README.md")),
        _portable_key(PurePosixPath("index.html")),
    }
    for special_path in (marker_relative, manifest_relative):
        if _portable_key(special_path) in copied_keys:
            raise SurfaceBuildError(f"sync output collides with committed source: {special_path}")

    output.mkdir(parents=True)
    copied = 0
    for relative in sorted(copied_paths, key=lambda item: item.as_posix()):
        mode, payload = committed_files[relative]
        destination = _destination(output, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        destination.chmod(0o755 if mode == "100755" else 0o644)
        copied += 1

    canonical = policy["canonical"]
    target = policy["target"]
    overlays = policy["overlays"]
    values = {
        "SOURCE_REVISION": source_revision,
        "SOURCE_SHORT": source_revision[:12],
        "SOURCE_URL": f"{canonical['repository']}/commit/{source_revision}",
    }

    readme_path = output / "README.md"
    try:
        canonical_readme = committed_files[PurePosixPath("README.md")][1].decode("utf-8")
    except (KeyError, UnicodeDecodeError) as exc:
        raise SurfaceBuildError("source commit has no valid UTF-8 README") from exc
    canonical_clone = (
        f"git clone {canonical['repository']}.git\ncd {canonical['checkout_directory']}"
    )
    hub_clone = (
        f"git clone https://huggingface.co/spaces/{target['repo_id']}\n"
        f"cd {target['checkout_directory']}"
    )
    if canonical_readme.count(canonical_clone) != 1:
        raise SurfaceBuildError("canonical README clone block changed; review the Hub overlay")
    hub_readme = canonical_readme.replace(canonical_clone, hub_clone, 1)
    try:
        preamble_template = committed_files[PurePosixPath(overlays["readme_preamble"])][1].decode("utf-8")
        index_template = committed_files[PurePosixPath(overlays["static_index"])][1].decode("utf-8")
    except (KeyError, TypeError, UnicodeDecodeError) as exc:
        raise SurfaceBuildError("source commit has no valid Hugging Face overlay") from exc
    preamble = _render(preamble_template, values, "README preamble")
    hub_readme = preamble.rstrip() + "\n\n" + hub_readme.lstrip()

    hub_index = _render(index_template, values, "static index")
    retired_reference = "".join(RETIRED_PUBLIC_REFERENCE_PARTS)
    retired_digest = hashlib.sha256(retired_reference.encode("utf-8")).hexdigest()
    if retired_digest not in policy.get("forbidden_public_reference_sha256", []):
        raise SurfaceBuildError("sync policy does not bind the retired public reference")
    readme_path.write_text(hub_readme, encoding="utf-8", newline="\n")
    (output / "index.html").write_text(hub_index, encoding="utf-8", newline="\n")

    retired_bytes = retired_reference.encode("utf-8")
    for path in output.rglob("*"):
        if path.is_file() and retired_bytes in path.read_bytes():
            raise SurfaceBuildError("retired public reference remains in Hub surface")

    file_records: dict[str, dict[str, Any]] = {}
    for path in sorted(output.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(output).as_posix()
        if relative in {marker_relative.as_posix(), manifest_relative.as_posix()}:
            continue
        file_records[relative] = {"sha256": _sha256(path), "size": path.stat().st_size}

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "source_repository": canonical["repository"],
        "source_revision": source_revision,
        "files": file_records,
    }
    manifest_bytes = _write_json(_destination(output, manifest_relative), manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    marker = {
        "schema": MARKER_SCHEMA,
        "mode": policy["mode"],
        "source_repository": canonical["repository"],
        "source_revision": source_revision,
        "target": target["url"],
        "manifest": manifest_relative.as_posix(),
        "manifest_sha256": manifest_sha256,
        "mirrored_files": len(file_records),
    }
    _write_json(_destination(output, marker_relative), marker)
    return {
        "source_revision": source_revision,
        "copied_tracked_files": copied,
        "mirrored_files": len(file_records) + 2,
        "manifest_sha256": manifest_sha256,
        "output": str(output),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        summary = build_surface(args.source_root, args.output, args.source_revision)
    except SurfaceBuildError as exc:
        raise SystemExit(f"Hugging Face surface build failed: {exc}") from exc
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
