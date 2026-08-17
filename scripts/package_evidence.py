"""Create a POSIX-metadata-preserving evidence archive and detached manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "lumi-eggcracker.portable-evidence.v1"
ROOT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_entries(root: Path) -> Iterator[Path]:
    yield root
    if root.is_symlink() or not root.is_dir():
        return
    for child in sorted(root.iterdir(), key=lambda item: item.name):
        yield from source_entries(child)


def safe_member_name(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or value.startswith(("/", "\\"))
        or "\\" in value
        or str(path) != value.rstrip("/")
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RuntimeError("archive member path is unsafe")
    return path


def safe_link(member: tarfile.TarInfo, names: set[str], *, hardlink: bool) -> None:
    target = PurePosixPath(member.linkname)
    if target.is_absolute() or "\\" in member.linkname:
        raise RuntimeError("archive link target is unsafe")
    if hardlink:
        resolved = safe_member_name(member.linkname)
        if str(resolved) not in names:
            raise RuntimeError("archive hardlink target is missing")
    else:
        resolved = PurePosixPath(
            os.path.normpath(str(PurePosixPath(member.name).parent / target)).replace(
                "\\", "/"
            )
        )
        source_root = PurePosixPath(member.name).parts[0]
        if any(part == ".." for part in resolved.parts) or resolved.parts[:1] != (
            source_root,
        ):
            raise RuntimeError("archive symlink target escapes")


def archive_entries(path: Path) -> list[dict[str, Any]]:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [str(safe_member_name(member.name)) for member in members]
        if len(names) != len(set(names)):
            raise RuntimeError("archive contains duplicate members")
        known = set(names)
        result: list[dict[str, Any]] = []
        for member in members:
            common: dict[str, Any] = {
                "gid": member.gid,
                "mode": member.mode,
                "mtime": member.mtime,
                "path": member.name,
                "uid": member.uid,
            }
            if member.isdir():
                common["type"] = "directory"
            elif member.isfile():
                handle = archive.extractfile(member)
                if handle is None:
                    raise RuntimeError("archive regular member cannot be read")
                value = hashlib.sha256()
                while block := handle.read(1024 * 1024):
                    value.update(block)
                common.update(
                    {"sha256": value.hexdigest(), "size": member.size, "type": "file"}
                )
            elif member.issym():
                safe_link(member, known, hardlink=False)
                common.update({"target": member.linkname, "type": "symlink"})
            elif member.islnk():
                safe_link(member, known, hardlink=True)
                common.update({"target": member.linkname, "type": "hardlink"})
            else:
                raise RuntimeError("archive contains an unsupported member type")
            result.append(common)
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root-name")
    args = parser.parse_args()
    supplied_root = args.evidence
    root = supplied_root.resolve(strict=True)
    root_name = args.root_name or root.name
    manifest_path = Path(str(args.output) + ".manifest.json")
    checksum_path = Path(str(args.output) + ".sha256")
    if (
        supplied_root.is_symlink()
        or not root.is_dir()
        or not ROOT_NAME.fullmatch(root_name)
        or args.output.suffixes[-2:] != [".tar", ".gz"]
        or not args.output.parent.is_dir()
        or any(path.exists() or path.is_symlink() for path in (args.output, manifest_path, checksum_path))
    ):
        raise SystemExit("evidence archive arguments are invalid or outputs already exist")
    try:
        args.output.resolve().relative_to(root)
    except ValueError:
        pass
    else:
        raise SystemExit("evidence archive cannot be written inside its source")

    with tarfile.open(
        args.output, "w:gz", format=tarfile.PAX_FORMAT, dereference=False
    ) as archive:
        for path in source_entries(root):
            relative = path.relative_to(root)
            name = root_name if not relative.parts else f"{root_name}/{relative.as_posix()}"
            archive.add(path, arcname=name, recursive=False)

    entries = archive_entries(args.output)
    value = {
        "archive": args.output.name,
        "archive_sha256": digest(args.output),
        "entries": entries,
        "root": root_name,
        "schema_version": SCHEMA,
    }
    manifest_path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    checksum_path.write_text(f"{value['archive_sha256']}  {args.output.name}\n", encoding="ascii")
    print(json.dumps({"entries": len(entries), "result": "PASS"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
