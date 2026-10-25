"""Build a deterministic, source-only GGUF file-observer zipapp."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_COMMIT = "5e7e6070fa973016f8ef73e44843e2c4cbbb1f06"
MANIFEST_NAME = "SOURCE-MANIFEST.json"
MANIFEST_SCHEMA = "lumi-eggcracker.gguf-file-source-manifest.v1"
MAIN_MODULE = (
    b"from lumi_eggcracker.gguf_file_observe import main\n"
    b"raise SystemExit(main())\n"
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_MODE = stat.S_IFREG | 0o644
ZIP_CREATE_SYSTEM = 3
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024


# The Git blob ids are deliberately checked without invoking Git.  They bind
# this small preview to the public source revision named above while the
# manifest records the stronger SHA-256 digest of each byte-for-byte member.
SOURCE_INPUTS = (
    ("LICENSE", "LICENSE", "b09cd7856d58590578ee1a4f3ad45d1310a97f87"),
    (
        "src/lumi_eggcracker/__init__.py",
        "lumi_eggcracker/__init__.py",
        "d1cd62d2bce3028bf96ad2f185902dba9b3fddf1",
    ),
    (
        "src/lumi_eggcracker/artifacts.py",
        "lumi_eggcracker/artifacts.py",
        "5ea622bfb1df320e2ffe675df66cbc2d8c20ba81",
    ),
    (
        "src/lumi_eggcracker/detector_catalogue.json",
        "lumi_eggcracker/detector_catalogue.json",
        "23d0592f1df359d954f54d057b9a38ac87d85dff",
    ),
    (
        "src/lumi_eggcracker/detectors.py",
        "lumi_eggcracker/detectors.py",
        "3fa79bc6af1295517da4510985d133444c5a962c",
    ),
    (
        "src/lumi_eggcracker/discovery.py",
        "lumi_eggcracker/discovery.py",
        "10cec85df3931c2b4d775484da9e97cc555927a9",
    ),
    (
        "src/lumi_eggcracker/gguf_file_observe.py",
        "lumi_eggcracker/gguf_file_observe.py",
        "7463a29d883a324b5c05382c2874f175f5bb4aa0",
    ),
    (
        "src/lumi_eggcracker/jsonio.py",
        "lumi_eggcracker/jsonio.py",
        "d09c32d35df2c423aa504f6e178c3820dae765cd",
    ),
    (
        "src/lumi_eggcracker/procfd.py",
        "lumi_eggcracker/procfd.py",
        "1cb27cd57f064eaf9ed1ca0c14146ae46b4191be",
    ),
)

SOURCE_ARCHIVE_NAMES = frozenset(archive_name for _, archive_name, _ in SOURCE_INPUTS)
EXPECTED_ARCHIVE_MEMBERS = frozenset({*SOURCE_ARCHIVE_NAMES, "__main__.py", MANIFEST_NAME})


class BuildError(Exception):
    """The requested source or output path is not safe for this build."""


def _is_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _is_safe_regular(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not _is_reparse(metadata)
    )


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        stat.S_IFMT(metadata.st_mode),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _safe_directory_chain(directory: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(directory)))
    chain = list(reversed((absolute, *absolute.parents)))
    for component in chain:
        try:
            metadata = component.lstat()
        except OSError as error:
            raise BuildError("an input or output parent cannot be inspected") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise BuildError("input and output parents must be real directories")
    return absolute


def _read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    if max_bytes < 1:
        raise BuildError("a source size bound is invalid")
    _safe_directory_chain(path.parent)
    try:
        before = path.lstat()
    except OSError as error:
        raise BuildError("a required source file cannot be inspected") from error
    if not _is_safe_regular(before) or not 1 <= before.st_size <= max_bytes:
        raise BuildError("a required source file is not a bounded regular file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BuildError("a required source file cannot be opened safely") from error

    try:
        opened = os.fstat(descriptor)
        if not _is_safe_regular(opened) or _identity(opened) != _identity(before):
            raise BuildError("a source file changed while being opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise BuildError("a required source file exceeds the size bound")
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            not _is_safe_regular(after_open)
            or not _is_safe_regular(after_path)
            or _identity(opened) != _identity(after_open)
            or _identity(before) != _identity(after_path)
            or total != after_path.st_size
        ):
            raise BuildError("a source file changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise BuildError("a required source file cannot be read safely") from error
    finally:
        os.close(descriptor)


def _git_blob_digest(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{encoded}\n".encode("ascii")


def _validate_members(members: dict[str, bytes]) -> None:
    if set(members) != EXPECTED_ARCHIVE_MEMBERS:
        raise BuildError("the archive member set is not literal")
    for name, data in members.items():
        if not isinstance(name, str) or not isinstance(data, bytes) or not name:
            raise BuildError("an archive member is invalid")
        if len(data) > MAX_MEMBER_BYTES:
            raise BuildError("an archive member exceeds the size bound")


def _source_members() -> dict[str, bytes]:
    members: dict[str, bytes] = {"__main__.py": MAIN_MODULE}
    if len(MAIN_MODULE) > MAX_MEMBER_BYTES:
        raise BuildError("the fixed entry exceeds the member size bound")

    source_manifest: list[dict[str, str]] = []
    for source_name, archive_name, expected_blob in SOURCE_INPUTS:
        limit = MAX_SOURCE_BYTES
        if archive_name == "lumi_eggcracker/artifacts.py":
            limit = min(MAX_SOURCE_BYTES, MAX_ARTIFACT_BYTES)
        data = _read_regular_file(ROOT / source_name, max_bytes=limit)
        actual_blob = _git_blob_digest(data)
        if actual_blob != expected_blob:
            raise BuildError(f"source identity mismatch for {source_name}")
        members[archive_name] = data
        source_manifest.append(
            {
                "git_blob": actual_blob,
                "path": archive_name,
                "sha256": _sha256(data),
                "source": source_name,
            }
        )

    archive_manifest = [
        {"path": name, "sha256": _sha256(members[name])}
        for name in sorted(members)
    ]
    manifest = {
        "archive_member_names": sorted((*members, MANIFEST_NAME)),
        "archive_members": archive_manifest,
        "base_commit": SOURCE_COMMIT,
        "deterministic_metadata": {
            "comment": "",
            "compression": "stored",
            "create_system": ZIP_CREATE_SYSTEM,
            "external_attr": ZIP_MODE << 16,
            "flag_bits": 0,
            "internal_attr": 0,
            "member_order": "lexicographic",
            "timestamp": list(ZIP_TIMESTAMP),
        },
        "schema_version": MANIFEST_SCHEMA,
        "source_members": sorted(source_manifest, key=lambda item: item["path"]),
    }
    manifest_bytes = _canonical_json(manifest)
    if len(manifest_bytes) > MAX_MEMBER_BYTES:
        raise BuildError("the source manifest exceeds the member size bound")
    members[MANIFEST_NAME] = manifest_bytes
    _validate_members(members)
    return members


def _archive_bytes(members: dict[str, bytes]) -> bytes:
    _validate_members(members)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = ZIP_CREATE_SYSTEM
            info.external_attr = ZIP_MODE << 16
            info.internal_attr = 0
            info.flag_bits = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(info, members[name])
    data = output.getvalue()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BuildError("the zipapp exceeds the archive size bound")
    return data


def _absolute_output(path: Path, *, label: str, suffix: str) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.name or absolute.suffix.lower() != suffix:
        raise BuildError(f"{label} must have a {suffix} filename")
    _safe_directory_chain(absolute.parent)
    try:
        absolute.lstat()
    except FileNotFoundError:
        return absolute
    except OSError as error:
        raise BuildError(f"{label} cannot be inspected") from error
    raise BuildError(f"{label} must not already exist")


def _remove_if_owned(path: Path, identity: tuple[int, int]) -> None:
    try:
        metadata = path.lstat()
        if (metadata.st_dev, metadata.st_ino) == identity:
            path.unlink()
    except OSError:
        pass


def _write_new_file(path: Path, data: bytes) -> tuple[int, int]:
    _safe_directory_chain(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o644)
    except OSError as error:
        raise BuildError("an output could not be created without overwriting") from error

    opened = os.fstat(descriptor)
    identity = (opened.st_dev, opened.st_ino)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short output write")
            view = view[written:]
        os.fsync(descriptor)
        return identity
    except OSError as error:
        _remove_if_owned(path, identity)
        raise BuildError("an output could not be written completely") from error
    finally:
        os.close(descriptor)


def _build(output: Path, checksum: Path) -> None:
    output = _absolute_output(output, label="zipapp output", suffix=".pyz")
    checksum = _absolute_output(checksum, label="checksum output", suffix=".sha256")
    if os.path.normcase(os.fspath(output)) == os.path.normcase(os.fspath(checksum)):
        raise BuildError("zipapp and checksum outputs must be different files")

    source_paths = {
        os.path.normcase(os.fspath(Path(os.path.abspath(ROOT / source_name))))
        for source_name, _, _ in SOURCE_INPUTS
    }
    if (
        os.path.normcase(os.fspath(output)) in source_paths
        or os.path.normcase(os.fspath(checksum)) in source_paths
    ):
        raise BuildError("an output path overlaps a source input")

    archive_data = _archive_bytes(_source_members())
    if len(archive_data) > MAX_ARCHIVE_BYTES:
        raise BuildError("the zipapp exceeds the archive size bound")
    archive_digest = _sha256(archive_data)
    checksum_data = f"{archive_digest}  {output.name}\n".encode("ascii")

    created: list[tuple[Path, tuple[int, int]]] = []
    try:
        created.append((output, _write_new_file(output, archive_data)))
        created.append((checksum, _write_new_file(checksum, checksum_data)))
    except BuildError:
        for path, identity in reversed(created):
            _remove_if_owned(path, identity)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new .pyz output path")
    parser.add_argument(
        "--checksum",
        type=Path,
        help="new checksum path (default: adjacent <output>.sha256)",
    )
    args = parser.parse_args()
    output = args.output
    checksum = args.checksum or Path(f"{output}.sha256")
    try:
        _build(output, checksum)
    except BuildError as error:
        print(f"gguf-file zipapp build refused: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("gguf-file zipapp build refused: a file operation failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
