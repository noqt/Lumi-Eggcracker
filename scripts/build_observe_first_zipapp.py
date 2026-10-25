"""Build a deterministic source-only observe-first zipapp."""

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
SOURCE_COMMIT = "47b822ca5d1dcc753535a7c2fcb74aece7f9b73d"
MAIN_MODULE = (
    b"from lumi_eggcracker.observe_first import main\n"
    b"raise SystemExit(main())\n"
)
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_MODE = stat.S_IFREG | 0o644
MAX_SOURCE_BYTES = 8 * 1024 * 1024

SOURCE_INPUTS = (
    ("LICENSE", "LICENSE", "50e6751797c50dedd75ef1b8a0d9e42f5f8472e9fbce91f34718e9f97b0c780a"),
    (
        "src/lumi_eggcracker/__init__.py",
        "lumi_eggcracker/__init__.py",
        "8ca0bc0b310bfdfad676471477e28fe30d6311fef2c1360dc67a2c530e2acf34",
    ),
    (
        "src/lumi_eggcracker/observe_first.py",
        "lumi_eggcracker/observe_first.py",
        "428997c394c5fc853e0fe5cce82b1c3eae2d09b2b72c27f35bea3e1ff9be2152",
    ),
    (
        "src/lumi_eggcracker/detectors.py",
        "lumi_eggcracker/detectors.py",
        "d2f0485dbac785dce2bb5bcef451ddcb49fb5200f03e13b19acdcada3581bab7",
    ),
    (
        "src/lumi_eggcracker/jsonio.py",
        "lumi_eggcracker/jsonio.py",
        "8d4955af0399dd478add5e50c2c2edc9f100ebeec49223d50c13280aef85dc15",
    ),
    (
        "src/lumi_eggcracker/detector_catalogue.json",
        "lumi_eggcracker/detector_catalogue.json",
        "e0556219f7012b0657366af84804a1f3b5874d9f281a1341b4fa8ae819962c6d",
    ),
)


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


def _read_regular_file(path: Path) -> bytes:
    _safe_directory_chain(path.parent)
    try:
        before = path.lstat()
    except OSError as error:
        raise BuildError("a required source file cannot be inspected") from error
    if not _is_safe_regular(before) or not 1 <= before.st_size <= MAX_SOURCE_BYTES:
        raise BuildError("a required source file is not a bounded regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
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
            chunk = os.read(descriptor, min(64 * 1024, MAX_SOURCE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
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


def _canonical_json(value: object) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{encoded}\n".encode("utf-8")


def _source_members() -> dict[str, bytes]:
    members = {"__main__.py": MAIN_MODULE}
    for source_name, archive_name, expected_digest in SOURCE_INPUTS:
        data = _read_regular_file(ROOT / source_name)
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != expected_digest:
            raise BuildError(f"source identity mismatch for {source_name}")
        members[archive_name] = data

    manifest = {
        "base_commit": SOURCE_COMMIT,
        "members": [
            {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(members.items())
        ],
        "schema_version": "lumi-eggcracker.observe-first-source-manifest.v1",
    }
    members["SOURCE-MANIFEST.json"] = _canonical_json(manifest)
    return members


def _archive_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for name in sorted(members):
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = ZIP_MODE << 16
            info.internal_attr = 0
            info.flag_bits = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(info, members[name])
    return output.getvalue()


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

    for source_name, _, _ in SOURCE_INPUTS:
        source = Path(os.path.abspath(os.fspath(ROOT / source_name)))
        if os.path.normcase(os.fspath(source)) in {
            os.path.normcase(os.fspath(output)),
            os.path.normcase(os.fspath(checksum)),
        }:
            raise BuildError("an output path overlaps a source input")

    archive_data = _archive_bytes(_source_members())
    archive_digest = hashlib.sha256(archive_data).hexdigest()
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
        print(f"observe-first zipapp build refused: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("observe-first zipapp build refused: a file operation failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
