from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import build_gguf_file_zipapp as builder

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_gguf_file_zipapp.py"
SOURCE_COMMIT = "5e7e6070fa973016f8ef73e44843e2c4cbbb1f06"
MANIFEST_NAME = "SOURCE-MANIFEST.json"
MANIFEST_SCHEMA = "lumi-eggcracker.gguf-file-source-manifest.v1"
MAIN_MODULE = (
    b"from lumi_eggcracker.gguf_file_observe import main\n"
    b"raise SystemExit(main())\n"
)
SOURCE_BLOBS = {
    "LICENSE": "b09cd7856d58590578ee1a4f3ad45d1310a97f87",
    "lumi_eggcracker/__init__.py": "d1cd62d2bce3028bf96ad2f185902dba9b3fddf1",
    "lumi_eggcracker/artifacts.py": "5ea622bfb1df320e2ffe675df66cbc2d8c20ba81",
    "lumi_eggcracker/detector_catalogue.json": "23d0592f1df359d954f54d057b9a38ac87d85dff",
    "lumi_eggcracker/detectors.py": "3fa79bc6af1295517da4510985d133444c5a962c",
    "lumi_eggcracker/discovery.py": "10cec85df3931c2b4d775484da9e97cc555927a9",
    "lumi_eggcracker/gguf_file_observe.py": "7463a29d883a324b5c05382c2874f175f5bb4aa0",
    "lumi_eggcracker/jsonio.py": "d09c32d35df2c423aa504f6e178c3820dae765cd",
    "lumi_eggcracker/procfd.py": "1cb27cd57f064eaf9ed1ca0c14146ae46b4191be",
}
EXPECTED_MEMBERS = {*SOURCE_BLOBS, "__main__.py", MANIFEST_NAME}


def _run_builder(
    output: Path, *, checksum: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    command = [sys.executable, str(BUILDER), "--output", str(output)]
    if checksum is not None:
        command.extend(["--checksum", str(checksum)])
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, check=False)


def _copy_source_tree(destination: Path) -> None:
    for source_name, _, _ in builder.SOURCE_INPUTS:
        source = ROOT / source_name
        target = destination / (
            "src/lumi_eggcracker" if source_name.startswith("src/") else ""
        ) / source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


class GgufFileZipappTests(unittest.TestCase):
    def test_build_is_deterministic_and_binds_exact_source_members(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gguf-file-zipapp-build-") as raw:
            directory = Path(raw)
            first = directory / "first.pyz"
            second = directory / "second.pyz"
            second_checksum = directory / "second.sha256"
            first_result = _run_builder(first)
            second_result = _run_builder(second, checksum=second_checksum)
            self.assertEqual(
                0,
                first_result.returncode,
                first_result.stderr.decode(errors="replace"),
            )
            self.assertEqual(
                0,
                second_result.returncode,
                second_result.stderr.decode(errors="replace"),
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())

            first_checksum = Path(f"{first}.sha256")
            first_digest = hashlib.sha256(first.read_bytes()).hexdigest()
            second_digest = hashlib.sha256(second.read_bytes()).hexdigest()
            self.assertEqual(
                f"{first_digest}  {first.name}\n",
                first_checksum.read_text(encoding="ascii"),
            )
            self.assertEqual(
                f"{second_digest}  {second.name}\n",
                second_checksum.read_text(encoding="ascii"),
            )

            with zipfile.ZipFile(first) as archive:
                infos = archive.infolist()
                self.assertEqual(
                    sorted(EXPECTED_MEMBERS), [item.filename for item in infos]
                )
                self.assertEqual(EXPECTED_MEMBERS, {item.filename for item in infos})
                for info in infos:
                    self.assertEqual(builder.ZIP_TIMESTAMP, info.date_time)
                    self.assertEqual(builder.ZIP_CREATE_SYSTEM, info.create_system)
                    self.assertEqual(zipfile.ZIP_STORED, info.compress_type)
                    self.assertEqual(0, info.flag_bits)
                    self.assertEqual(stat.S_IFREG, stat.S_IFMT(info.external_attr >> 16))
                    self.assertEqual(0o644, stat.S_IMODE(info.external_attr >> 16))

                self.assertEqual(MAIN_MODULE, archive.read("__main__.py"))
                for name in SOURCE_BLOBS:
                    member = archive.read(name)
                    source = ROOT / ("LICENSE" if name == "LICENSE" else f"src/{name}")
                    self.assertEqual(source.read_bytes(), member)

                manifest_bytes = archive.read(MANIFEST_NAME)
                manifest = json.loads(manifest_bytes)
                self.assertEqual(SOURCE_COMMIT, manifest["base_commit"])
                self.assertEqual(MANIFEST_SCHEMA, manifest["schema_version"])
                self.assertEqual(
                    sorted(EXPECTED_MEMBERS), manifest["archive_member_names"]
                )
                self.assertEqual(
                    {
                        "comment": "",
                        "compression": "stored",
                        "create_system": 3,
                        "external_attr": builder.ZIP_MODE << 16,
                        "flag_bits": 0,
                        "internal_attr": 0,
                        "member_order": "lexicographic",
                        "timestamp": list(builder.ZIP_TIMESTAMP),
                    },
                    manifest["deterministic_metadata"],
                )

                expected_archive_digests = {
                    name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in EXPECTED_MEMBERS
                    if name != MANIFEST_NAME
                }
                self.assertEqual(
                    expected_archive_digests,
                    {
                        item["path"]: item["sha256"]
                        for item in manifest["archive_members"]
                    },
                )
                expected_sources = {
                    name: hashlib.sha256(archive.read(name)).hexdigest()
                    for name in SOURCE_BLOBS
                }
                self.assertEqual(
                    expected_sources,
                    {
                        item["path"]: item["sha256"]
                        for item in manifest["source_members"]
                    },
                )
                self.assertEqual(
                    SOURCE_BLOBS,
                    {
                        item["path"]: item["git_blob"]
                        for item in manifest["source_members"]
                    },
                )
                self.assertEqual(
                    (
                        json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode("ascii"),
                    manifest_bytes,
                )

    def test_rejects_existing_outputs_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gguf-file-zipapp-existing-") as raw:
            directory = Path(raw)
            output = directory / "existing.pyz"
            checksum = directory / "existing.sha256"
            output.write_bytes(b"keep archive")
            checksum.write_bytes(b"keep checksum")

            result = _run_builder(output, checksum=checksum)
            self.assertEqual(2, result.returncode)
            self.assertEqual(b"keep archive", output.read_bytes())
            self.assertEqual(b"keep checksum", checksum.read_bytes())

    def test_tampered_source_is_refused_before_creating_outputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gguf-file-zipapp-tamper-") as raw:
            directory = Path(raw)
            source_root = directory / "source"
            _copy_source_tree(source_root)
            tampered = source_root / "src/lumi_eggcracker/discovery.py"
            tampered.write_bytes(tampered.read_bytes() + b"tampered\n")
            output = directory / "out" / "artifact.pyz"
            checksum = directory / "out" / "artifact.sha256"
            output.parent.mkdir()

            with (
                patch.object(builder, "ROOT", source_root),
                self.assertRaisesRegex(builder.BuildError, "source identity mismatch"),
            ):
                builder._build(output, checksum)
            self.assertFalse(output.exists())
            self.assertFalse(checksum.exists())

    def test_rejects_unsafe_source_and_output_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gguf-file-zipapp-boundary-") as raw:
            directory = Path(raw)
            source_root = directory / "source"
            _copy_source_tree(source_root)
            (source_root / "src/lumi_eggcracker/procfd.py").unlink()
            (source_root / "src/lumi_eggcracker/procfd.py").mkdir()
            output = directory / "valid" / "artifact.pyz"
            checksum = directory / "valid" / "artifact.sha256"
            output.parent.mkdir()
            with (
                patch.object(builder, "ROOT", source_root),
                self.assertRaisesRegex(builder.BuildError, "bounded regular file"),
            ):
                builder._build(output, checksum)
            self.assertFalse(output.exists())
            self.assertFalse(checksum.exists())

            bad_parent = directory / "not-a-directory"
            bad_parent.write_bytes(b"file")
            result = _run_builder(bad_parent / "artifact.pyz")
            self.assertEqual(2, result.returncode)
            self.assertFalse((bad_parent / "artifact.pyz").exists())

    def test_rejects_nonliteral_or_oversized_archive_members(self) -> None:
        members = {name: b"" for name in builder.EXPECTED_ARCHIVE_MEMBERS}
        with self.assertRaisesRegex(builder.BuildError, "member set"):
            builder._archive_bytes({**members, "unexpected": b""})

        members["lumi_eggcracker/artifacts.py"] = b"x" * (builder.MAX_MEMBER_BYTES + 1)
        with self.assertRaisesRegex(builder.BuildError, "member exceeds"):
            builder._archive_bytes(members)

    def test_nonblocking_open_rejects_nonregular_descriptor_and_closes_it(self) -> None:
        path = Path("selected")
        descriptor = 73
        nonblock = 1 << 20
        regular = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=11,
            st_ino=22,
            st_size=1,
            st_mtime_ns=33,
        )
        nonregular = SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        with (
            patch.object(builder, "_safe_directory_chain"),
            patch.object(builder.os, "O_NONBLOCK", nonblock, create=True),
            patch.object(Path, "lstat", return_value=regular) as lstat,
            patch.object(builder.os, "open", return_value=descriptor) as open_file,
            patch.object(builder.os, "fstat", return_value=nonregular) as fstat,
            patch.object(builder.os, "close") as close,
            self.assertRaisesRegex(builder.BuildError, "changed while being opened"),
        ):
            builder._read_regular_file(path, max_bytes=1024)

        lstat.assert_called_once_with()
        open_file.assert_called_once()
        opened_path, flags = open_file.call_args.args
        self.assertEqual(path, opened_path)
        self.assertEqual(nonblock, flags & nonblock)
        fstat.assert_called_once_with(descriptor)
        close.assert_called_once_with(descriptor)
