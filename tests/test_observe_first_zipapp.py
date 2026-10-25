from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_observe_first_zipapp.py"
SOURCE_COMMIT = "47b822ca5d1dcc753535a7c2fcb74aece7f9b73d"
MAIN_MODULE = (
    b"from lumi_eggcracker.observe_first import main\n"
    b"raise SystemExit(main())\n"
)
PINNED_HASHES = {
    "LICENSE": "50e6751797c50dedd75ef1b8a0d9e42f5f8472e9fbce91f34718e9f97b0c780a",
    "lumi_eggcracker/__init__.py": (
        "8ca0bc0b310bfdfad676471477e28fe30d6311fef2c1360dc67a2c530e2acf34"
    ),
    "lumi_eggcracker/observe_first.py": (
        "428997c394c5fc853e0fe5cce82b1c3eae2d09b2b72c27f35bea3e1ff9be2152"
    ),
    "lumi_eggcracker/detectors.py": (
        "d2f0485dbac785dce2bb5bcef451ddcb49fb5200f03e13b19acdcada3581bab7"
    ),
    "lumi_eggcracker/jsonio.py": (
        "8d4955af0399dd478add5e50c2c2edc9f100ebeec49223d50c13280aef85dc15"
    ),
    "lumi_eggcracker/detector_catalogue.json": (
        "e0556219f7012b0657366af84804a1f3b5874d9f281a1341b4fa8ae819962c6d"
    ),
}
MANIFEST_NAME = "SOURCE-MANIFEST.json"
MANIFEST_SCHEMA = "lumi-eggcracker.observe-first-source-manifest.v1"


def _run_builder(
    output: Path, *, checksum: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    command = [sys.executable, str(BUILDER), "--output", str(output)]
    if checksum is not None:
        command.extend(["--checksum", str(checksum)])
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(command, capture_output=True, cwd=ROOT, env=environment, check=False)


def _reference_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONPATH"] = str(ROOT / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _expected_members() -> dict[str, str]:
    return {**PINNED_HASHES, "__main__.py": hashlib.sha256(MAIN_MODULE).hexdigest()}


def test_build_is_deterministic_and_binds_exact_source_members() -> None:
    with tempfile.TemporaryDirectory(prefix="observe-first-zipapp-build-") as raw:
        directory = Path(raw)
        first = directory / "first.pyz"
        second = directory / "second.pyz"
        second_checksum = directory / "second-checksum.sha256"
        first_result = _run_builder(first)
        second_result = _run_builder(second, checksum=second_checksum)

        assert first_result.returncode == 0, first_result.stderr.decode("utf-8", errors="replace")
        assert second_result.returncode == 0, second_result.stderr.decode("utf-8", errors="replace")
        assert first.read_bytes() == second.read_bytes()

        first_checksum = Path(f"{first}.sha256")
        first_digest = hashlib.sha256(first.read_bytes()).hexdigest()
        second_digest = hashlib.sha256(second.read_bytes()).hexdigest()
        assert first_checksum.read_text(encoding="ascii") == f"{first_digest}  {first.name}\n"
        assert second_checksum.read_text(encoding="ascii") == f"{second_digest}  {second.name}\n"

        expected_members = _expected_members()
        with zipfile.ZipFile(first) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            assert names == sorted(names)
            assert set(names) == {*expected_members, MANIFEST_NAME}
            for info in infos:
                assert info.date_time == (1980, 1, 1, 0, 0, 0)
                assert info.create_system == 3
                assert info.compress_type == zipfile.ZIP_STORED
                assert stat.S_IFMT(info.external_attr >> 16) == stat.S_IFREG
                assert stat.S_IMODE(info.external_attr >> 16) == 0o644

            for name, expected_digest in expected_members.items():
                member = archive.read(name)
                assert hashlib.sha256(member).hexdigest() == expected_digest
            assert archive.read("__main__.py") == MAIN_MODULE

            expected_manifest = {
                "base_commit": SOURCE_COMMIT,
                "members": [
                    {"path": name, "sha256": expected_members[name]}
                    for name in sorted(expected_members)
                ],
                "schema_version": MANIFEST_SCHEMA,
            }
            manifest_bytes = archive.read(MANIFEST_NAME)
            assert manifest_bytes == (
                json.dumps(expected_manifest, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("utf-8")


def test_zipapp_matches_pinned_source_module_and_rejects_malformed_input() -> None:
    with tempfile.TemporaryDirectory(prefix="observe-first-zipapp-run-") as raw:
        directory = Path(raw)
        archive_path = directory / "observe-first.pyz"
        result = _run_builder(archive_path)
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")

        run_directory = directory / "clean-cwd"
        run_directory.mkdir()
        archive_environment = os.environ.copy()
        archive_environment.pop("PYTHONPATH", None)
        archive_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        reference_environment = _reference_environment()

        cases = (
            ("benign.json", ()),
            ("complete-match.json", ()),
            ("partial-match.json", ()),
            ("complete-match.json", ("--explain-selection",)),
        )
        for fixture_name, flags in cases:
            fixture = ROOT / "examples" / "observe-first" / fixture_name
            archive_command = [sys.executable, str(archive_path), *flags, str(fixture)]
            archive_result = subprocess.run(
                archive_command,
                capture_output=True,
                cwd=run_directory,
                env=archive_environment,
                check=False,
            )
            source_command = [
                sys.executable,
                "-m",
                "lumi_eggcracker.observe_first",
                *flags,
                str(fixture),
            ]
            source_result = subprocess.run(
                source_command,
                capture_output=True,
                cwd=run_directory,
                env=reference_environment,
                check=False,
            )
            assert archive_result.returncode == source_result.returncode
            assert archive_result.returncode == 0, archive_result.stderr.decode(
                "utf-8", errors="replace"
            )
            assert source_result.returncode == 0, source_result.stderr.decode(
                "utf-8", errors="replace"
            )
            assert archive_result.stderr == source_result.stderr
            assert json.loads(archive_result.stdout) == json.loads(source_result.stdout)
            assert archive_result.stdout == source_result.stdout

        malformed = run_directory / "malformed.json"
        malformed.write_bytes(b'{"schema_version":')
        malformed_result = subprocess.run(
            [sys.executable, str(archive_path), str(malformed)],
            capture_output=True,
            cwd=run_directory,
            env=archive_environment,
            check=False,
        )
        assert malformed_result.returncode == 2
        assert malformed_result.stdout == b""
        assert b"Traceback" not in malformed_result.stderr
