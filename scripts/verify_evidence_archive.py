"""Verify a portable Eggcracker evidence archive without extracting it."""

from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path

from package_evidence import SCHEMA, archive_entries, digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--require-sha256")
    args = parser.parse_args()
    if (
        args.archive.is_symlink()
        or args.manifest.is_symlink()
        or not args.archive.is_file()
        or not args.manifest.is_file()
    ):
        raise SystemExit("archive and manifest must be regular files")
    try:
        value = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit("portable evidence manifest is invalid") from error
    if set(value) != {"archive", "archive_sha256", "entries", "root", "schema_version"}:
        raise SystemExit("portable evidence manifest schema is invalid")
    actual = digest(args.archive)
    if (
        value["schema_version"] != SCHEMA
        or value["archive"] != args.archive.name
        or value["archive_sha256"] != actual
        or (args.require_sha256 is not None and args.require_sha256 != actual)
    ):
        raise SystemExit("portable evidence archive identity is invalid")
    try:
        entries = archive_entries(args.archive)
    except (OSError, RuntimeError, tarfile.TarError) as error:
        raise SystemExit(str(error)) from error
    if entries != value["entries"]:
        raise SystemExit("portable evidence archive metadata or content differs")
    roots = {entry["path"].split("/", 1)[0] for entry in entries}
    if roots != {value["root"]}:
        raise SystemExit("portable evidence archive root differs")
    print(
        json.dumps(
            {"archive_sha256": actual, "entries": len(entries), "result": "PASS"},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
