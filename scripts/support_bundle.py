"""Write a local redacted support bundle through the installed zipapp."""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

INSTALLED_APP = Path("/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz")


def validated_installed_app(path: Path = INSTALLED_APP) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("Eggcracker is not installed") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise RuntimeError("installed Eggcracker zipapp is not a regular file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("installed Eggcracker zipapp has unsafe ownership or mode")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="write a local redacted Eggcracker support bundle"
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("support bundle must run as root")
    try:
        app = validated_installed_app()
    except RuntimeError as error:
        parser.error(str(error))
    os.execv(
        "/usr/bin/python3",
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(app),
            "support-bundle",
            "--output",
            str(args.output),
        ],
    )
    raise RuntimeError("exec returned unexpectedly")


if __name__ == "__main__":
    raise SystemExit(main())
