"""Tiny workload-side pre-exec gate; it has no supervisor privileges."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eggcracker internal-gate")
    parser.add_argument("--fifo", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing gated command")
    with args.fifo.open("rb", buffering=0) as gate:
        if gate.read(3) != b"GO\n":
            raise SystemExit("invalid launch-gate release")
    os.execvp(command[0], command)
    return 127
