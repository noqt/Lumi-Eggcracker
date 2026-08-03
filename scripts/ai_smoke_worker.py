"""Workload-side stdout/stderr routing for the real-AI smoke test."""

from __future__ import annotations

import argparse
import os
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdout", required=True, type=Path)
    parser.add_argument("--stderr", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing AI runner command")
    stdout = os.open(args.stdout, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    stderr = os.open(args.stderr, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.dup2(stdout, 1)
        os.dup2(stderr, 2)
    finally:
        os.close(stdout)
        os.close(stderr)
    os.execv(command[0], command)
    return 127
