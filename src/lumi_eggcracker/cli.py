"""Public CLI for protected workloads and autonomous AI-runtime enforcement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .client import request
from .gate import main as gate_main
from .jsonio import JsonInputError, write_new_json
from .supervisor import main as supervisor_main


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eggcracker")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="launch an explicitly selected protected workload")
    start.add_argument("--name", required=True)
    start.add_argument("--max-pids", required=True, type=int)
    start.add_argument("argv", nargs=argparse.REMAINDER)
    kill = commands.add_parser("kill", help="terminate one protected workload")
    kill.add_argument("--name", required=True)
    kill.add_argument("--receipt", required=True, type=Path)
    status = commands.add_parser("status", help="show one protected workload")
    status.add_argument("--name", required=True)
    commands.add_parser("list", help="list protected workloads")
    approve = commands.add_parser("approve", help="approve one exact AI runtime invocation")
    approve.add_argument("--name", required=True)
    approve.add_argument("--uid", required=True, type=int)
    approve.add_argument("argv", nargs=argparse.REMAINDER)
    revoke = commands.add_parser("revoke", help="revoke one exact AI runtime approval")
    revoke.add_argument("--name", required=True)
    commands.add_parser("approvals", help="list exact AI runtime approvals")
    commands.add_parser("detections", help="list autonomous containment summaries")
    commands.add_parser("doctor", help="check the installed protected supervisor")
    commands.add_parser("version", help="print the public version")
    return parser


def _command(argv: list[str]) -> list[str]:
    return argv[1:] if argv[:1] == ["--"] else argv


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if values[:1] == ["_supervisor"]:
        return supervisor_main(values[1:])
    if values[:1] == ["_gate"]:
        return gate_main(values[1:])
    args = _parser().parse_args(values)
    if args.command == "version":
        print(__version__)
        return 0
    try:
        if args.command == "doctor":
            value = request("doctor")
            print(json.dumps(value, sort_keys=True))
            return 0 if value.get("result") == "PASS" else 6
        if args.command == "start":
            value = request("start", name=args.name, max_pids=args.max_pids, argv=_command(args.argv))
        elif args.command == "status":
            value = request("status", name=args.name)
        elif args.command == "list":
            value = request("list")
        elif args.command == "approve":
            value = request("approve", name=args.name, uid=args.uid, argv=_command(args.argv))
        elif args.command == "revoke":
            value = request("revoke", name=args.name)
        elif args.command == "approvals":
            value = request("approvals")
        elif args.command == "detections":
            value = request("detections")
        else:
            # This validation is deliberately read-only: no receipt reservation before kill.
            if args.receipt.exists() or args.receipt.is_symlink() or not args.receipt.parent.is_dir():
                raise JsonInputError("receipt must be a new file under an existing directory")
            value = request("kill", name=args.name)
            write_new_json(args.receipt, value)
        print(json.dumps(value, sort_keys=True))
        return 0
    except (JsonInputError, OSError) as error:
        print(f"eggcracker: {error}", file=sys.stderr)
        return 4
