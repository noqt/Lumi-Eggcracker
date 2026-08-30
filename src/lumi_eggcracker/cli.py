"""Public CLI for protected workloads and autonomous AI-runtime enforcement."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .client import request
from .gate import main as gate_main
from .jsonio import JsonInputError, write_new_json
from .supervisor import main as supervisor_main
from .support_bundle import main as support_bundle_main
from .watchdog import main as watchdog_main


class _RejectDuplicateIdentifier(argparse.Action):
    """Accept one identifier option and fail closed on a repeated spelling."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        marker = f"_eggcracker_seen_{self.dest}"
        if getattr(namespace, marker, False):
            raise argparse.ArgumentError(
                self,
                f"{option_string or self.dest} may only be specified once",
            )
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eggcracker")
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="launch an explicitly selected protected workload")
    start.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    start.add_argument("--max-pids", required=True, type=int)
    start.add_argument("--max-memory-mib", default=2048, type=int)
    start.add_argument("--cpu-quota-percent", default=400, type=int)
    start.add_argument(
        "--exec-policy",
        action=_RejectDuplicateIdentifier,
        help="root-created sealed-exec policy identifier",
    )
    start.add_argument("argv", nargs=argparse.REMAINDER)
    kill = commands.add_parser("kill", help="terminate one protected workload")
    kill.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    kill.add_argument("--receipt", required=True, type=Path)
    status = commands.add_parser("status", help="show one protected workload")
    status.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    commands.add_parser("list", help="list protected workloads")
    approve = commands.add_parser("approve", help="approve one exact AI runtime invocation")
    approve.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    approve.add_argument("--uid", required=True, type=int)
    approve.add_argument("--max-pids", default=64, type=int)
    approve.add_argument("--max-memory-mib", default=2048, type=int)
    approve.add_argument("--cpu-quota-percent", default=400, type=int)
    approve.add_argument("argv", nargs=argparse.REMAINDER)
    revoke = commands.add_parser("revoke", help="revoke one exact AI runtime approval")
    revoke.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    commands.add_parser("approvals", help="list exact AI runtime approvals")
    exec_policy = commands.add_parser("exec-policy", help="manage root-created executable policies")
    exec_commands = exec_policy.add_subparsers(dest="exec_action", required=True)
    create_policy = exec_commands.add_parser("create", help="create an immutable executable policy")
    create_policy.add_argument(
        "--name", required=True, action=_RejectDuplicateIdentifier
    )
    create_policy.add_argument("paths", nargs=argparse.REMAINDER)
    revoke_policy = exec_commands.add_parser("revoke", help="revoke an executable policy")
    revoke_policy.add_argument(
        "--policy-id", required=True, action=_RejectDuplicateIdentifier
    )
    exec_commands.add_parser("list", help="list executable policies")
    commands.add_parser("detections", help="list autonomous containment summaries")
    commands.add_parser("incidents", help="list bounded local lockdown incidents")
    incident = commands.add_parser("incident", help="inspect or clear one local lockdown incident")
    incident_commands = incident.add_subparsers(dest="incident_action", required=True)
    for action, help_text in (
        ("show", "show one root-only incident detail"),
        ("acknowledge", "acknowledge one incident as root"),
        ("clear", "clear one local lockdown as root"),
    ):
        command = incident_commands.add_parser(action, help=help_text)
        command.add_argument("incident_id")
    commands.add_parser("doctor", help="check the installed protected supervisor")
    support = commands.add_parser(
        "support-bundle", help="write a local redacted health and receipt bundle"
    )
    support.add_argument("--output", required=True, type=Path)
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
    if values[:1] == ["_watchdog"]:
        return watchdog_main(values[1:])
    args = _parser().parse_args(values)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "support-bundle":
        return support_bundle_main(args.output)
    try:
        if args.command == "doctor":
            value = request("doctor")
            print(json.dumps(value, sort_keys=True))
            return 0 if value.get("result") == "PASS" else 6
        if args.command == "start":
            start_args = {
                "action": "start",
                "name": args.name,
                "max_pids": args.max_pids,
                "max_memory_mib": args.max_memory_mib,
                "cpu_quota_percent": args.cpu_quota_percent,
                "argv": _command(args.argv),
            }
            if args.exec_policy is not None:
                start_args["exec_policy"] = args.exec_policy
            action = start_args.pop("action")
            value = request(action, **start_args)
        elif args.command == "status":
            value = request("status", name=args.name)
        elif args.command == "list":
            value = request("list")
        elif args.command == "approve":
            if os.geteuid() != 0:
                raise JsonInputError("approve requires root administrative authority; use sudo")
            value = request(
                "approve",
                name=args.name,
                uid=args.uid,
                max_pids=args.max_pids,
                max_memory_mib=args.max_memory_mib,
                cpu_quota_percent=args.cpu_quota_percent,
                argv=_command(args.argv),
            )
        elif args.command == "revoke":
            if os.geteuid() != 0:
                raise JsonInputError("revoke requires root administrative authority; use sudo")
            value = request("revoke", name=args.name)
        elif args.command == "approvals":
            value = request("approvals")
        elif args.command == "exec-policy":
            if args.exec_action == "list":
                value = request("exec_policies")
            elif args.exec_action == "create":
                if os.geteuid() != 0:
                    raise JsonInputError("execution policy creation requires root administrative authority; use sudo")
                value = request("exec_policy_create", name=args.name, paths=_command(args.paths))
            else:
                if os.geteuid() != 0:
                    raise JsonInputError("execution policy revocation requires root administrative authority; use sudo")
                value = request("exec_policy_revoke", policy_id=args.policy_id)
        elif args.command == "detections":
            value = request("detections")
        elif args.command == "incidents":
            value = request("incidents")
        elif args.command == "incident":
            if os.geteuid() != 0:
                raise JsonInputError("incident administration requires root administrative authority; use sudo")
            action = {
                "show": "incident_show",
                "acknowledge": "incident_acknowledge",
                "clear": "incident_clear",
            }[args.incident_action]
            value = request(action, incident_id=args.incident_id)
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
