"""Public CLI for protected workloads and autonomous AI-runtime enforcement."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import time
from pathlib import Path

from . import __version__
from .brokered.compare_detection_receipts import main as compare_detection_receipts_main
from .client import RequestDeadlineExceeded, request, request_before
from .gate import main as gate_main
from .jsonio import JsonInputError, write_new_json
from .kill_receipt import main as validate_kill_receipt_main
from .kill_receipt import prepare_handoff_main
from .supervisor import main as supervisor_main
from .support_bundle import main as support_bundle_main
from .support_bundle import validate_main as validate_support_bundle_main
from .supported_path_receipt import main as supported_receipt_main
from .watchdog import main as watchdog_main

_DOCTOR_SUMMARY_SCHEMA = "lumi-eggcracker.doctor-summary.v1"
_DOCTOR_SUMMARY_ERROR = "eggcracker: doctor summary unavailable"
_CHECK_START_SCHEMA = "lumi-eggcracker.check-start.v1"
_CHECK_START_ERROR = "eggcracker: check-start response unavailable"
_CHECK_START_REASONS = frozenset(
    {
        "APPROVAL_MISSING",
        "EXACT_APPROVAL_MATCHED",
        "EXECUTION_POLICY_INVALID",
        "INVALID_ARGUMENTS",
        "LOCKDOWN",
        "NAME_UNAVAILABLE",
        "STATE_UNAVAILABLE",
    }
)
_CHECK_START_NEXT_ACTIONS = {
    "EXACT_APPROVAL_MATCHED": (
        "run start --require-approval immediately; admission is revalidated"
    ),
    "APPROVAL_MISSING": (
        "create or restore the exact root approval for this tuple, then check again"
    ),
    "EXECUTION_POLICY_INVALID": (
        "use a valid root-created execution policy or omit it, then check again"
    ),
    "INVALID_ARGUMENTS": "correct the launch tuple, then check again",
    "LOCKDOWN": "clear the exact local lockdown through root recovery, then check again",
    "NAME_UNAVAILABLE": "choose an unused workload name, then check again",
    "STATE_UNAVAILABLE": "repair unavailable supervisor state, then check again",
}
_CHECK_START_RESULTS = frozenset({"READY_TO_ATTEMPT", "NOT_READY"})
_DOCTOR_SUMMARY_INSTALLATION_STATES = frozenset(
    {"HEALTHY", "DRIFT", "RECOVERY_REQUIRED", "NOT_INSTALLED"}
)
_DOCTOR_SUMMARY_NETWORK_MODES = frozenset({"offline", "unsupported"})
_DOCTOR_RECOVERY_PLAN_SCHEMA = "lumi-eggcracker.doctor-recovery-plan.v1"
_DOCTOR_RECOVERY_PLAN_ERROR = "eggcracker: doctor recovery plan unavailable"
_DOCTOR_RECOVERY_PLAN_ACTIONS = {
    "cgroup_v2": "MANUAL_HOST_REVIEW",
    "discovery": "MANUAL_SUPERVISOR_REVIEW",
    "execution_boundary": "MANUAL_POLICY_REVIEW",
    "incidents": "MANUAL_INCIDENT_REVIEW",
    "network_cleanup": "MANUAL_SUPERVISOR_REVIEW",
    "network_mode": "MANUAL_POLICY_REVIEW",
    "network_primitives": "MANUAL_HOST_REVIEW",
    "pidfd": "MANUAL_HOST_REVIEW",
    "receipt_persistence": "MANUAL_SUPERVISOR_REVIEW",
    "supervisor_readiness": "MANUAL_SUPERVISOR_REVIEW",
    "workload_identity": "MANUAL_IDENTITY_REVIEW",
}
_DOCTOR_RECOVERY_PLAN_INSTALLATION_ACTIONS = {
    "NOT_INSTALLED": "MANUAL_INSTALLATION_REQUIRED",
    "DRIFT": "MANUAL_INSTALLATION_REPAIR",
    "RECOVERY_REQUIRED": "MANUAL_INSTALLATION_RECOVERY",
}
_WAIT_PUBLIC_STATUS_KEYS = frozenset(
    {
        "exec_policy_digest",
        "exec_policy_id",
        "incident_lockdown",
        "name",
        "network_mode",
        "run_id",
        "state",
        "unit",
        "workload_uid",
    }
)
_WAIT_ACTIVE_STATES = frozenset({"STARTING", "RUNNING"})
_WAIT_TERMINAL_STATES = frozenset(
    {
        "COMPLETED_ALLOWED",
        "CONTAINED_RECEIPT_FAILED",
        "CONTAINMENT_FAILED",
        "TERMINATED",
    }
)
_WAIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_WAIT_RUN_ID = re.compile(r"[0-9a-f]{24}\Z")
_WAIT_UNIT_PREFIX = "lumi-eggcracker-workload-"
_WAIT_HEX = re.compile(r"[0-9a-f]{64}\Z")
_WAIT_POLL_CADENCE_SECONDS = 0.1
_WAIT_ERROR = "ERROR"
_WAIT_TERMINAL = "TERMINAL"
_WAIT_TIMED_OUT = "TIMED_OUT"


class _DoctorSummaryInvalid(ValueError):
    """The supervisor response cannot be safely reduced to a doctor summary."""


def _doctor_summary(value: object) -> dict[str, object]:
    """Reduce a doctor response to a fixed, nonidentifying health object."""

    if type(value) is not dict:
        raise _DoctorSummaryInvalid

    result = value.get("result")
    if type(result) is not str or result not in {"PASS", "UNSUPPORTED"}:
        raise _DoctorSummaryInvalid

    def required_bool(container: object, key: str) -> bool:
        if type(container) is not dict or key not in container:
            raise _DoctorSummaryInvalid
        item = container[key]
        if type(item) is not bool:
            raise _DoctorSummaryInvalid
        return item

    autonomous_discovery = required_bool(value, "autonomous_discovery")
    cgroup_v2 = required_bool(value, "cgroup_v2")
    pidfd = required_bool(value, "pidfd")

    network = value.get("network")
    if type(network) is not dict:
        raise _DoctorSummaryInvalid
    network_mode = network.get("mode")
    if type(network_mode) is not str or network_mode not in _DOCTOR_SUMMARY_NETWORK_MODES:
        raise _DoctorSummaryInvalid
    network_primitives = network.get("primitives")
    primitives_supported = required_bool(network_primitives, "supported")
    network_cleanup = required_bool(network, "cleanup_healthy")

    execution_boundary = value.get("execution_boundary")
    execution_supported = required_bool(execution_boundary, "supported")

    discovery = value.get("discovery")
    discovery_healthy = required_bool(discovery, "healthy")
    receipt_persistence = required_bool(discovery, "receipt_persistence_healthy")

    incidents = value.get("incidents")
    incidents_healthy = required_bool(incidents, "healthy")
    incidents_lockdown = required_bool(incidents, "lockdown")
    if not incidents_healthy and not incidents_lockdown:
        raise _DoctorSummaryInvalid

    installation = value.get("installation")
    if type(installation) is not dict or "state" not in installation:
        raise _DoctorSummaryInvalid
    installation_state = installation["state"]
    if (
        type(installation_state) is not str
        or installation_state not in _DOCTOR_SUMMARY_INSTALLATION_STATES
    ):
        raise _DoctorSummaryInvalid

    workload_identity = value.get("workload_identity")
    workload_identity_healthy = required_bool(workload_identity, "healthy")

    failed_checks: set[str] = set()
    if not cgroup_v2:
        failed_checks.add("cgroup_v2")
    if not pidfd:
        failed_checks.add("pidfd")
    if network_mode != "offline":
        failed_checks.add("network_mode")
    if not primitives_supported:
        failed_checks.add("network_primitives")
    if not network_cleanup:
        failed_checks.add("network_cleanup")
    if not execution_supported:
        failed_checks.add("execution_boundary")
    if not discovery_healthy:
        failed_checks.add("discovery")
    if not receipt_persistence:
        failed_checks.add("receipt_persistence")
    if not incidents_healthy:
        failed_checks.add("incidents")
    if installation_state != "HEALTHY":
        failed_checks.add("installation")
    if not workload_identity_healthy:
        failed_checks.add("workload_identity")

    if result == "PASS":
        if not autonomous_discovery or failed_checks:
            raise _DoctorSummaryInvalid
        summary_result = "READY"
    else:
        if autonomous_discovery:
            raise _DoctorSummaryInvalid
        if not failed_checks:
            # The supervisor also gates readiness on quarantine_root, which is
            # deliberately not exposed by its public doctor response.
            failed_checks.add("supervisor_readiness")
        summary_result = "NOT_READY"

    return {
        "failed_checks": sorted(failed_checks),
        "next_action": (
            "NONE" if summary_result == "READY" else "REVIEW_SUPERVISOR_READINESS"
        ),
        "result": summary_result,
        "schema": _DOCTOR_SUMMARY_SCHEMA,
    }


def _doctor_recovery_plan(value: object) -> dict[str, object]:
    """Reduce a doctor response to a fixed, nonidentifying recovery plan."""

    summary = _doctor_summary(value)
    installation = value["installation"]
    installation_state = installation["state"]
    failed_checks = summary["failed_checks"]

    actions = {
        _DOCTOR_RECOVERY_PLAN_ACTIONS[check]
        for check in failed_checks
        if check != "installation"
    }
    if installation_state != "HEALTHY":
        actions.add(_DOCTOR_RECOVERY_PLAN_INSTALLATION_ACTIONS[installation_state])

    return {
        "actions": sorted(actions),
        "failed_checks": failed_checks,
        "installation_state": installation_state,
        "result": summary["result"],
        "schema": _DOCTOR_RECOVERY_PLAN_SCHEMA,
    }


def _check_start_projection(value: object) -> dict[str, str]:
    """Accept only the supervisor's fixed, nonidentifying check result."""
    if type(value) is not dict or set(value) != {
        "next_action",
        "reason_code",
        "result",
        "schema",
    }:
        raise ValueError
    schema = value["schema"]
    reason_code = value["reason_code"]
    result = value["result"]
    next_action = value["next_action"]
    if (
        type(schema) is not str
        or schema != _CHECK_START_SCHEMA
        or type(reason_code) is not str
        or reason_code not in _CHECK_START_REASONS
        or type(result) is not str
        or result not in _CHECK_START_RESULTS
        or type(next_action) is not str
        or next_action != _CHECK_START_NEXT_ACTIONS[reason_code]
        or (result == "READY_TO_ATTEMPT") != (reason_code == "EXACT_APPROVAL_MATCHED")
    ):
        raise ValueError
    return {
        "next_action": next_action,
        "reason_code": reason_code,
        "result": result,
        "schema": schema,
    }


def _wait_status_projection(value: object, *, name: str) -> dict[str, object]:
    """Validate and close the supervisor's public run projection."""

    if type(value) is not dict or set(value) != _WAIT_PUBLIC_STATUS_KEYS:
        raise ValueError
    if (
        type(value["name"]) is not str
        or value["name"] != name
        or _WAIT_NAME.fullmatch(value["name"]) is None
    ):
        raise ValueError
    run_id = value["run_id"]
    if type(run_id) is not str or _WAIT_RUN_ID.fullmatch(run_id) is None:
        raise ValueError
    state = value["state"]
    if type(state) is not str or state not in _WAIT_ACTIVE_STATES | _WAIT_TERMINAL_STATES:
        raise ValueError
    unit = value["unit"]
    if type(unit) is not str or unit != f"{_WAIT_UNIT_PREFIX}{run_id}.service":
        raise ValueError
    network_mode = value["network_mode"]
    if type(network_mode) is not str or network_mode not in {"offline", "none"}:
        raise ValueError
    exec_policy_id = value["exec_policy_id"]
    if type(exec_policy_id) is not str or _WAIT_NAME.fullmatch(exec_policy_id) is None:
        raise ValueError
    exec_policy_digest = value["exec_policy_digest"]
    if type(exec_policy_digest) is not str or _WAIT_HEX.fullmatch(exec_policy_digest) is None:
        raise ValueError
    if type(value["incident_lockdown"]) is not bool:
        raise ValueError
    workload_uid = value["workload_uid"]
    if type(workload_uid) is not int or workload_uid < 0:
        raise ValueError
    return {
        "exec_policy_digest": exec_policy_digest,
        "exec_policy_id": exec_policy_id,
        "incident_lockdown": value["incident_lockdown"],
        "name": value["name"],
        "network_mode": network_mode,
        "run_id": run_id,
        "state": state,
        "unit": unit,
        "workload_uid": workload_uid,
    }


class _WaitClock:
    """Read one monotonic clock and reject non-monotonic or invalid samples."""

    def __init__(self) -> None:
        self._last: float | None = None

    def now(self) -> float:
        value = time.monotonic()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or self._last is not None
            and value < self._last
        ):
            raise ValueError
        self._last = float(value)
        return self._last


def _wait_output(marker: str, state: dict[str, object] | None = None) -> None:
    print(marker)
    if state is not None:
        print(json.dumps(state, sort_keys=True))


def _wait_error() -> int:
    print(_WAIT_ERROR, file=sys.stderr)
    return 4


def _wait_main(*, name: str, timeout_seconds: int) -> int:
    clock = _WaitClock()
    try:
        started = clock.now()
        deadline = started + timeout_seconds
        if not math.isfinite(deadline):
            raise ValueError
        last_state: dict[str, object] | None = None
        pinned_run_id: str | None = None
        while True:
            remaining = deadline - clock.now()
            if remaining <= 0:
                _wait_output(_WAIT_TIMED_OUT, last_state)
                return 6
            try:
                value = request_before(
                    "status", deadline_monotonic=deadline, name=name
                )
            except (RequestDeadlineExceeded, TimeoutError):
                _wait_output(_WAIT_TIMED_OUT, last_state)
                return 6
            except Exception:  # noqa: BLE001 - wait failures are constant and closed
                return _wait_error()
            # A response completing at or after the absolute deadline cannot be
            # treated as a validated observation for this bounded wait.
            if clock.now() >= deadline:
                _wait_output(_WAIT_TIMED_OUT, last_state)
                return 6
            try:
                state = _wait_status_projection(value, name=name)
            except Exception:  # noqa: BLE001 - malformed status is constant
                return _wait_error()
            run_id = state["run_id"]
            if pinned_run_id is None:
                pinned_run_id = run_id
            elif run_id != pinned_run_id:
                return _wait_error()
            last_state = state
            if state["state"] in _WAIT_TERMINAL_STATES:
                _wait_output(_WAIT_TERMINAL, state)
                return 0
            remaining = deadline - clock.now()
            if remaining <= 0:
                _wait_output(_WAIT_TIMED_OUT, last_state)
                return 6
            time.sleep(min(_WAIT_POLL_CADENCE_SECONDS, remaining))
    except Exception:  # noqa: BLE001 - clock and sleep failures are constant
        return _wait_error()


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


class _CheckStartParseFailure(Exception):
    """Internal marker for one closed check-start parse failure."""


class _CheckStartHelp(Exception):
    """Internal marker for successfully rendered check-start help."""


class _CheckStartParser(argparse.ArgumentParser):
    """Keep check-start parser failures fixed and nonidentifying."""

    def error(self, message: str) -> None:
        raise _CheckStartParseFailure from None

    def exit(self, status: int = 0, message: str | None = None) -> None:
        if status == 0:
            raise _CheckStartHelp
        raise _CheckStartParseFailure from None


def _add_check_start_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    parser.add_argument("--max-pids", required=True, type=int)
    parser.add_argument("--max-memory-mib", default=2048, type=int)
    parser.add_argument("--cpu-quota-percent", default=400, type=int)
    parser.add_argument(
        "--exec-policy",
        action=_RejectDuplicateIdentifier,
        help="root-created sealed-exec policy identifier",
    )
    parser.add_argument("argv", nargs=argparse.REMAINDER)


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
    start.add_argument(
        "--require-approval",
        action="store_true",
        help="reject the launch unless an exact approval exists at admission time",
    )
    start.add_argument("argv", nargs=argparse.REMAINDER)
    check_start = commands.add_parser(
        "check-start",
        help="check one exact approved launch without reserving or starting it",
    )
    _add_check_start_arguments(check_start)
    kill = commands.add_parser("kill", help="terminate one protected workload")
    kill.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    kill.add_argument("--receipt", required=True, type=Path)
    status = commands.add_parser("status", help="show one protected workload")
    status.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    wait = commands.add_parser(
        "wait", help="wait for one protected workload to reach a terminal state"
    )
    wait.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    wait.add_argument(
        "--timeout-seconds",
        required=True,
        type=_wait_timeout,
        action=_RejectDuplicateIdentifier,
        help="maximum wait duration in seconds (1-300)",
    )
    commands.add_parser("list", help="list protected workloads")
    history = commands.add_parser(
        "history",
        help="list retained terminal records in recorded monotonic order",
    )
    history.add_argument(
        "--limit",
        default=20,
        type=_history_limit,
        action=_RejectDuplicateIdentifier,
        help="number of retained terminal records to return (1-20; default: 20)",
    )
    history.add_argument(
        "--state",
        choices=sorted(_WAIT_TERMINAL_STATES),
        action=_RejectDuplicateIdentifier,
        help="show only records in the selected terminal state",
    )
    approve = commands.add_parser("approve", help="approve one exact AI runtime invocation")
    approve.add_argument("--name", required=True, action=_RejectDuplicateIdentifier)
    approve.add_argument("--uid", required=True, type=int)
    approve.add_argument("--max-pids", default=64, type=int)
    approve.add_argument("--max-memory-mib", default=2048, type=int)
    approve.add_argument("--cpu-quota-percent", default=400, type=int)
    approve.add_argument(
        "--allow-interface-discovery",
        action="store_true",
        help="allow unprivileged interface lookup inside the offline namespace",
    )
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
    doctor = commands.add_parser("doctor", help="check the installed protected supervisor")
    doctor_projection = doctor.add_mutually_exclusive_group()
    doctor_projection.add_argument(
        "--summary",
        action="store_true",
        help="emit a bounded readiness summary instead of the full doctor response",
    )
    doctor_projection.add_argument(
        "--recovery-plan",
        action="store_true",
        help="emit a bounded manual recovery plan instead of the full doctor response",
    )
    support = commands.add_parser(
        "support-bundle", help="write a local redacted health and receipt bundle"
    )
    support.add_argument("--output", required=True, type=Path)
    validate_support = commands.add_parser(
        "validate-support-bundle",
        help="offline structural review of a support bundle",
    )
    validate_support.add_argument("FILE", type=Path)
    validate_kill_receipt = commands.add_parser(
        "validate-kill-receipt",
        help="offline structural review of one manual kill receipt",
    )
    validate_kill_receipt.add_argument("FILE", type=Path)
    handoff = commands.add_parser(
        "prepare-kill-receipt-handoff",
        help="prepare a local redacted manual kill receipt handoff",
    )
    handoff.add_argument("RECEIPT", type=Path)
    handoff.add_argument(
        "--route",
        required=True,
        choices=("q-and-a", "bug-report", "private-security"),
    )
    handoff.add_argument("--output", required=True, type=Path)
    commands.add_parser(
        "compare-detection-receipts",
        help="compare two redacted detection receipt exports",
    )
    commands.add_parser(
        "supported-receipt",
        help="write, verify, compare or summarize bounded local supported-path receipts",
    )
    commands.add_parser("version", help="print the public version")
    return parser


def _command(argv: list[str]) -> list[str]:
    return argv[1:] if argv[:1] == ["--"] else argv


def _history_limit(value: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("history limit must be an integer from 1 to 20")
    result = int(value)
    if not 1 <= result <= 20:
        raise argparse.ArgumentTypeError("history limit must be an integer from 1 to 20")
    return result


def _wait_timeout(value: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("wait timeout must be an integer from 1 to 300")
    result = int(value)
    if not 1 <= result <= 300:
        raise argparse.ArgumentTypeError("wait timeout must be an integer from 1 to 300")
    return result


def _check_start_main(values: list[str]) -> int:
    parser = _CheckStartParser(prog="eggcracker check-start")
    _add_check_start_arguments(parser)
    try:
        args = parser.parse_args(values)
        check_args = {
            "name": args.name,
            "max_pids": args.max_pids,
            "max_memory_mib": args.max_memory_mib,
            "cpu_quota_percent": args.cpu_quota_percent,
            "argv": _command(args.argv),
        }
        if args.exec_policy is not None:
            check_args["exec_policy"] = args.exec_policy
        value = _check_start_projection(request("check_start", **check_args))
    except _CheckStartHelp:
        return 0
    except Exception:  # noqa: BLE001 - parse/transport/shape failures are constant
        print(_CHECK_START_ERROR, file=sys.stderr)
        return 4
    print(json.dumps(value, sort_keys=True))
    return 0 if value["result"] == "READY_TO_ATTEMPT" else 6


def main(argv: list[str] | None = None) -> int:
    values = sys.argv[1:] if argv is None else argv
    if values[:1] == ["supported-receipt"]:
        return supported_receipt_main(
            values[1:], prog="eggcracker supported-receipt"
        )
    if values[:1] == ["check-start"]:
        return _check_start_main(values[1:])
    if values[:1] == ["compare-detection-receipts"]:
        return compare_detection_receipts_main(
            values[1:], prog="eggcracker compare-detection-receipts"
        )
    if values[:1] == ["validate-support-bundle"]:
        if values[1:] == ["--help"]:
            _parser().parse_args(values)
            return 0
        return validate_support_bundle_main(values[1:])
    if values[:1] == ["validate-kill-receipt"]:
        if values[1:] == ["--help"]:
            _parser().parse_args(values)
            return 0
        return validate_kill_receipt_main(values[1:])
    if values[:1] == ["prepare-kill-receipt-handoff"]:
        if values[1:] == ["--help"]:
            _parser().parse_args(values)
            return 0
        return prepare_handoff_main(values[1:])
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
    if args.command == "wait":
        return _wait_main(name=args.name, timeout_seconds=args.timeout_seconds)
    try:
        if args.command == "doctor":
            if args.summary:
                try:
                    summary = _doctor_summary(request("doctor"))
                except Exception:  # noqa: BLE001 - summary failures are intentionally constant
                    print(_DOCTOR_SUMMARY_ERROR, file=sys.stderr)
                    return 6
                print(json.dumps(summary, sort_keys=True))
                return 0 if summary["result"] == "READY" else 6
            if args.recovery_plan:
                try:
                    recovery_plan = _doctor_recovery_plan(request("doctor"))
                except Exception:  # noqa: BLE001 - plan failures are intentionally constant
                    print(_DOCTOR_RECOVERY_PLAN_ERROR, file=sys.stderr)
                    return 6
                print(json.dumps(recovery_plan, sort_keys=True))
                return 0 if recovery_plan["result"] == "READY" else 6
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
            if args.require_approval:
                start_args["require_approval"] = True
            action = start_args.pop("action")
            value = request(action, **start_args)
        elif args.command == "status":
            value = request("status", name=args.name)
        elif args.command == "list":
            value = request("list")
        elif args.command == "history":
            history_args: dict[str, object] = {"limit": args.limit}
            if args.state is not None:
                history_args["state"] = args.state
            value = request("history", **history_args)
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
                allow_interface_discovery=args.allow_interface_discovery,
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
