"""Run the synthetic brokered-operator example without installed dependencies."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lumi_eggcracker.brokered import BrokeredOperator

_RUN_FAILURE_STAGES = frozenset(
    {
        "client_setup",
        "submit",
        "admission_validation",
        "dispatch",
        "dispatch_validation",
        "result",
        "result_validation",
        "outcome_serialization",
        "outcome_output",
    }
)
_RUN_VALIDATED_STAGES = frozenset({"admission", "dispatch"})
_MAX_RUN_FAILURE_BYTES = 256


def _show(name: str, value: object) -> None:
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    print(json.dumps({name: value}, sort_keys=True, separators=(",", ":")))


def _valid_queue_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 32
        and all(character in "0123456789abcdef" for character in value)
    )


def _report_run_failure(
    failed_stage: str,
    queue_id: object = None,
    last_validated_stage: str | None = None,
    effect_status: str = "UNKNOWN",
) -> None:
    if failed_stage not in _RUN_FAILURE_STAGES:
        failed_stage = "outcome_output"
    validated_queue_id = queue_id if _valid_queue_id(queue_id) else None
    if validated_queue_id is None:
        last_validated_stage = None
        effect_status = "UNKNOWN"
    else:
        if last_validated_stage not in _RUN_VALIDATED_STAGES:
            last_validated_stage = "admission"
        if effect_status != "CONFIRMED_APPLIED" or last_validated_stage != "dispatch":
            effect_status = "UNKNOWN"

    details: dict[str, str] = {
        "effect_status": effect_status,
        "error": "failed closed",
        "failed_stage": failed_stage,
    }
    if validated_queue_id is not None:
        details["last_validated_stage"] = last_validated_stage
        details["queue_id"] = validated_queue_id
    encoded = json.dumps(
        {"run_failure": details},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _MAX_RUN_FAILURE_BYTES:
        raise RuntimeError("bounded run diagnostic exceeded its fixed limit")
    print(encoded.decode("utf-8"), file=sys.stderr)


def _run_one_shot(client: Any, operation_id: str, ipc: Any) -> int:
    failed_stage = "submit"
    queue_id: str | None = None
    last_validated_stage: str | None = None
    effect_status = "UNKNOWN"
    try:
        admission = client.submit(operation_id)
        failed_stage = "admission_validation"
        admission_receipt = _validated_receipt(
            admission,
            ipc,
            phase="admission",
            outcome="QUEUED",
            code="ADMITTED",
            effect_applied=False,
        )
        queue_id = admission_receipt["queue_id"]
        last_validated_stage = "admission"

        failed_stage = "dispatch"
        dispatch = client.dispatch(queue_id)
        failed_stage = "dispatch_validation"
        dispatch_receipt = _validated_receipt(
            dispatch,
            ipc,
            phase="dispatch",
            outcome="APPLIED",
            code="EFFECT_APPLIED",
            effect_applied=True,
            queue_id=queue_id,
        )
        if not _valid_queue_id(dispatch_receipt.get("queue_id")):
            raise ValueError("dispatch receipt queue identifier is invalid")
        last_validated_stage = "dispatch"
        effect_status = "CONFIRMED_APPLIED"

        failed_stage = "result"
        result = client.get_result(queue_id)
        failed_stage = "result_validation"
        _validated_result(result, queue_id, ipc)
        outcome = {"run": {"admission": admission, "dispatch": dispatch, "result": result}}
        failed_stage = "outcome_serialization"
        encoded = json.dumps(
            outcome,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > (3 * ipc.MAX_IPC_RESPONSE_BYTES) + 128:
            raise ValueError("combined response exceeds its output bound")
        failed_stage = "outcome_output"
        print(encoded.decode("utf-8"))
        return 0
    except Exception:  # noqa: BLE001 - any client error must fail closed
        _report_run_failure(failed_stage, queue_id, last_validated_stage, effect_status)
        return 1


def _validated_receipt(
    response: object,
    ipc: Any,
    *,
    phase: str,
    outcome: str,
    code: str,
    effect_applied: bool,
    queue_id: str | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(response, dict)
        or set(response) != {"receipt", "schema_version"}
        or type(response["schema_version"]) is not str
        or response["schema_version"] != ipc.IPC_SCHEMA
    ):
        raise ValueError("receipt response is malformed")
    receipt = response["receipt"]
    if (
        not ipc._valid_receipt(receipt)
        or receipt.get("phase") != phase
        or receipt.get("outcome") != outcome
        or receipt.get("code") != code
        or receipt.get("effect_applied") is not effect_applied
        or not _valid_queue_id(receipt.get("queue_id"))
        or (queue_id is not None and receipt.get("queue_id") != queue_id)
    ):
        raise ValueError("receipt did not match the required stage")
    return receipt


def _validated_result(response: object, queue_id: str, ipc: Any) -> None:
    if not isinstance(response, dict):
        raise TypeError("result response is malformed")
    required = {"outcome", "phase", "queue_id", "report", "schema_version"}
    if (
        not required <= set(response)
        or set(response) - required
        or type(response["schema_version"]) is not str
        or response["schema_version"] != ipc.IPC_SCHEMA
        or response["phase"] != "result"
        or response["outcome"] != "AVAILABLE"
        or not _valid_queue_id(response["queue_id"])
        or response["queue_id"] != queue_id
        or not ipc._valid_report(response["report"])
        or len(ipc._canonical_json(response["report"])) > ipc.MAX_RESULT_BYTES
    ):
        raise ValueError("result did not match the required stage")


def portable_demo() -> int:
    with tempfile.TemporaryDirectory(prefix="brokered-operator-demo-") as temporary:
        state_dir = Path(temporary) / "state"
        registrar, operator = BrokeredOperator.bootstrap(state_dir)
        grant = registrar.register_run()
        client = operator.client(grant)

        allowed_queue = client.admit("demo-allowed-1")
        _show("admission", allowed_queue)
        applied = operator.dispatch(allowed_queue.queue_id)
        _show("dispatch", applied)
        _show("replayed_dispatch", operator.dispatch(allowed_queue.queue_id))

        stale_queue = client.admit("demo-stale-1")
        _show("queued_before_stop_request", stale_queue)
        _show("stop_request_revocation", operator.request_stop(grant.run_id))
        _show("stale_queued_dispatch", operator.dispatch(stale_queue.queue_id))
        _show("post_stop_admission", client.admit("demo-post-stop-1"))
        _show("verified_process_stop", operator.verified_process_stop(grant.run_id))

        before_reopen = operator.world_snapshot()
        _show("before_reopen", before_reopen.__dict__)
        _, reopened = BrokeredOperator.open(state_dir)
        _show("after_reopen", reopened.world_snapshot().__dict__)
        _show("reopened_stale_dispatch", reopened.dispatch(stale_queue.queue_id))
        return 0


def linux_ipc_demo(arguments: argparse.Namespace) -> int:
    if sys.platform != "linux" or not hasattr(os, "geteuid"):
        raise SystemExit("--linux-ipc modes require Linux")
    from lumi_eggcracker.brokered import linux_ipc
    from lumi_eggcracker.brokered.linux_ipc import BrokeredLinuxClient, BrokeredLinuxService

    if arguments.linux_ipc == "serve":
        required = (arguments.state_dir, arguments.socket, arguments.workload_uid, arguments.workload_gid)
        if any(value is None for value in required):
            raise SystemExit("serve requires --state-dir, --socket, --workload-uid and --workload-gid")
        service = BrokeredLinuxService.open(
            arguments.state_dir,
            arguments.socket,
            workload_uid=arguments.workload_uid,
            workload_gid=arguments.workload_gid,
        )
        try:
            with service:
                _show(
                    "service",
                    {
                        "ipc": "AF_UNIX/SOCK_SEQPACKET",
                        "ready": True,
                        "process_stop": "UNSUPPORTED",
                    },
                )
                service.serve_forever()
        except KeyboardInterrupt:
            _show("trusted_stop_request", service.request_stop())
        return 0

    if arguments.linux_ipc in {"submit", "dispatch", "result", "run"}:
        if arguments.socket is None or arguments.service_uid is None:
            raise SystemExit(f"{arguments.linux_ipc} requires --socket and --service-uid")
        if arguments.linux_ipc == "run" and arguments.operation_id is None:
            raise SystemExit("run requires --operation-id")
        if arguments.linux_ipc == "run":
            try:
                client = BrokeredLinuxClient(arguments.socket, service_uid=arguments.service_uid)
            except Exception:  # noqa: BLE001 - any client setup error must fail closed
                _report_run_failure("client_setup")
                return 1
            return _run_one_shot(client, arguments.operation_id, linux_ipc)
        client = BrokeredLinuxClient(arguments.socket, service_uid=arguments.service_uid)
        if arguments.linux_ipc == "submit":
            if arguments.operation_id is None:
                raise SystemExit("submit requires --operation-id")
            _show("submission", client.submit(arguments.operation_id))
        else:
            if arguments.queue_id is None:
                raise SystemExit(f"{arguments.linux_ipc} requires --queue-id")
            if arguments.linux_ipc == "dispatch":
                _show("dispatch", client.dispatch(arguments.queue_id))
            else:
                _show("result", client.get_result(arguments.queue_id))
        return 0

    if arguments.linux_ipc in {"stop", "snapshot"}:
        if arguments.state_dir is None:
            raise SystemExit(f"{arguments.linux_ipc} requires --state-dir")
        _, operator = BrokeredOperator.open(arguments.state_dir)
        operator._assert_service_state_owner(os.geteuid())
        if arguments.linux_ipc == "stop":
            grant = operator._existing_service_run_grant()
            _show("authority_fence", operator.request_stop(grant.run_id))
            _show("verified_process_stop", operator.verified_process_stop(grant.run_id))
        else:
            snapshot = operator.world_snapshot()
            _show(
                "synthetic_world",
                {
                    "protected_effects": snapshot.protected_effects,
                    "unrelated_canary_allocation": snapshot.unrelated_canary_allocation,
                },
            )
            grant = operator._existing_service_run_grant()
            _show("verified_process_stop", operator.verified_process_stop(grant.run_id))
        return 0

    raise SystemExit("unsupported Linux IPC demo mode")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--linux-ipc",
        choices=("serve", "submit", "dispatch", "result", "run", "stop", "snapshot"),
        help="run one side of the Linux authenticated local-IPC demonstration",
    )
    parser.add_argument("--state-dir")
    parser.add_argument("--socket")
    parser.add_argument("--workload-uid", type=int)
    parser.add_argument("--workload-gid", type=int)
    parser.add_argument("--service-uid", type=int)
    parser.add_argument("--operation-id")
    parser.add_argument("--queue-id")
    arguments = parser.parse_args(argv)
    if arguments.linux_ipc is None:
        return portable_demo()
    return linux_ipc_demo(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
