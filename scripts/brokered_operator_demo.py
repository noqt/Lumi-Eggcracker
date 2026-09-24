"""Run the synthetic brokered-operator example without installed dependencies."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lumi_eggcracker.brokered import BrokeredOperator


def _show(name: str, value: object) -> None:
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    print(json.dumps({name: value}, sort_keys=True, separators=(",", ":")))


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

    if arguments.linux_ipc in {"submit", "dispatch", "result"}:
        if arguments.socket is None or arguments.service_uid is None:
            raise SystemExit(f"{arguments.linux_ipc} requires --socket and --service-uid")
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
        choices=("serve", "submit", "dispatch", "result", "stop", "snapshot"),
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
