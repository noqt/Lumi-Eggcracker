"""Run the synthetic brokered-operator example without installed dependencies."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lumi_eggcracker.brokered import BrokeredOperator


def _show(name: str, value: object) -> None:
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    print(json.dumps({name: value}, sort_keys=True, separators=(",", ":")))


def main() -> int:
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


if __name__ == "__main__":
    raise SystemExit(main())
