"""Mock-only VM-controller journey. No native process, job, QEMU or IPC calls."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
controller_module = importlib.import_module("experiments.human_override.windows_vm_controller")


class MockJudge:
    """Query-only model; a real separate judge process is NOT implemented."""

    def __init__(self, query_handle):
        if (type(query_handle) is not controller_module.MockQueryHandle
                or query_handle.rights != frozenset({"query", "synchronize"})):
            raise ValueError("judge requires query-only handle")
        self.handle = query_handle
        self.identity = dict(query_handle.process.identity)
        self.seen_running = False
        self.lost = False

    def observe(self, identity):
        process = self.handle.process
        if self.lost or identity != self.identity or process.identity != self.identity:
            return "UNKNOWN"
        if process.alive and not process.suspended:
            self.seen_running = True
            return "MOCK_RUNNING"
        if not process.alive and process.exit_code is not None and self.seen_running:
            return "MOCK_VERIFIED_PRIMARY_EXIT"
        return "UNKNOWN"


# Direct/runpy execution uses the same canonical class as imported callers.
# Controller checks exact type and issued query-capability identity.
if __name__ == "__main__":
    MockJudge = importlib.import_module("experiments.human_override.windows_vm_lab").MockJudge


def run(output):
    output = Path(output)
    if not output.is_absolute() or not output.parent.is_dir():
        raise ValueError("fresh absolute output under trusted existing parent required")
    output.mkdir(exist_ok=False)
    cases = []

    def require(condition):
        if not condition:
            raise ValueError("mock journey invariant failed")

    for crash in (False, True):
        kernel = controller_module.MockKernel()
        path = output / ("crash.json" if crash else "stop.json")
        controller = controller_module.Controller(path, kernel, create=True)
        # Kernel-owned B is outside the target controller's only admitted scope A.
        canary_job = kernel.create_job()
        canary = kernel.spawn_suspended(canary_job, 1, controller.config_hash,
                                        atomic_job=True, inherit=False, allocation="B")
        kernel.resume(canary)
        canary_before = asdict(canary)

        def command(operation, judge=None):
            state = controller.state
            return controller.command("human", operation, allocation="A",
                                      generation=state["generation"], epoch=state["epoch"],
                                      sequence=state["sequence"] + 1, judge=judge)

        require(command("approve") == "OK")
        require(command("start") == "MOCK_RUNNING")
        require(controller.process.identity["allocation"] == "A")
        require(canary.identity["allocation"] == "B")
        require(controller.job is not canary_job)
        judge = MockJudge(kernel.duplicate_for_judge(controller.process))
        require(judge.observe(controller.state["identity"]) == "MOCK_RUNNING")
        if crash:
            controller.crash()
            controller = controller_module.Controller(path, kernel)
        else:
            require(command("stop") == "MOCK_STOP_DISPATCHED")
            require(controller.observed(judge) == "MOCK_RUNNING")
            kernel.complete_exit(controller.process)
        require(command("start") == "DENIED")
        require(controller.observed(judge) == "MOCK_VERIFIED_PRIMARY_EXIT")
        require(command("reset", judge) == "OK")
        require(kernel.resumes == 2)  # One target plus one outside mock canary.
        require(command("start") == "DENIED")
        require(command("approve") == "OK")
        require(command("start") == "MOCK_RUNNING")
        require(controller.state["generation"] == 2)
        controller.crash()
        require(canary.alive and not canary.suspended and not canary_job.closed)
        require(asdict(canary) == canary_before)
        cases.append({"case": "controller-loss" if crash else "human-stop", "passed": True,
                      "events": kernel.events, "resumes": kernel.resumes,
                      "canary_allocation": "B", "canary_unchanged_and_running": True})
        kernel.close_job(canary_job)
    paths = ("experiments/human_override/windows_vm_controller.py",
             "experiments/human_override/windows_vm_contract.v1.json",
             "experiments/human_override/windows_vm_lab.py",
             "tests/test_windows_vm_controller.py", "docs/windows-whole-vm-human-stop.md")
    result = {"evidence_label": "IMPLEMENTED_INTERNAL", "evidence_class": "MOCK_ONLY",
              "native_adapter": False, "separate_native_judge": False, "cases": cases,
              "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                                for path in paths},
              "limits": "No Windows API, process creation/termination, real canary, VM or power-loss proof."}
    with (output / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        run(args.output)
    except (OSError, ValueError, AssertionError):
        print("MOCK_ONLY ERROR; no native execution", file=sys.stderr)
        return 2
    print("MOCK_ONLY: 2 journeys PASS; native adapter and independent process judge absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
