"""Reproducible source-checkout CLI for the SIMULATION_ONLY human-stop model."""

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
model = importlib.import_module("experiments.human_override.model")
SOURCE_PATHS = (
    "experiments/counter_ai/protocol.v1.json",
    "experiments/human_override/scenarios.v1.json",
    "experiments/human_override/model.py",
    "experiments/human_override/lab.py",
    "tests/test_human_override_lab.py",
    "docs/human-override-prototype.md",
)


def run_case(case, directory):
    directory.mkdir()
    world = model.World()
    path = directory / "controller.json"
    controller = model.Controller(path, world, create=True)
    trace = []
    for index, step in enumerate(case["steps"]):
        allocation = step.get("allocation", "A")
        action = step["action"]
        if action == "command":
            row = controller.allocations[allocation]
            principal = step.get("principal", "human")
            event = {"op": step["op"], "allocation": allocation,
                     "generation": row.generation, "epoch": row.epoch,
                     "sequence": row.sequence[principal] + 1}
            outcome = controller.command(principal, event)
        elif action == "adapter":
            outcome = controller.adapter(allocation, cancel_remote=step.get("cancel_remote", False))
        elif action == "observe":
            outcome = controller.observe(allocation, fail=step.get("fail", False))
        elif action == "reload":
            controller = model.Controller(path, world)
            outcome = controller.storage_ok
        elif action == "effect":
            outcome = world.effect(allocation, step["kind"])
        elif action == "control":
            outcome = controller.set_control(allocation, step["available"])
        elif action == "advance":
            world.advance(step["ticks"])
            outcome = True
        else:
            raise ValueError("unknown manifest action")
        status = controller.status(allocation)
        execution = asdict(world.allocations[allocation])
        checks = [type(outcome) is type(step["expect"]), outcome == step["expect"]]
        for key, expected in step.get("status", {}).items():
            checks.append(status[key] == expected)
        for key, expected in step.get("execution", {}).items():
            checks.append(execution[key] == expected)
        trace.append({"index": index, "tick": world.tick, "action": action,
                      "allocation": allocation, "outcome": outcome, "status": status,
                      "execution": execution, "pass": all(checks)})
    return {"id": case["id"], "pass": all(row["pass"] for row in trace), "trace": trace}


def run(output):
    output = Path(output)
    if not output.is_absolute() or not output.parent.is_dir():
        raise ValueError("output must be a fresh absolute directory with an existing trusted parent")
    # No overwrite, recovery cleanup, or attacker-controlled output paths are supported.
    output.mkdir(exist_ok=False)
    manifest = model.bounded_json((ROOT / SOURCE_PATHS[1]).read_bytes())
    protocol = model.bounded_json((ROOT / SOURCE_PATHS[0]).read_bytes())
    if manifest["schema"] != "human-stop-scenarios.v1" or protocol["schema"] != "counter-ai.v1":
        raise ValueError("manifest/protocol version")
    cases = [run_case(case, output / f"case-{index:02d}")
             for index, case in enumerate(manifest["cases"])]
    result = {
        "schema": "human-stop-result.v1", "evidence_label": "IMPLEMENTED_INTERNAL",
        "evidence_class": "SIMULATION_ONLY", "result": "PASS" if all(
            case["pass"] for case in cases) else "FAIL",
        "approved_stop_relaunch": next(case["pass"] for case in cases
                                       if case["id"] == "approved-stop-relaunch"),
        "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                          for path in SOURCE_PATHS},
        "cases": cases,
        "limitations": ["trusted synthetic driver, no authentication or real isolation",
                        "no real termination, sockets, credentials or provider calls",
                        "no AI detector evaluation or native efficacy evidence"],
    }
    with (output / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = run(args.output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SIMULATION_ONLY ERROR: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(f"SIMULATION_ONLY {result['result']}: {len(result['cases'])} cases")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
