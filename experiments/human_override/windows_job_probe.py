"""Print a hash-bound SOURCE_ONLY probe proposal; native modes always refuse."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    "experiments/human_override/windows_job_backend.py",
    "experiments/human_override/windows_job_probe.py",
    "tests/test_windows_job_backend.py",
    "docs/windows-whole-vm-human-stop.md",
    "experiments/human_override/windows_vm_contract.v1.json",
)


def proposal():
    return {
        "schema": "windows-harmless-probe-proposal.v1",
        "status": "SOURCE_ONLY_NOT_EXECUTABLE",
        "native_api_calls": False,
        "separate_native_observer_implemented": False,
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in SOURCE_PATHS},
        "target": {
            "runtime": "CPython 3.12.10 Windows x86_64 portable, existing pinned artifact",
            "executable_sha256": "6461fe8dc13c642302f591c0c1c16b220629f7a336f74ce88aa2cdd31c43e62a",
            "code": "import time; time.sleep(60)",
            "flags": ["-I", "-S", "-B"],
            "job_committed_memory_bytes": 268435456,
            "active_process_limit": 1,
            "cpu_rate_per_10000": 1000,
            "children_or_breakaway": False,
            "inherited_handles": [],
            "program_requests_only_sleep": True,
            "startup_limit": "Interpreter and OS loading still access runtime files; flags "
                             "are not a sandbox or proof of no startup file access.",
        },
        "intended_ownership": {
            "supervisor": "Separate trusted process owns exact created controller handle; "
                          "30-second deadline starts before controller creation, never PID reopen. "
                          "Also retain exact created observer/canary termination+synchronize "
                          "handles solely for bounded cleanup; never a target job handle.",
            "controller": "Only owner of target kill-on-close job; target created suspended "
                          "with JOB_LIST. Persist identity before resume. Serial start/stop.",
            "observer": "Separate trusted process outside target job. Inherit ONLY explicitly "
                        "listed query/synchronize target duplicate; never job/terminate rights. "
                        "Require exact identity, pre-stop liveness and post-stop signal/exit code.",
        },
        "proposed_deadline": {
            "milliseconds": 30000,
            "enforcer": "Independent supervisor terminates only its retained controller on "
                        "hang/deadline or selected crash case; last job close kills target.",
            "observer_loss": "UNKNOWN, inhibit restart; observer cannot stop anything.",
            "missing_implementation": "Native role launch/handle transfer, controller watchdog, "
                                      "bounded role cleanup and independent observation protocol.",
        },
        "timing_controls": {
            "natural_sleep_seconds": 60,
            "human_stop_or_crash_seconds_after_live_handshake": 1,
            "maximum_post_intervention_observation_seconds": 4,
            "matched_no_stop_control": "Confirm same target live for 5 seconds, then exact "
                                       "owned-handle cleanup; never credit planned cleanup as stop.",
            "deadline_case": "Controller hang at live handshake; supervisor intervention by "
                             "30 seconds from controller creation, observe target exit within "
                             "4 seconds and before natural sleep completion. Late evidence UNKNOWN.",
        },
        "role_resource_plan": {
            "max_simultaneous_processes_including_supervisor": 5,
            "max_serial_cases": 10,
            "parallel_cases": 0,
            "controller_job_committed_memory_bytes_including_nested_target": 536870912,
            "controller_job_active_process_limit_including_nested_target": 2,
            "observer_job_committed_memory_bytes": 134217728,
            "canary_job_committed_memory_bytes": 134217728,
            "observer_and_canary_job_active_process_limit_each": 1,
            "role_cpu_plan": "Controller/job has no CPU rate cap so target's 10% is not "
                             "accidentally reduced by a parent cap. Observer/canary each 5% cap; "
                             "trusted supervisor fixed bounded waits, no workload loop.",
            "lifetime": "Supervisor enforces 30-second case deadline plus at most 5 seconds "
                        "exact-role cleanup; all observer/canary handles close afterwards.",
            "supervisor_crash_limit": "Supervisor-created controller/observer/canary jobs "
                                      "would each be kill-on-last-close and non-inheritable; "
                                      "only supervisor owns those outer job handles. Controller "
                                      "alone owns distinct inner target job. Requires native "
                                      "nested-job/ownership qualification; not implemented.",
            "unproved": "These limits are a concrete design, not installed native controls. "
                        "Supervisor memory and OS job-kill scheduling latency are not hard bounded.",
        },
        "disk_and_log_plan": "No VM or disk image. The child program requests only sleep. "
                              "Future trusted controller/judge records must use fixed-count "
                              "bounded writes (total <=64 KiB/case), not unbounded pipes/logs. "
                              "Not an OS disk quota or containment of adversarial code.",
        "cases": ["explicit human stop", "controller crash", "controller hang/deadline",
                  "identity persistence fails before resume", "stop persistence failure",
                  "stop during suspended creation", "observer loss is UNKNOWN",
                  "stale generation/out-of-scope refusal", "restart stays inhibited",
                  "distinct outside canary remains live; separate scoped cleanup"],
        "required_before_execution": [
            "Exact source revision and all hashes accepted by fresh non-author technical review",
            "Direct Risk acceptance and separate Chair execution grant",
            "Native binder, separate roles and fail-closed admission integration implemented/reviewed",
            "Exact F/G fresh paths and Python dependency manifest; no secrets in environment",
            "Actual successful job-limit and atomic-creation checks; no fallback on unsupported API",
            "Explicit controller, observer and canary resource/cleanup bounds and authority",
            "Pre/post artifact hashes held against change, unprivileged trusted host/account",
        ],
        "excluded": ["native execution now", "QEMU", "firmware", "VM boot", "WSL",
                     "PID scan/reopen", "adaptive opponent", "host isolation claim", "GPU"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="plan", choices=(
        "plan", "native-controller", "native-observer", "native-supervisor"))
    args = parser.parse_args(argv)
    if args.mode != "plan":
        parser.error("SOURCE_ONLY: native loading, child creation and execution are not released")
    print(json.dumps(proposal(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
