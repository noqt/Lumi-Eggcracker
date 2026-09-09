"""Print the hash-bound harmless-process contract. Native roles always refuse."""

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
        "implemented_internal": [
            "Guarded lazy Win64 binder and exact injected ABI table",
            "Connected five-role STUB scheduler with separate synthetic handle tables",
            "Atomic suspended job/explicit handle-list arguments; serialized temporary copies",
            "Controller-to-observer query-only duplicate and bounded identity/resume handshake",
            "Monotonic supervisor deadline decisions; exact-role cleanup and loss is UNKNOWN",
            "Read-only selected runtime inventory and exact source/config/runtime STUB approval",
            "Strict source/application pin mapping and held-file verification through injected APIs",
            "Fixed-schema bounded evidence and same-instance restart refusal",
        ],
        "target": {
            "runtime": "Existing pinned CPython 3.12.10 Windows x86_64 portable",
            "executable_sha256": "6461fe8dc13c642302f591c0c1c16b220629f7a336f74ce88aa2cdd31c43e62a",
            "code": "import time; time.sleep(60)",
            "flags": ["-I", "-S", "-B"],
            "job_committed_memory_bytes": 268435456,
            "active_process_limit": 1,
            "cpu_rate_per_10000_of_parent": 5000,
            "intended_effective_system_cpu_percent": 10,
            "children_or_breakaway": False,
            "inherited_handles": [],
            "startup_limit": "Interpreter/OS loading accesses runtime files. These flags are not "
                             "a sandbox or proof of no startup access.",
        },
        "intended_ownership": {
            "supervisor": "Creates observer, canary and controller; owns all outer jobs and exact "
                          "created-role cleanup handles. No inner target-job handle.",
            "controller": "Sole inner target-job owner. Inherits only an observer PROCESS_DUP_HANDLE "
                          "handle and two exact protocol endpoints. No outer job inherited.",
            "observer": "Supervisor-created, inside outer but outside target inner job. Receives "
                        "only QUERY_LIMITED_INFORMATION|SYNCHRONIZE target handle by direct "
                        "DuplicateHandle into observer; never target terminate/job rights.",
            "canary": "Fixed sleep outside outer job; check before intervention cleanup.",
        },
        "role_resource_plan": {
            "max_simultaneous_processes_including_supervisor": 5,
            "max_serial_cases": 10,
            "parallel_cases": 0,
            "outer_job": {"active_processes": 3, "committed_memory_mib": 640, "system_cpu_percent": 20},
            "observer_job": {"active_processes": 1, "committed_memory_mib": 128,
                             "cpu_percent_of_outer": 25},
            "canary_job": {"active_processes": 1, "committed_memory_mib": 128, "system_cpu_percent": 5},
            "preexisting_supervisor_job": "Refuse; no implicit compatibility or breakaway",
            "limit": "Stub arguments, not installed native controls. Committed memory is not "
                     "resident memory or disk quota. Supervisor memory is not job-bounded.",
        },
        "timing_controls": {
            "deadline_seconds_before_any_role_creation": 30,
            "cleanup_acceptance_window_seconds": 5,
            "natural_sleep_seconds": 60,
            "stop_or_crash_seconds_after_live": 1,
            "maximum_post_intervention_observation_seconds": 4,
            "matched_no_stop_live_seconds": 5,
            "unknown": "Missing, stale, premature or late evidence; observer or supervisor loss; "
                       "failed persistence/cleanup. Dispatch alone never proves exit.",
            "limit": "Stub monotonic timeline, not independent native scheduling or OS latency guarantee.",
        },
        "protocol": {
            "frame_bytes": 88, "max_frames_per_pipe": 16, "pipe_count": 3,
            "evidence_bytes_per_case": 65536, "max_evidence_records": 128,
            "order": "Suspended exact identity -> observer ack -> controller resume -> resume "
                     "notification -> observed LIVE -> intervention -> observed EXIT",
            "write_limit": "Synchronous writers are expendable controller/observer roles only. "
                           "Supervisor only reads complete available frames. Not an OS disk quota.",
        },
        "restart_safety": "UNQUALIFIED in this harness. Same-instance refusal only; accepted "
                          "persistent mock admission code remains unchanged. No native reset.",
        "cases": ["human_stop", "controller_crash", "controller_deadline", "identity_failure",
                  "stop_persistence_failure", "suspended_stop", "observer_loss", "supervisor_loss",
                  "no_stop_control", "same_instance_restart_refused"],
        "required_before_execution": [
            "Fresh non-author technical and direct Risk acceptance of exact five hashes",
            "Separate exact Chair native execution grant",
            "Native process bootstrap/role dispatch and independently scheduled supervisor",
            "Implemented and statically reviewed native integration of prepared held-file admission",
            "Reviewed unprivileged-host preflight procedure for the authorized qualification run",
            "Windows system-DLL provenance decision; selected inventory does not cover those files",
            "Reviewed bounded native test procedures for job nesting, inheritance, limits and cleanup",
        ],
        "required_after_authorized_qualification": [
            "Observed held-file identity/path-lock behavior and unprivileged-host preflight results",
            "Observed native job nesting, exact inheritance, limits, kill-on-last-close and cleanup",
            "Originating native stop/crash/deadline/canary outcomes before efficacy or expanded use",
            "Durable admission implementation and restart tests before any restart-safety claim",
        ],
        "excluded": ["native execution now", "QEMU", "firmware", "VM boot", "WSL", "PID scan/reopen",
                     "adaptive opponent", "host isolation claim", "GPU", "E4 completion"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="plan", choices=(
        "plan", "native-controller", "native-observer", "native-supervisor"))
    parser.add_argument("--bootstrap", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.mode != "plan" or args.bootstrap is not None:
        parser.error("SOURCE_ONLY: native loading, child creation and execution are not released")
    print(json.dumps(proposal(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
