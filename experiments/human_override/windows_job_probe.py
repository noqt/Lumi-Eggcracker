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
_RETAINED_SUPERVISOR = None  # Only the exact CLI process lifetime releases unresolved OS handles.


def load_prepared_backend():
    """Fixed source loader for isolated-mode role preparation; no sys.path edit.

    The strict parent holds this exact file before any intended role launch.
    This loader is not a sandbox or an independent runtime-loading baseline.
    """
    import sys
    from types import ModuleType

    name = "eggcracker_windows_prepared_backend"
    path = ROOT / SOURCE_PATHS[0]
    with path.open("rb") as stream:
        source = stream.read(1024 * 1024 + 1)
    if len(source) > 1024 * 1024:
        raise ValueError("Fixed backend source exceeds reviewed limit")
    module = ModuleType(name)
    module.__file__ = str(path)
    previous = sys.modules.get(name)
    sys.modules[name] = module  # Required by dataclass; never modifies import search paths.
    try:
        # Compile the exact fixed source, never an unpinned repository pyc.
        exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102 - fixed held source
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def prepared_role_entry(mode, encoded, api_factory, clock, pause, persist):
    """Exact injected entry for exercising the fixed loader + role dispatch.

    Not reachable from CLI. Native modes refuse before calling this function.
    The factory receives only the loaded backend to construct its exact StubApi.
    """
    from types import FunctionType

    if any(type(hook) is not FunctionType for hook in (api_factory, clock, pause, persist)):
        raise TypeError("SOURCE_ONLY: exact injected role hooks required")
    backend = load_prepared_backend()
    value = backend.decode_bootstrap(encoded)
    if mode != "native-" + value["role"]:
        raise ValueError("Mode differs from fixed role bootstrap")
    worker = backend.PreparedRole(encoded, api_factory(backend), clock, persist)
    worker.run(pause)


def native_refusal():
    """One of two explicit source-only gates; no flag/environment can bypass it."""
    raise PermissionError("SOURCE_ONLY: native loading and execution are not released")


def process_preflight(backend, config, trusted_host=None):
    """Runtime facts only; the owned API path separately checks actual elevation."""
    import os
    import sys
    import tempfile

    if (os.name != "nt" or sys.version_info[:3] != (3, 12, 10) or sys.maxsize != 2**63 - 1
            or backend.exact_path(sys.executable) != backend.exact_path(config["application"])
            or Path.cwd().resolve() != Path(config["cwd"]).resolve()
            or Path(tempfile.gettempdir()).resolve() != Path(config["cwd"]).resolve()
            or (ROOT / SOURCE_PATHS[1]).resolve() != Path(config["source"]).resolve()):
        raise ValueError("Host runtime/source/cwd/temp differs from approved case")
    backend._physical(Path(config["cwd"]))
    if trusted_host is not None:
        if (os.environ.get("COMPUTERNAME") != trusted_host["machine"]
                or os.environ.get("USERNAME") != trusted_host["account"]):
            raise ValueError("Trusted-host identity differs from approved packet")
        # Environment strings check packet consistency, not token identity.
        # The executing supervisor/roles check their own TokenElevation before
        # jobs/targets. Windows system-DLL trust remains an accepted baseline.
        if any(Path(config["cwd"]).iterdir()):
            raise ValueError("Approved case directory must initially be empty")


def fixed_clock_and_pause():
    import time

    def clock():
        return time.monotonic_ns()

    def pause(nanoseconds):
        if type(nanoseconds) is not int or nanoseconds != 100_000_000:
            raise ValueError("Only fixed bounded 100ms polling is selected")
        time.sleep(0.1)

    return clock, pause


def wired_role_body(backend, mode, encoded, api_factory, clock, pause):
    """Post-gate orchestration shared with injected tests; never selects a DLL."""
    value = backend.decode_bootstrap(encoded)
    if mode != "native-" + value["role"]:
        raise ValueError("Mode differs from exact role bootstrap")
    journal = None
    try:
        if value["role"] == "controller":
            journal = backend.CaseJournal(value["cwd"], value["case"])

        def persist(phase, identity):
            if journal is None:
                raise ValueError("Observer cannot persist controller state")
            journal.persist(phase, identity)

        worker = backend.PreparedRole(encoded, api_factory(), clock, persist)
        worker.run(pause)
    finally:
        if journal is not None:
            journal.close()


def native_role_entry(mode, encoded):
    native_refusal()  # Must remain first: source-only candidate never reaches the body.
    backend = load_prepared_backend()
    value = backend.decode_bootstrap(encoded)
    if mode != "native-" + value["role"]:
        raise ValueError("Mode differs from exact role bootstrap")
    process_preflight(backend, value)
    clock, pause = fixed_clock_and_pause()
    wired_role_body(backend, mode, encoded, lambda: backend.NativeApi(), clock, pause)


class SupervisorSession:
    """Strong ownership across run, serialization and exclusive output failure.

    No destructor releases anything. The CLI retains this session through
    process exit; unresolved integer handles are then closed by OS teardown,
    with NO observed-zero or successful-cleanup claim and no automatic retry.
    """

    def __init__(self, backend, packet, api_factory, clock):
        self.backend = backend
        self.run = backend.PreparedQualification(
            packet["grant"], packet["grant"], packet["config"], packet["inventory"],
            packet["physical"], api_factory, clock, authority="NATIVE_QUALIFICATION")
        self.result = self.payload = None
        self.output_durable = False
        self.entry_failed = False

    def execute(self, pause):
        try:
            self.result = self.run.run(pause)
            self.run.stage = "SERIALIZE"
            self.payload = self.backend.bounded_json(
                self.result, self.backend.CASE_RESULT_LIMIT - 1) + b"\n"
        except BaseException as error:  # noqa: BLE001 - include serialization and interruption
            self.entry_failed = True
            self.run.note_failure(error)
            self.run.abort_owned_once()
            self.result = None
            # Constant emergency record: bounded independently of failed evidence.
            self.payload = (b'{"outcome":"UNKNOWN","entry_failed":true,'
                            b'"cleanup":"CONSULT_EXIT_STATUS_UNCONFIRMED"}\n')

    def write_result(self, output):
        import os

        try:
            self.run.stage = "OUTPUT"
            with output.open("xb") as stream:
                if stream.write(self.payload) != len(self.payload):
                    raise OSError("Partial bounded result write")
                stream.flush()
                os.fsync(stream.fileno())
            self.output_durable = True
        except BaseException as error:  # noqa: BLE001 - preserve capabilities on I/O failure
            self.entry_failed = True
            self.run.note_failure(error)
            self.run.abort_owned_once()
            # Preserve any partial file; do not overwrite/retry or claim fsync.

    def exit_code(self):
        matched = self.result is not None and self.result["case_matched_expected_observation"]
        return 0 if matched and self.output_durable and not self.entry_failed else 3


def wired_supervisor_body(backend, packet, api_factory, clock, pause):
    """Injected test entry; return ownership even after result/serialization failure."""
    session = SupervisorSession(backend, packet, api_factory, clock)
    session.execute(pause)
    return session


def require_unused_supervisor():
    if _RETAINED_SUPERVISOR is not None:
        raise PermissionError("One supervisor entry per process; retained session cannot be replaced")


def retain_supervisor(session):
    global _RETAINED_SUPERVISOR

    require_unused_supervisor()
    if type(session) is not SupervisorSession:
        raise TypeError("Exact supervisor session required")
    _RETAINED_SUPERVISOR = session


def native_supervisor_entry(packet_path, approved_sha256):
    native_refusal()  # Must remain first: no packet read or binding in this revision.
    require_unused_supervisor()  # Before packet reads, factories or any owned capability.
    import sys

    backend = load_prepared_backend()
    path = Path(backend.exact_path(packet_path))
    backend._physical(path)
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    packet = backend.decode_run_packet(raw, approved_sha256)
    process_preflight(backend, packet["config"], packet["trusted_host"])
    clock, pause = fixed_clock_and_pause()
    session = SupervisorSession(
        backend, packet, lambda _role, _process: backend.NativeApi(), clock)
    retain_supervisor(session)  # Set BEFORE the first owned API capability exists; never reset.
    session.execute(pause)
    output = Path(packet["config"]["cwd"]) / "result.json"
    session.write_result(output)
    code = session.exit_code()
    if code:
        try:
            sys.stderr.write("UNKNOWN: run failed; no retry or residual-cleanup claim.\n")
        except OSError:
            pass  # The nonzero process status remains authoritative if stderr fails.
    return code


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
            "Strict five-role prepared path with separate role-local polling loops and bootstrap",
            "Atomic suspended job/explicit handle-list arguments; serialized temporary copies",
            "Controller-to-observer query-only duplicate and bounded identity/resume handshake",
            "Monotonic supervisor deadline decisions; exact-role cleanup and loss is UNKNOWN",
            "Read-only selected runtime inventory and exact source/config/runtime STUB approval",
            "Strict source/application pin mapping and held-file verification through injected APIs",
            "Fixed-schema bounded evidence and same-instance restart refusal",
            "Supervisor uses observer reports, retained role handles and its own clock only",
            "Fixed isolated-mode backend loader and injected role entry; native CLI still refuses",
            "Exact owned outer-job termination plus bounded job-empty accounting before pin release",
            "Transactional verified process/thread bindings permit outer-member await only after a successful exact outer dispatch; canary and unverified members use direct cleanup",
            "Bounded cleanup ordinal dispositions and actual outer-dispatch status; no handles, paths or causal labels",
            "At most ten serial prepared cases; unresolved cleanup prevents the next case",
            "Dormant one-case native packet wiring, exclusive journal and bounded result file",
            "Current-process TokenElevation DWORD preflight before jobs/targets; injected tests only",
            "Finite one-shot abort and retained session through CLI exit; unresolved cleanup is UNKNOWN",
            "Hash-bound optional inherited-nested mode; fixed immediate-job queries, no ancestor control",
            "Every created role's exact owned-job membership checked at creation and before resume",
            "Bounded immediate-job query refusal reason and validated-shape flags; no query added",
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
            "cpu_limit_interpretation": "Configured ceiling without tighter ancestors, not reserved capacity",
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
            "canary": "Fixed sleep outside owned outer job, not independent of inherited ancestors; "
                      "check before intervention cleanup.",
        },
        "role_resource_plan": {
            "max_simultaneous_processes_including_supervisor": 5,
            "max_serial_cases": 10,
            "first_native_packet_cases": ["human_stop"],
            "parallel_cases": 0,
            "outer_job": {"active_processes": 3, "committed_memory_mib": 640, "system_cpu_percent": 20},
            "observer_job": {"active_processes": 1, "committed_memory_mib": 128,
                             "cpu_percent_of_outer": 25},
            "canary_job": {"active_processes": 1, "committed_memory_mib": 128, "system_cpu_percent": 5},
            "preexisting_supervisor_job": "OUTSIDE_ONLY default refuses membership. Explicit "
                                          "hash-bound REQUIRE_INHERITED_NESTED requires membership "
                                          "and fixed immediate-job UI/limit checks; unknown flags, "
                                          "UI/silent-breakaway, failed or malformed queries refuse. "
                                          "Explicit BREAKAWAY_OK permission accepted without ever "
                                          "requesting escape; both creation paths validate fixed flags. "
                                          "No ancestor control or full-chain validation.",
            "limit": "Stub arguments, not installed native controls. Committed memory is not "
                     "resident memory or disk quota. Supervisor memory is not job-bounded. "
                     "Inherited quotas can tighten configured caps; allocation is not guaranteed. "
                     "Shared ancestor loss/canary death is UNKNOWN, never stop proof.",
        },
        "timing_controls": {
            "pin_manifest_metadata_validation_bytes": 2097152,
            "deadline_seconds_before_any_role_creation": 30,
            "scheduled_deadline_intervention_seconds": 29,
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
                     "notification -> observed LIVE/ack -> stop intent/observer ack -> "
                     "stop completion status -> observed EXIT",
            "bootstrap_bytes_per_role": 16384,
            "journal_bytes": 8192, "final_result_with_newline_bytes": 12288,
            "write_limit": "Synchronous writers are expendable controller/observer roles only. "
                           "Supervisor only reads complete available frames. Not an OS disk quota.",
        },
        "restart_safety": "UNQUALIFIED in this harness. Same-instance refusal only; accepted "
                          "persistent mock admission code remains unchanged. No native reset.",
        "first_native_failure_contract": {
            "entry": "One session per process; retain exact owner through CLI process exit",
            "success": "Expected human_stop early exit + valid protocol + live canary + job-zero "
                       "cleanup before normal pin release + fsynced result + CLI exit0",
            "failure": "UNKNOWN exit3; one finite non-yielding abort; no retry or next case",
            "residual": "OS exit releases jobs AND pins; termination may lag without observed zero. "
                        "No pin retention until death, surviving owner or cleanup guarantee.",
            "output": "A complete-looking file alone is not success; require matching process exit0. "
                      "Output/fsync may fail; preserve partial files and report unconfirmed failure.",
        },
        "cases": ["human_stop", "controller_crash", "controller_deadline", "identity_failure",
                  "stop_persistence_failure", "suspended_stop", "observer_loss", "supervisor_loss",
                  "no_stop_control", "same_instance_restart_refused"],
        "required_before_execution": [
            "Fresh non-author technical and direct Risk acceptance of exact five hashes",
            "Separate exact Chair native execution grant",
            "Separate reviewed native wiring release: current entry and APIs are injected-only",
            "Reviewed native wiring of mandatory held-file admission and fixed role loops",
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
    parser.add_argument("--packet", help=argparse.SUPPRESS)
    parser.add_argument("--approved-packet-sha256", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.mode != "plan" or any(value is not None for value in (
            args.bootstrap, args.packet, args.approved_packet_sha256)):
        try:
            native_refusal()
            if (args.mode == "native-supervisor" and args.bootstrap is None
                    and args.packet is not None and args.approved_packet_sha256 is not None):
                return native_supervisor_entry(args.packet, args.approved_packet_sha256)
            if (args.mode in ("native-controller", "native-observer") and args.packet is None
                    and args.approved_packet_sha256 is None and args.bootstrap is not None):
                return native_role_entry(args.mode, args.bootstrap)
            raise ValueError("Exact native role or supervisor argument set required")
        except (PermissionError, ValueError) as error:
            parser.error(str(error))
    print(json.dumps(proposal(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
