# Lumi Eggcracker whole-VM stop: source and mock preparation only

This is an `IMPLEMENTED_INTERNAL`, `MOCK_ONLY` source-checkout experiment.
It does **not** implement a native Windows adapter or start/stop any VM.
The accepted backend is exactly `MockKernel`; imports and tests make no native
process/job calls. Do not treat the word "Windows" as native qualification.

```text
python -B experiments/human_override/windows_vm_lab.py --output ABSOLUTE_FRESH_DIRECTORY
python -B -m unittest discover -s tests -p test_windows_vm_controller.py -v
```

Use a fresh destination beneath a trusted existing parent; no existing output
is removed. Apply the repository's assigned F:/G: runtime/temp checks first in
the controlled environment. Retain source revision, Python/OS identity, UTC
time, command and result hash with each replay. The result hashes five files.

## Intended native boundary, not implemented

One disposable Linux QEMU guest would run under a trusted Windows host/user.
No QMP, NIC, host shares, guest agent or external-job cancellation is included.
This is whole-VM emergency interruption, not selective AI detection or the
production Lumi Eggcracker daemon. Host/user compromise is outside the model.

The proposed launch ordering is durable START_INTENT, atomic job-bound suspended
creation, retained-handle identity persistence, then resume. There is no fallback
to unassigned or running creation. A stop and start are single-writer ordered;
the latch is checked again immediately before resume. Pending, corrupt or missing
state and every controller restart inhibit admission. PID/name reacquisition is
absent. The primary handle, creation identity, configuration and generation must
stay bound; a filename alone is not authority to terminate a process.

A stop persists its latch before dispatch. If persistence fails, emergency stop
is still attempted against the already-retained validated target, but durable
restart safety remains unconfirmed. Dispatch is asynchronous and never proves
exit. The mock judge requires earlier running observation and the exact query-only
handle's exit state; guest shutdown text is not input. The native judge must be a
separate process outside the job and must never receive a job or terminate handle.
Current `MockJudge` is only a Python object, not an isolation mechanism.
The controller accepts only its canonical judge type with an issued query-only
capability for the current process identity. An arbitrary `observe()` success
string, unregistered handle or old-generation judge cannot authorize reset.

Controller loss is proposed to close the last unnamed kill-on-close job handle,
stopping the entire VM. This sacrifices availability and may corrupt its disposable
overlay. It is not graceful cleanup. A signaled primary-process handle proves only
that primary process exited; all VM execution must be demonstrably confined to it
or job emptiness separately established before claiming whole-VM cessation.

Human reset is generation/epoch-bound, requires a fresh judge observation, advances
the epoch and clears approval. Reset never starts. New approval and an explicit
start create the next generation. Lost judge state means UNKNOWN, not a scan for
another process. The native identity/handle implementation remains unimplemented.

## What these checks cannot establish

The mock persists exclusive pending files, flushes/fsyncs and replaces the snapshot.
This exercises process-restart logic, not Windows power-loss durability. Mock job
assignment, handle rights and crash cleanup are invented simulator semantics until
tested against actual Windows APIs. The canary is also synthetic. Resource limits
in [the contract](../experiments/human_override/windows_vm_contract.v1.json) are
proposals, not enforcement: virtual disk size and a free-space preflight do not
constitute a host disk quota or reservation.

Native release still requires exact reviewed source and artifact hashes, actual
atomic creation/job support, no leaked job handles or escaped children, a separate
judge, enforceable CPU/memory/disk/log/duration bounds, inspected firmware/device
and guest startup, fresh disposable overlay, and explicit Risk/technical acceptance
and destructive execution scope. Preserve historical disks and the immutable base.
No Windows/Linux efficacy, AI attribution, independent adoption or power-loss
guarantee follows from this model. The separate E1/E3 negative detector result is
unchanged and does not gate this human-stop investigation.

## Source-only Windows x64 backend preparation

The backend now contains a lazy Win64 binder body behind unconditional refusal.
Imports do not load a DLL or construct an API table. NativeApi construction,
native_backend and all three native CLI roles refuse before native loading.
Only exact injected Python-function tables enter the source/stub adapter.

```text
python -B experiments/human_override/windows_job_probe.py
python -B -m unittest discover -s tests -p test_windows_job_backend.py -v
```

The default CLI prints the current five-file hashes and a harmless-process
proposal. It launches nothing and writes no file. The original RetainedJob
primitive and accepted MockKernel/Controller admission implementation are
preserved. Windows x64 layouts use fixed-width DWORD/BOOL/UTF-16 and pointer-sized
HANDLE/SIZE_T; no packed or x86 fallback exists.

### Connected source/stub path

RoleHandles prepares explicit suspended JOB_LIST creation, serialized temporary
HANDLE_LIST inheritance, exact query-only duplication, fixed resource arguments,
and retained-handle cleanup. PreparedQualification performs mandatory strict pin
admission and runs only the supervisor loop. PreparedRole constructs either
controller or observer from a bounded canonical bootstrap and runs its own loop.
The supervisor cannot call or inspect either role object: it receives reports
through its sole pipe reader and uses its own clock and retained process handles.
Tests schedule the role loops separately using synthetic handle tables, including
uneven polling and stalled roles. StubQualification remains a legacy synchronous
regression fixture, not the prepared entry. Target and canary are only fake
processes. This is IMPLEMENTED_INTERNAL source/stub logic, not independently
scheduled OS processes or native qualification.

The supervisor owns an outer kill-on-close job containing controller, target and
observer: three processes, 640 MiB committed memory, proposed 20% CPU hard cap.
It creates the observer first, with a separate nested one-process 128 MiB job.
The controller solely owns the target inner job: one process, 256 MiB, proposed
50% of the parent's CPU allowance (intended 10% system). The observer rate is
25% of the parent (intended 5% system). The outside canary has its own one-process
128 MiB job and proposed 5% system CPU cap. All outer jobs belong only to the
supervisor; no job handle is inherited. No compatible host-job assumption or
breakaway fallback is permitted: a preexisting supervisor job refuses setup.

These are stubbed arguments and arithmetic, not observed native enforcement.
Actual parent/JOB_LIST nesting, active-process counts, committed-memory/CPU
limits, last-handle closure and inheritance need native qualification.
Committed memory is not resident memory or a disk quota. The supervisor remains
outside these jobs, with unbounded-by-job memory and an explicit availability
dependency. At most five roles including supervisor and ten serial cases are
proposed. The prepared serial driver accepts at most ten distinct fresh cases
and refuses to start the next after unresolved cleanup.

Supervisor launches fixed observer/controller source commands with only selected
inherited handles. Controller receives PROCESS_DUP_HANDLE to the observer plus
two protocol endpoints. It duplicates only QUERY_LIMITED_INFORMATION and
SYNCHRONIZE target rights directly into the observer, then immediately closes its
observer-process capability. The returned numeric handle belongs exclusively to
the observer, never the controller. A lost notification is cleaned by ending the
exact observer role, which closes its table, not by guessing a remote handle.
The target and canary inherit nothing.

PROCESS_DUP_HANDLE is substantial authority. Independence here means fault
separation among trusted reviewed roles, not resistance to a malicious controller
or compromised host. A target/guest never receives that authority. Original
unused pipe ends and temporary inheritable copies close on success/failure;
temporary copies exist only inside the process-creation lock.

The 88-byte protocol binds generation, configuration digest, sequence, trusted
monotonic tick, observer-local target handle, PID and creation FILETIME.
Suspended identity must be acknowledged before controller resume; a resume
notification precedes the observer's real stub-handle LIVE query. Only a later
signaled handle plus exit-code query can supply EXIT. No controller assertion is
an observer result. An already-bound exclusively retained handle is not reopened
or reidentified by image after exit. Missing/stale/out-of-order/partial/oversized
evidence fails or remains UNKNOWN; no PID/name scan exists.

The observer also acknowledges post-resume LIVE to the controller. Fixed local
stop cases wait one second after that acknowledgement, send stop intent and wait
for the observer's acknowledgement before attempting stop. The observer forwards
its local intent-receipt time; the supervisor records its own receipt time. Stop
completion includes persistence status or same-instance restart refusal before
the observer reports EXIT. These are trusted-role control metadata, not proof of
termination or power-loss durability. Query evidence alone proves neither cause
nor restart safety. The no-stop result comes from a second actual observer LIVE
query at least five seconds after its first, never direct supervisor inspection.
A broken controller pipe after resume does not suppress retained-handle queries.
Malformed control permanently invalidates the verdict while subsequent genuine
EXIT evidence can still be recorded. Missing completion remains UNKNOWN.

The case deadline starts before any role creation. Stub scheduling separates
controller crash/hang decisions from the supervisor's 30-second clock. The
prepared supervisor schedules deadline intervention at 29 seconds, reserving one
second of margin; actual dispatch later than 30 seconds cannot pass. A late
clock jump still triggers exact cleanup, never an on-time claim.
Intervention follows the live handshake by one second; early exit must be observed
within four seconds, before the fixed 60-second natural lifetime. A matched
no-stop control stays live for five seconds before separate cleanup. Natural or
pre-intervention exits do not qualify. Supervisor loss closes its modeled job
ownership, potentially losing observer and canary: the result is UNKNOWN.

Each pipe permits at most 16 fixed frames. Evidence permits at most 128
fixed-schema records; fields/counts are bounded before JSON serialization and
validated again at finalization. Three 4 KiB pipe buffers and two maximum 16 KiB
bootstrap wire records are reserved inside the combined 64 KiB case evidence
limit. The bootstrap is canonical lower-case hex of bounded JSON, binding the
role, exact three inherited handles, fixed paths, case, generation, configuration
hash and shared start/deadline. It is bounded before JSON parsing and rejects
duplicate/noncanonical keys, unexpected fields, pseudo/duplicate handles and
configuration mismatches. These are wire/evidence bounds, not Python heap limits.
Writers belong only to expendable
controller/observer roles; supervisor reads a complete available frame after
PeekNamedPipe. Synchronous writes may stall and need the genuinely independent
native supervisor. The stub scheduler does not establish real pipe latency.
Prepared cleanup retains supervisor-owned jobs, explicitly terminates only the
exact owned outer job, and separately disposes of exact retained role processes
including the canary. It waits for retained created processes to signal before
releasing those process/thread references. It then queries the fixed 48-byte
BasicAccountingInformation for every retained job, including partial-setup jobs.
Only verified ActiveProcesses=0 allows closing jobs and releasing artifact pins.
The outer count covers the nested target when its observer has been lost;
controller/observer exit or last-job-handle-close dispatch alone is insufficient.
Accounting can retain terminated members until process references are released,
so signaled process references close before the zero-count poll, not after it.
Job termination/query/close failure, malformed size/count or nonzero counts keep
the result UNKNOWN and retain remaining job handles and pins. This remains
stubbed API semantics, not observed Windows job emptiness.
After at most five seconds of cleanup polling, or the 35-second hard case window,
unconfirmed job emptiness retains pins/job handles and cleanup responsibility and forbids
restart of that one-shot case. No second case may start while those roles remain
unresolved. The 30+5 second windows are
acceptance targets, not OS scheduling guarantees.

Restart safety is UNQUALIFIED in this new harness. Same-instance retry refusal
does not prove durable inhibition across a controller restart. The separately
accepted persistent mock controller retains its own narrower evidence; that
property does not transfer to this adapter. No native reset is implemented.
The case is explicitly named same_instance_restart_refused.

### Runtime inventory and remaining native preparation

The selected future target/canary command is the existing pinned portable
CPython 3.12.10 x64 executable (SHA-256
6461fe8dc13c642302f591c0c1c16b220629f7a336f74ce88aa2cdd31c43e62a)
with fixed -I -S -B and import time; time.sleep(60). No caller code or target
arguments are admitted. OS/interpreter startup still accesses runtime files:
these flags are not a sandbox.

The inventory helper bounds selected files, byte totals, directory count, name
bytes and entry count; rejects reparse/alias escapes; hashes selected bytes and
records directory entry names/types. Persisted JSON round-trips and changed,
missing or additional selected-directory entries are checked. Source/config/
runtime hashes must match a separately trusted STUB_ONLY approval before any
stub API call. Synthetic application aliases are only for stub fixtures.

This inventory is NOT proof of complete dependency closure or launch-time
identity. Pathname checks do not close TOCTOU windows. It explicitly records
path_handles_held=false and system_dlls_verified=false. System DLLs are outside
this selected portable-runtime inventory and require an explicit trusted-OS
baseline decision; no whole-host/credential audit is implied.

The mandatory PreparedQualification strict path links application to inventory-root/python.exe
and the script to the exact five-file source pin set, with no alias fallback.
HeldArtifacts then prepares read handles denying write/delete sharing, retains
ancestor handles, rejects reparse/final-path substitution and rechecks held
volume/file index, size, write time and streaming SHA. Acquisition precedes any
job or pipe creation. The connected fixture uses virtual file objects and
reports HELD_STUB_OBJECTS, not observed physical Windows file locks. Alias-only
legacy fixtures explicitly report SYNTHETIC_ALIASES. There is no alias fallback
in the prepared path; the legacy optional branch is never native authority.

The hashed read handle is at EOF and serves as an identity lock; CreateProcess
and Python would reopen the bound path. Denied write/delete sharing and retained
ancestors preserve the selected objects, not import/dependency closure. Directory
handles do not prevent adding child entries. Python bytecode-cache reads and OS
DLL resolution still require the accepted runtime-loading baseline.

The prepared role entry loads only the fixed backend sibling by explicit file
location, without adding cwd or the repository to sys.path. This prepares the
-I -S child-loading path, but imports are not a security sandbox. The entry is
tested only with exact injected APIs and is unreachable from the native CLI.
Before any native execution release, separately review native wiring of this
fixed loader/bootstrap, mandatory held-file admission and role-local loops.
Bind exact local paths, files,
host/account and source hashes; obtain direct Risk and fresh technical acceptance
plus a separate exact Chair grant. Native creation/limits/ownership/cleanup then
need their own originating qualification. This preparation is not VM boot,
firmware acceptance, adaptive-opponent evidence, Windows efficacy or E4 completion.
Implementation/static acceptance and a bounded test contract precede the first
authorised native qualification run; observed native behavior is an outcome of
that run, required before efficacy or expanded-use claims, not a circular
prerequisite to the first qualification call. The older top-level QEMU contract
is a distinct mocked plan and cannot grant sleeper execution or restart safety.

### Primary ABI/design references

- [Process creation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) and [STARTUPINFOEX](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw).
- [Attribute lists, JOB_LIST and HANDLE_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
- [Job basic limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information), [extended layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information) and [CPU hard cap](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information).
- [DuplicateHandle rights and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle), [creation FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes) and [image identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew).
- [Owned-job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject), [fixed job query](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject) and [basic accounting layout and reference lifetime](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).
