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
supervisor; no job handle is inherited. The default OUTSIDE_ONLY mode rejects
preexisting supervisor jobs. The separately hash-bound inherited-nested mode
below has explicit admission checks, never a breakaway fallback. In that mode
ancestor quotas may tighten these configured caps; system CPU allocation is not
guaranteed and the canary is not independent of inherited ancestors.

These are stubbed arguments and arithmetic, not observed native enforcement.
Actual parent/JOB_LIST nesting, active-process counts, committed-memory/CPU
limits, last-handle closure and inheritance need native qualification.
Committed memory is not resident memory or a disk quota. The supervisor remains
outside these jobs, with unbounded-by-job memory and an explicit availability
dependency. At most five roles including supervisor and ten serial cases are
available in injected tests. The native packet decoder selects exactly ONE
human_stop case, not a batch or automatic retry. The prepared serial test driver accepts at most ten distinct fresh cases
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
bootstrap wire records, plus an 8 KiB controller journal, are reserved inside the combined 64 KiB case evidence
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
After this cleanup invocation's exact retained outer TerminateJobObject call
returns success, a controller/observer process may skip redundant
TerminateProcess only when its own retained process/thread binding has already
passed exact membership verification in that same outer job and the handles,
job and (3-process, 640-MiB, 2000-rate) contract remain uniquely retained.
The verified marker is transactional: failed membership, duplicate or
malformed mappings, a missing/closed thread, a wrong outer job or a partial
binding falls back to direct disposal. A successful outer dispatch permits
awaiting a member but never proves exit; a failed dispatch never suppresses
direct disposal. The canary is outside the outer job and remains direct.
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

The prepared role entry compiles only bounded bytes of the fixed backend sibling,
never a repository bytecode cache, without adding cwd or the repository to sys.path. This prepares the
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

### Dormant native wiring and one-case failure contract

The source-only entry now prepares fixed supervisor/role dispatch, canonical
whole-packet SHA admission, runtime/cwd/temp consistency checks, a three-record
exclusive controller journal, owned cleanup and bounded result writing. Both
unconditional native gates remain. Default plan mode does not bind or call any
native API. CLI options, environment variables and matching packet/digest pairs
cannot remove the source gate or grant execution. A later, mechanically small
gate-release candidate needs its own exact source hashes, complete packet hash,
independent review and Chair grant naming the exact command. Digest equality is
consistency with that separate approval, not authentication of a CLI caller.
The result also reports only bounded ordinal/disposition cleanup diagnostics
(`ALREADY_SIGNALED`, `OUTER_DISPATCH_AWAITED`, `EXACT_TERMINATE`) and the
actual outer-dispatch boolean; it contains no handles, paths or causal labels.

The selected first packet is one human_stop only: at most five trusted roles,
fixed sleep60 target/canary, the existing job/resource limits, 29-second deadline
fallback, latest accepted intervention at 30 seconds and five-second cleanup
window. Deadline fallback cannot pass the human-stop observation. No retry or
follow-on case is admitted by this packet. Actual supervisor-loss testing would
need a separate surviving judge and scope; this packet does not select it.

Before its first job or target, each prepared supervisor/controller/observer
checks the executing process's own token. Only GetCurrentProcess's pseudo-handle,
OpenProcessToken with TOKEN_QUERY, and GetTokenInformation TokenElevation with
one four-byte DWORD are selected. The returned length must be exactly four and
the value zero. Failed, elevated, unwritten, malformed or ambiguous output
refuses admission; a successful token open transfers exact close responsibility.
Only that returned token is closed, never the process pseudo-handle. Failed
token close retains the handle and refuses downstream work. This measures
elevation only, not identity, integrity level, all privileges or impersonation.
Environment host/account strings and a launching-shell diagnostic are not a
replacement for this executing-Python check. No credential/token contents are
logged and no privilege changes are implemented.

The host baseline for the proposed run is explicitly trusted current Windows
with normal System32-only explicit DLL binding and trusted pinned portable
Python loading. The selected runtime inventory includes observed source/cache
files and selected native dependencies, not exhaustive Windows dependencies.
system_dlls_verified remains false. Existing stdlib pyc reads are allowed within
this baseline; hashes do not establish source/cache correspondence. Fixed source
loading prevents the repository backend's unpinned pyc from taking precedence.
Held files and ancestor/case-directory handles protect selected objects, not
all child-directory additions or a compromised host. No sandbox claim follows.

CaseJournal permits exactly START_INTENT, IDENTIFIED_SUSPENDED and STOP_REQUESTED
in order, using exclusive creation, bounded records, flush and fsync. It is
qualification evidence only, not durable restart authority or a power-loss
guarantee. The final result including its newline is limited to 12 KiB; with
the journal, pipe reservations and bootstrap wires this is at most 64 KiB.
This is an application evidence budget, not an OS disk quota or heap limit.

SupervisorSession retains the exact qualification owner across polling,
serialization and exclusive output errors. No generator yields from a finally
block and no destructor is treated as cleanup. An exceptional driver interruption
attempts one finite, non-yielding, zero-wait abort with existing handles only;
an already attempted cleanup is not retried or silently waived. Normal cleanup
must observe zero owned-job membership before releasing pins. Any unresolved
cleanup overrides an earlier stop observation: UNKNOWN/failed and exit 3.
There is no infinite wait, automatic retry, next case or PID/name reacquisition.

The exact CLI keeps unresolved ownership until supervisor process exit. OS
teardown is expected to close its sole non-inherited kill-on-close jobs, but
without observed zero it is NOT confirmed cleanup. Process exit releases both
job and pin handles; target termination scheduling may lag pin release. This
explicit loss-of-evidence terminal is accepted only for the trusted harmless
sleep experiment, not for a VM or real workload. Sleep60 is not a hard scheduling
or whole-harness lifetime guarantee. Failed/missing/partial output is likewise
unconfirmed; fsync itself can block or fail and is not a surviving owner.
Preserve artifacts after failure: no runtime replacement, pin-file reuse/removal,
cleanup escalation or new case until a separately scoped recovery decision.

Only expected early primary exit, valid protocol, live outside canary, complete
owned-job-zero cleanup and successfully flushed/fsynced result allow CLI exit 0.
Read a result together with the exit status; a file alone cannot prove successful
output durability. Injected APIs always label results STUB_ONLY/STUB outcomes,
including tests of the native packet wiring. Only the exact real NativeApi under
native authority selects NATIVE_QUALIFICATION_RUN and observed native labels.
The dormant public entry does not produce native qualification evidence.

### Pin-manifest validation repair and bounded diagnostics

The combined source/runtime pin map now has an explicit 2 MiB conservative
pre-encoder metadata budget. The old default 64 KiB budget rejected a realistic
149-entry map before the first pin API call in an injected reproduction. This
is a source-order reproduction, not a native API trace. A preserved failed
qualification attempt lacking error detail cannot by itself identify the API
or prove successful role startup, human stop or native pin behaviour.

The repair leaves all content and resource limits unchanged: 1..256 files,
1024-character paths, 16 MiB per file, 128 MiB aggregate content and 512 retained
file/ancestor handles. Full manifest validation still precedes all pin APIs.
Injected regressions cover 149 entries and 256 maximum-length paths, malformed
and excessive inputs with zero API calls, and the 149-pin independent role
journey. None of these fake file objects establishes native path acceptance.

A result may contain one first-failure diagnostic: fixed supervisor stage,
fixed error category, optional unsigned 32-bit numeric error field and its
domain, fixed pin phase, and manifest ordinal 1..256 (0 means no file ordinal).
WINERROR identifies the exception's winerror field; ERRNO identifies its errno
field, which fixed API wrappers populate with the immediate last-error code.
No exception message, dynamic type name, path, process argument, identity or
credential is recorded. Later cleanup failures do not replace the first cause.
This diagnostic is not a complete event/API trace; null does not prove success.

Default OUTSIDE_ONLY admission preserves existing refusal and call order.
HOST_JOB identifies query failure or an ambiguous membership value;
HOST_JOB_MEMBERSHIP identifies a mode/membership mismatch. HOST_JOB_LIMITS and
HOST_JOB_UI identify the new nested-mode immediate-job admission queries;
HOST_JOB_DEADLINE identifies the later deadline check. Admission refusal retains
precedence over deadline refusal. An older combined HOST_JOB/VALUE result stays
ambiguous; new source labels never change historical evidence.

The latest immediate-job query additionally records only fixed information class,
returned byte count after API success, flags after exact-size validation, and a
fixed refusal reason (API_FAILURE, RETURN_SIZE, UI_FLAGS, LIMIT_FLAGS or the
selected invalid limit field). Missing or malformed buffers never supply flag
values. This small record distinguishes admission branches without another query,
exception text, paths or unrelated process data. A null refusal marks that query's
accepted shape and values only, not host compatibility. Old HOST_JOB_LIMITS/VALUE
results without this record stay ambiguous. Refusal predicates and evidence
budgets are unchanged; the diagnostic itself grants no retry or native probe.

Diagnostics share the unchanged 12 KiB final-result and 64 KiB total case-evidence
limits. Serialization failure retains the constant emergency record; output
failure can retain diagnostics only in the live session, without rewriting or
retrying a partial result. Exit status remains essential. The failed immutable
qualification artifacts and consumed grant are not reusable: any further native
attempt requires a fresh reviewed snapshot, exact packet and separate grant.

### Explicit inherited-job preparation mode

The optional `supervisor_job_mode` field accepts exactly `OUTSIDE_ONLY` or
`REQUIRE_INHERITED_NESTED`. Omission preserves the original OUTSIDE_ONLY
configuration and digest. An explicit field participates in the configuration
hash and each role bootstrap; adding or changing it invalidates existing bound
admission. There is no automatic mode selection or retry after refusal.

After the existing elevation and launch-pin checks, nested mode requires the
current-process `IsProcessInJob` query to return exactly TRUE; outside-only mode
requires exactly FALSE. Failed calls or values other than 0/1 are refused.
Nested mode then issues only two fixed read-only NULL-job queries: extended
limits (class 9, 144 bytes) and UI restrictions (class 4, 4 bytes), with exact
returned lengths. These expose the immediate job only, not the entire ancestor
chain, and obtain no ancestor handle. Nonzero UI restrictions, silent breakaway,
unknown flags outside the selected 0x7fff mask, and malformed selected limit
values are refused before owned jobs or children are created. Known limits are
not removed or loosened. Unqueried classes and higher ancestors remain unproved.

Existing immediate-parent `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (0x800) is accepted:
this permits explicit breakaway only when process creation requests
`CREATE_BREAKAWAY_FROM_JOB` (0x01000000), which this harness never requests.
`SILENT_BREAKAWAY_OK` (0x1000), including its combination with 0x800, remains
refused. Both creation paths validate the exact fixed flags 0x08080404 before
submitting them to CreateProcessW; no caller flag override is available. All
owned jobs retain flags 0x2208, with neither breakaway mode. This distinguishes
compatibility with existing host permission from exercising escape or changing
host policy. Injected tests cover 0x800 and 0x2800, not native compatibility.

Each child is still created suspended with the fixed ordered atomic JOB_LIST,
without breakaway or a substitute parent. Its exact retained process handle is
checked against every selected owned job both after creation and immediately
before resume. Failed, false or ambiguous membership prevents resume and enters
existing owned-only cleanup; it never falls back to ordinary process creation.
Owned-job limits, retained pins, query-only observation and zero-process cleanup
requirements remain unchanged. No parent-job termination, modification, handle
acquisition, privilege change or host-policy change is introduced.

Inherited limits can be stricter than the configured owned-job ceilings and can
prevent creation or progress. CPU percentages are ceilings relative to the job
hierarchy, not guaranteed capacity. The canary is outside the owned outer job but
can share inherited ancestors with every role. Shared-ancestor interruption or
missing observations remain UNKNOWN, not proof of successful independent stop.
The result binds the selected mode and immediate observations and always records
`ancestor_chain_validated: false`; it is not a full host compatibility audit.
`immediate_job_breakaway_ok` records accepted immediate-parent permission, or
null when limits were not admitted; it does not report that escape occurred.

This mode is implemented for injected testing only. Public native refusal gates
remain unconditional. A future agent-operated native run needs fresh acceptance
of the actual changed source and whole procedure, plus its own exact run scope;
prior human-only or consumed grants do not authorise it. Stub success does not
establish native Windows behaviour, a Linux boundary, durable real restart
inhibition, adaptive-opponent resistance, or completion of the experiment brief.

### Prepared cleanup exit-race reconciliation

Prepared cleanup makes at most one TerminateProcess attempt per exact retained
created role handle. A failed call captures its last-error immediately. Only
code 5 permits one immediate zero-time wait on that same handle; only an exact
signaled result reconciles the documented terminate-after-exit race. It proves
current death, not which action caused it. A live, failed or unexpected wait,
any other code, and every job-termination/query/close error remain UNKNOWN.
There is no second termination attempt, PID lookup, rights expansion or added
deadline. Later signaling cannot waive a failed immediate recheck. All retained
owned jobs must still report zero active processes before pins are released.

First-failure diagnostics include a fixed cleanup-operation label, or null
outside cleanup. At most three fixed recheck records contain only a process
ordinal, code 5 and a fixed wait-state label. No raw handles, identities, paths or
exception messages are recorded; existing evidence budgets remain unchanged.
These are injected-source semantics, not native qualification. Historical
cleanup errors lacking an operation label remain unattributed and consumed.

### Primary ABI/design references

- [Process creation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) and [STARTUPINFOEX](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw).
- [Process termination, asynchronous completion and post-exit error 5](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).
- [Attribute lists, JOB_LIST and HANDLE_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
- [Nested jobs and inherited limits](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs) and [fixed UI restriction layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions).
- [Job basic limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information), [extended layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information) and [CPU hard cap](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information).
- [DuplicateHandle rights and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle), [creation FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes) and [image identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew).
- [Owned-job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject), [fixed job query](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject) and [basic accounting layout and reference lifetime](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).
- [Current-process token open](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken), [fixed token query](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) and [four-byte elevation value](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_elevation).
