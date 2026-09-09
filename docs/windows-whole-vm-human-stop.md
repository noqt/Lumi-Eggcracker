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

`windows_job_backend.py` adds lazy ctypes data layouts and API signature metadata
bound **only to injected Python functions**. There is no DLL loader or executable
native binding. Imports do not even construct the layouts. `native_backend()`
always refuses; the CLI's three native roles also always refuse. This is
`IMPLEMENTED_INTERNAL` stub preparation, not a qualified native adapter.

```text
python -B experiments/human_override/windows_job_probe.py
python -B -m unittest discover -s tests -p test_windows_job_backend.py -v
```

The default CLI prints a proposal with SHA-256 hashes of all five current source
files. It launches nothing and writes no result file. The tests call Python fakes
and exercise Windows x64 layouts on a 64-bit interpreter. They do not validate
Windows API availability or enforcement. Fixed-width DWORD/BOOL/UTF-16 and
pointer-sized HANDLE/SIZE_T avoid host-dependent `c_long`/`c_wchar` widths.
The selected structures are naturally aligned, not packed; x86 is refused.

The one-shot adapter prepares an unnamed job with kill-on-close, one active
process, a 256 MiB committed-memory limit and a 10% CPU hard cap. These are
**stubbed API arguments**, not observed resource enforcement. Creation uses an
explicit application, mutable UTF-16 command/environment, no inherited handles,
no console, and suspended atomic JOB_LIST assignment. Unsupported creation or
limit setup fails closed. No running/unassigned fallback exists. The only child
command represented is isolated-mode Python sleeping for 60 seconds; that child
program requests only sleep. OS/interpreter startup still loads runtime files;
`-I -S -B` is not a sandbox or a promise of zero startup access.
Its chosen executable is not yet hash-admitted
by this adapter: path/configuration syntax checks are not provenance checks.

Both returned process/thread handles are retained before identity checks. A
creation FILETIME, returned PID, exact image path, generation and configuration
digest are persisted before resume through a trusted injected persistence hook.
The hook is not native durable storage. A stop sets the latch first, persists,
then validates and terminates only the same retained process handle; persistence
failure still attempts dispatch but returns durability unconfirmed. Job close
is attempted before other owned handles; failures remain UNKNOWN and all other
closes are attempted. Successfully closed handles are never closed twice.
Injected close interruptions are retained as cleanup failures without aborting
the remaining closes or masking the original startup failure. UNKNOWN remains
sticky after an earlier cleanup failure, even if a later retry closes the handle.

The local query duplicate has only QUERY_LIMITED_INFORMATION and SYNCHRONIZE,
is non-inheritable and remains owned by the adapter. Observation holds the same
lock as close to avoid numeric-handle reuse during queries. It requires matching
identity, prior liveness and a signaled process plus successful exit-code query.
This is an in-process stub observer, **not the independent native judge**. It
does not feed the accepted mock admission controller or authorize native reset.
The existing `MockKernel`, `Controller` and admission logic remain unchanged.

### Next harmless-process proposal, not executable authority

Before a VM, propose the pinned portable CPython 3.12.10 Windows x64 executable
(SHA-256 `6461fe8dc13c642302f591c0c1c16b220629f7a336f74ce88aa2cdd31c43e62a`)
running only `import time; time.sleep(60)` with `-I -S -B`. The exact local
executable, dependent runtime files and fresh F/G paths must be separately
recorded, held against change and reviewed. The CLI binds this proposal to the
current five-file source hashes; those hashes alone do not grant execution.

A separate supervisor would retain the controller handle from its own creation
call and enforce a 30-second deadline starting before controller creation. On
the scoped crash/hang case it would terminate only that exact controller,
causing the target job's last handle to close. This deadline is **not implemented**;
a sleeping target and a controller-local timer are not independent enforcement.
Supervisor loss and any unconfirmed cleanup must remain explicit residual gaps.

A separately created observer outside the target job would receive only a
query/synchronize target duplicate through an explicit HANDLE_LIST. The observer
launch needs inheritance enabled for that precise list; the target launch does
not. Never inherit the job or a terminate handle. Observer ownership transfer,
its pre-liveness handshake, bounded result channel and shutdown are not yet
implemented. No process handle is reopened by PID, name or a saved numeric value.
The temporary inheritable copy must close after confirmed transfer and on launch
failure, with concurrent launches excluded while it exists. The observer must
acknowledge its suspended-target identity before resume, then actual liveness
before any measured intervention; handshake failure aborts the launch.

The future contract must separately bound controller, supervisor, observer and
outside-canary resources and cleanup, including permission to terminate only
those exact created roles. Fixed-count trusted evidence writes totaling at most
64 KiB per case are proposed. The fixed sleep has no output or file-writing
code; this is not an OS disk quota, an adversarial sandbox, or a VM disk solution.
Missing observer evidence stays UNKNOWN; do not claim primary exit proves a
whole job empty. Test actual job constraints before allowing that inference.

The concrete proposal selects at most ten serial cases and five simultaneous
roles including the supervisor. The controller's outer job would allow two
processes and 512 MiB committed memory including the nested target; observer and
canary jobs each allow one process and 128 MiB. Observer/canary CPU caps would be
5% each. No parent CPU rate is selected for the controller job so the inner
target's 10% setting is not silently multiplied by a parent rate. Each outer job
is unnamed, non-inheritable, kill-on-last-close, and owned only by the supervisor;
the distinct inner target job is owned only by the controller. This proposed
nested-job containment is unimplemented and needs actual capability checks.

The supervisor would retain minimal termination/synchronization handles to its
exact created observer and canary for cleanup, in addition to its controller
handle. It holds no inner target-job handle. Allow at most five seconds for
bounded cleanup after the 30-second case deadline; never abandon live roles
silently. Supervisor memory and OS job-termination scheduling latency are not
hard bounded by this proposal. If outer job close after supervisor loss does not
establish target/role exit, report UNKNOWN; no broad cleanup scan is permitted.

The child sleep was changed from 20 to 60 seconds during source review because
natural exit at 20 seconds would confound a 30-second deadline test. Human stop
and controller crash would occur one second after the live handshake and require
exit evidence within four seconds. A matched no-stop case must stay live for
five seconds before separate planned cleanup. The hang case requires independent
deadline intervention by 30 seconds and evidence within four seconds, clearly
before the child's natural sleep completion. Missing/late evidence is UNKNOWN,
not successful kill-on-close. No timing or native test has run.

Execution still requires a separate exact Chair grant and direct Risk/technical
acceptance after native binding, role separation, hash admission, deadline and
bounded logging are implemented and reviewed. No native qualification, Linux
boot, adaptive opponent, E4 completion or Windows efficacy follows here.

### Primary ABI/design references

- [Process creation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) and [STARTUPINFOEX](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw).
- [Attribute lists, JOB_LIST and HANDLE_LIST](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
- [Job basic limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information), [extended layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information) and [CPU hard cap](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information).
- [DuplicateHandle rights and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle), [creation FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes) and [image identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew).
