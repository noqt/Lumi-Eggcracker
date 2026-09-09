# Lumi Eggcracker whole-VM stop: mock design only

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
