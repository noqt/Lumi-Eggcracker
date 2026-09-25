# Brokered synthetic operator

This additive package is a standard-library-only synthetic operator example. It
does not alter Lumi Eggcracker's daemon, containment, installer, or public CLI.
The existing in-process API remains a portable reference; the Linux local-IPC
path adds a separate unprivileged service/workload boundary. Neither path is a
production control plane or a general-purpose executor.

## Portable in-process reference

The trusted registrar creates a random immutable run identity and signs one
fixed capability: action `increment`, target
`synthetic.protected-counter`, generation zero, a 60-second wall-clock expiry,
and a four-action budget. The client receives that grant and can submit only an
operation identifier. It cannot choose identity, target, action, generation,
expiry, or budget. The UTF-8 JSON envelope is canonical (sorted keys, compact
separators, one trailing newline). Runtime validation rejects duplicate keys,
unknown fields, non-canonical encodings, booleans in integer fields, invalid
signatures, and input over 4096 bytes.

Admission stores the exact canonical bytes and reserves per-run and global
budgets. Dispatch accepts a server-created queue identifier. Under the durable
state lock it reloads and validates the immutable bytes, capability,
target/action, expiry, replay key, budget, run status, and generation immediately
before appending the synthetic effect. An applied or rejected item cannot be
dispatched again. Replay keys are retained for the store lifetime; capacity
exhaustion fails closed without evicting keys or changing live generation
fences.

The journal is append-only and HMAC-chained. A separately anchored witness
records the latest journal sequence and digest, so missing, malformed,
replaced, or rolled-back journal state fails closed on reopen. Revocation and a
stop request advance the stored generation and make earlier queued actions
stale. Receipts have fixed fields and a 512-byte maximum; they contain no
capability or request payload. Admission, dispatch/effect, revocation, and
process-stop reporting have distinct phases. A stop request revokes authority
only. Verified process termination is explicitly `UNSUPPORTED`.

## Linux authenticated local IPC

`lumi_eggcracker.brokered.linux_ipc` is Linux-only. It uses a pathname
`AF_UNIX` `SOCK_SEQPACKET` socket and checks the kernel-provided `SO_PEERCRED`
UID on every accepted connection before parsing the packet. The workload client
also checks `SO_PEERCRED` after connect and requires the expected service UID.
Service/workload UIDs, the service primary GID, and the IPC GID must be
non-root; service and workload UIDs must differ, and the service may not have
the root supplementary group. The service's state directory and files must be
service-owned with exactly `0700` and `0600` modes (special bits are rejected).
The socket's dedicated parent must be service-owned, owned by the workload IPC
group, and mode `0710`; the socket is created as service:workload-group mode
`0660`. Group access permits connection, but the exact UID check is the
authorization decision. The service pins the parent directory identity and
revalidates its path and inode around bind, accept, service, and close; it
removes only the exact socket inode it created from that pinned directory.

The service owns one durable run. First open creates its immutable identity;
later opens recover the same grant from the journal. A store with multiple run
identities fails closed. Reopen never creates a replacement identity after a
stop request or expiry. The grant remains private to the service process; the
workload protocol contains no run ID, target, action, generation, expiry,
capability, filesystem path, or work payload:

- `submit` accepts one bounded operation identifier and returns an admission
  receipt plus a server-created queue ID.
- `dispatch` accepts only that queue ID and uses an atomic run-bound dispatch
  check. The existing durable expiry, replay, budget, and generation fences are
  rechecked before effect.
- `get_result` accepts only the queue ID for an already-applied item. On first
  service registration, the service creates a bounded synthetic research batch
  with random sample identities and units, stores it in its private durable
  journal, and never accepts it from the workload. Dispatch journals the
  bounded aggregate report atomically with the applied queue/effect. Reopen
  replays and verifies that result, so it remains retrievable without exposing
  the private input or trusting workload input or an arbitrary output path.

IPC messages are canonical UTF-8 JSON with one trailing newline, duplicate
keys and unknown fields rejected, and exact operation-specific fields enforced
at runtime. Requests are limited to 1024 bytes, responses to 2048 bytes, and a
report to 1024 bytes. A rejected peer is denied before parsing or effect. There
is no generic callback, URL, arbitrary file target, shell, network action,
secret access, process kill, reset, or resume operation. The default
`scripts/brokered_operator_demo.py` remains the portable demo. Its `--linux-ipc`
modes expose service, submit, dispatch, result, run, trusted stop, and snapshot
commands for use under the separately provisioned service and workload
identities. For example, run `serve` as the service UID and client commands as
the workload UID. The one-shot `run` mode performs admission, dispatch, and
bounded result retrieval in order, then prints one JSON outcome containing all
three protocol responses:

```sh
python scripts/brokered_operator_demo.py --linux-ipc serve \
  --state-dir /var/lib/eggcracker-brokered/state \
  --socket /run/eggcracker-brokered/operator.sock \
  --workload-uid 1201 --workload-gid 1301
python scripts/brokered_operator_demo.py --linux-ipc run \
  --socket /run/eggcracker-brokered/operator.sock --service-uid 1200 --operation-id demo-1
```

On failure, `run` writes one bounded `run_failure` JSON diagnostic to stderr.
After a validated admission it includes that queue ID, the last validated
stage, and `effect_status`: `UNKNOWN` until an exact applied dispatch receipt
has been validated, then `CONFIRMED_APPLIED`. `UNKNOWN` does not establish
that no effect occurred; `CONFIRMED_APPLIED` describes only the synthetic
broker receipt.

For manual recovery, begin with the side-effect-free result lookup for the
validated queue ID:

```sh
python scripts/brokered_operator_demo.py --linux-ipc result \
  --socket /run/eggcracker-brokered/operator.sock --service-uid 1200 --queue-id QUEUE_ID
```

If it returns `AVAILABLE`, use that report and do not dispatch again. If it
returns `NOT_FOUND`, that lookup alone does not establish that no effect
occurred. If the operator decides to continue, the existing dispatch command
can be used manually with that validated queue ID, followed by inspection of
its receipt:

```sh
python scripts/brokered_operator_demo.py --linux-ipc dispatch \
  --socket /run/eggcracker-brokered/operator.sock --service-uid 1200 --queue-id QUEUE_ID
```

`run` never retries, resubmits, or redispatches automatically. Re-running it
with the same operation ID can return `REPLAY` without recovering the earlier
queue ID, so re-running is not a recovery path. This guidance does not
establish general retry safety.

Use the separate `submit` command when you need a queued operation to remain
pending; submitting it before the trusted service-side `stop` command lets you
observe stale queued denial. Subsequent submissions remain denied. Restarting
`serve` on the same state and socket paths recovers the stopped run rather than
minting a new one. `snapshot` reports the protected synthetic effect count and
the unchanged unrelated canary allocation.

A trusted service-side controller may call the service's `request_stop()` or
the demo's `--linux-ipc stop` command. This durably advances the run generation;
queued actions become stale and new admissions are revoked, including after
reopen. The service can remain available to return denials. `get_result` may
still retrieve an already-completed result; retrieval creates no new effect.
The stop receipt is an authority fence, not evidence that the service or a
workload process terminated. `verified_process_stop()` remains
`UNSUPPORTED`.

## Limits

The Linux IPC boundary authenticates a local peer UID; it does not make the
service's same-UID files tamper-resistant. Same-UID state protection is
unsupported: a process with the service UID can read or replace the anchor and
journal. The workload UID must not share the service UID. Authenticated IPC is
supported only for this specific local socket protocol; it does not imply
mutual authentication against a compromised service or protection from root.

OS containment and isolation are unsupported. This synthetic service does not
control an agent's other local APIs, inherited handles, environment, or
filesystem access outside the private state directory. Verified process
termination is unsupported. The wall-clock expiry depends on the trusted
service's local clock. Do not use a synthetic receipt as evidence that a real
process was admitted, dispatched, stopped, contained, or verified empty.
