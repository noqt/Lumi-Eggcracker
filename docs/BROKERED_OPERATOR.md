# Synthetic brokered operator

This package is a standard-library-only, unprivileged demonstration of a
brokered action flow. It is separate from Lumi Eggcracker's daemon and public
command line. Its only effect is a durable increment of a synthetic protected
counter. It cannot address a process, arbitrary file or path, URL, shell,
network, or secret.

The trusted registrar creates a random immutable run identity and signs one
fixed capability: action `increment`, target
`synthetic.protected-counter`, generation zero, a 60-second wall-clock expiry,
and a four-action budget. The client receives that grant and can submit only an
operation identifier. It cannot choose identity, target, action, generation,
expiry, or budget. The JSON envelope is UTF-8, canonical JSON with sorted keys,
compact separators, and one trailing newline. Runtime validation rejects
duplicate keys, unknown fields, non-canonical encodings, booleans in integer
fields, invalid token signatures, and inputs over 4096 bytes. The JSON Schemas
in `schemas/brokered-*.schema.json` describe the same public envelope, grant
claims, and bounded receipt shapes; the runtime does not rely on a schema
validator.

Admission stores the exact canonical bytes and reserves the per-run and global
budgets. Dispatch accepts only a server-created queue identifier. Under the
durable state lock it reloads and validates those immutable bytes, the signed
capability, exact target/action, expiry, replay key, budget, run status, and
generation immediately before appending the one synthetic effect. A request at
or after its expiry millisecond is expired. An applied or rejected queue item
cannot be dispatched again. Replay keys are retained for the store lifetime;
when the bounded registry fills, new admission fails closed without evicting
keys or changing live generation fences.

The journal is append-only and HMAC-chained. A separately anchored witness
records the latest journal sequence and digest, so missing, malformed, replaced,
or rolled-back journal state fails closed on reopen. Revocation and a stop
request advance the stored generation and make earlier queued actions stale.
Receipts have fixed fields and a 512-byte maximum; they contain no capability or
request payload. Admission, dispatch/effect, revocation, and process-stop
reporting have distinct phases. A stop request revokes the capability only.
Verified process termination is explicitly `UNSUPPORTED`.

The demo can be run from the repository root with:

```powershell
python scripts/brokered_operator_demo.py
```

It shows one applied action, replay and post-stop denials, a stale queued action,
an unsupported process-stop proof, an unchanged unrelated synthetic allocation,
and the same protected-effect count after state reopen.

## Limits

This is an in-process synthetic slice, not a production control plane or a
security boundary. Same-UID state protection is unsupported: a user able to
rewrite both the anchor and journal can replace the trust state. Authenticated
IPC is unsupported. OS containment and isolation are unsupported. Verified
process termination is unsupported. The wall-clock expiry depends on the local
trusted registrar's clock. Do not use the synthetic receipt as evidence that a
real process was admitted, dispatched, stopped, contained, or verified empty.
