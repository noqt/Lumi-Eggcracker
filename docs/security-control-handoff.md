# Inert security-control handoff example

This Lumi Eggcracker developer example explores a future local workflow handoff:
an authorised control requests action on exactly one owned supervised workload,
and technical and stakeholder views describe the same bounded result. It is a
contract fixture, **not a production interface, authentication mechanism or stop
command**. It imports no Eggcracker runtime, touches no processes, opens no socket,
and uses only fabricated identifiers and an in-memory fake receiver. Passing
tests establish internal contract behaviour only, not containment or customer use.

Existing runtime controls are not replaced. See [Security model](../SECURITY_MODEL.md)
and [Limitations](../LIMITATIONS.md) for existing socket roles, approval boundaries
and single-use workload names. This example does not imply those controls are absent.

## Runnable unprivileged path

From the repository root, use an existing Python 3.11+ environment. No installation,
extra dependency, daemon or administrator session is required.

On Linux, first set `TMPDIR` to an existing writable POSIX directory approved for
your test work. Do not use a privileged session for this example.
The following creates a fresh child directory and checks the interpreter's actual
temporary-directory choice before running the inert tests:

```sh
(
    set -eu
    : "${TMPDIR:?Set TMPDIR to your existing approved test directory}"
    test "$(id -u)" -ne 0
    task_temp=$(mktemp -d "$TMPDIR/eggcracker-handoff.XXXXXX")
    task_temp=$(cd "$task_temp" && pwd -P)
    export TEMP="$task_temp" TMP="$task_temp" TMPDIR="$task_temp"
    export PYTHONDONTWRITEBYTECODE=1
    python3 -B - <<'PY'
import os
import pathlib
import runpy
import sys
import tempfile

assert sys.version_info >= (3, 11)
assert pathlib.Path(tempfile.gettempdir()).resolve() == pathlib.Path(os.environ["TMPDIR"]).resolve()
sys.argv = ["tests/test_security_control_handoff_contract.py", "-v"]
runpy.run_path(sys.argv[0], run_name="__main__")
PY
)
```

Expected result: `Ran 13 tests` and `OK`, including the valid journey and explicit
refusal cases. This is the inert contract suite, not the full product regression
or Linux containment qualification. The created temporary directory is left in
place; this command performs no cleanup of existing data.

The test suite covers acceptance/refusal, stale handle, replay, replacement,
fake failure and concurrent-request cases. `test_valid_one_owned_fixture_and_two_identical_views`
is the complete valid journey. It checks one fake call for `owner-a/generation-a`,
`accepted=True`, `dispatched=True`, `observation=SIMULATED_COMPLETE`, and
`verified_stop=False`. No receipt file or telemetry is generated.

## Proposed request and trust assumptions

The request has exactly `request_id`, `handle`, `issued`, and `expires`.
Identifiers are 1–64 lowercase ASCII letters/digits/hyphens, not PIDs, names of
executables, paths or containment destinations. Integer fixture clock values
require `0 <= issued <= now < expires <= issued + 30`; booleans are not integers
for this contract. The separately simulated supervisor supplies the clock,
trusted caller identity, registry, current generation, grants and support flag.
These are **test assumptions, not real authentication or a deployable trust boundary**.
There is no credential store. A request-supplied caller field is malformed.

An opaque fixture handle binds one owner and generation, with its own expiry.
Authority is the tuple (trusted caller, owner, generation), not possession of the
handle or local access alone. A replacement gets a different handle and generation;
the old binding remains stale and grants never transfer. Revalidation under one
lock immediately before fake dispatch covers freshness, current binding, authority
and support. Registry and grant changes in tests stand for a trusted supervisor,
not public mutation operations. The model has one current generation per owner;
that simplification is not a proposal for runtime workload ownership.

## Closed results and one source of truth

| Code | Meaning in this fixture | New fake calls |
| --- | --- | --- |
| `MALFORMED` | Shape, field type or identifier rejected | 0 |
| `NOT_FRESH` | Future, expired or invalid request lifetime | 0 |
| `UNKNOWN_HANDLE` / `HANDLE_EXPIRED` / `STALE_HANDLE` | Target binding unavailable or no longer current | 0 |
| `NOT_AUTHORIZED` / `UNSUPPORTED` | Simulated grant or supported-path gate absent | 0 |
| `DUPLICATE` | Same caller/request ID and exact request already accepted | 0 |
| `REPLAY_CONFLICT` | Same caller/request ID reused with different contents | 0 |
| `ALREADY_DISPATCHED` | Another ID already reserved this instance | 0 |
| `NO_RECEIVER` | Accepted, but no receiver available; no observation | 0 |
| `FAKE_RECEIVER_FAILED` | Fake call raised; failure remains unconfirmed | 1 |
| `FAKE_DISPATCHED` | Fake receiver returned a bounded observation | 1 |

Every result contains only `code`, `accepted`, `dispatched`, `observation`,
`verified_stop` and fixed scope `FABRICATED_OWNED_FIXTURE_ONLY`. Both views are
derived from that immutable record, not independently authored summaries. Raw
requests, exceptions and unexpected receiver data are never included. Observations
are `NONE`, `SIMULATED_COMPLETE`, `PARTIAL`, `UNKNOWN`, or `FAILED`; unexpected
fake output becomes `UNKNOWN`. **Even SIMULATED_COMPLETE never verifies a stop.**
Acceptance, dispatch, observation and verification are separate facts.

Replay lookup follows current authority/freshness/binding checks. Duplicate replies
are explicit refusals of a new dispatch, not reissued old success. A changed target
under the same ID is a conflict; a newly authorised replacement needs a new ID.
Different IDs cannot dispatch the same instance twice. The synchronous lock
serialises simultaneous calls; tests synchronise competing threads with a barrier
and assert exactly one call regardless of winner. Reservation occurs before the
fake call, so failure, uncertainty or a missing receiver cannot trigger automatic
retry. In this toy model `ALREADY_DISPATCHED` includes that reservation, not proof
that the receiver ran. All replay state is memory-only: restart recovery, durable
idempotency and production concurrency are unresolved, not supported features.

## Evidence limits and next integration gate

The example exercises only fabricated scope and outcome consistency. It establishes
neither AI detection nor real stopping, safe production authorisation, external
service revocation, demand, or independent use. It does not change the existing
optional local receipt or grant sharing authority.

The smallest next real-integration recommendation is to assess the existing trusted
local interface and supervisor lifecycle against this contract: caller identity,
target-specific authority, immutable instance binding, minimum privilege, replay
recovery and bounded outcomes. Resolve those choices and obtain fresh independent
pre-action technical review before connecting any real receiver. A separately
authorised disposable supported-host replay of an owned harmless child tree with
an unrelated canary would then test that exact path only. No automatic retries,
arbitrary killing, privilege expansion, public listener or external-system control
is authorised by this example.
