# Lumi Eggcracker inert human-stop prototype

This source-checkout experiment is separate from the production daemon. Its
evidence label is `IMPLEMENTED_INTERNAL`; every result carries
`SIMULATION_ONLY`. It does not install or change a detector, approval policy,
socket, cgroup, firewall, provider integration or privileged service.

## Run the originating journey

Use Python 3.11 or later, from a checkout containing all six experiment files:

```text
python -B experiments/human_override/lab.py --output ABSOLUTE_FRESH_DIRECTORY
python -B -m unittest discover -s tests -p test_human_override_lab.py -v
```

Replace `ABSOLUTE_FRESH_DIRECTORY` with a new directory beneath a trusted,
existing parent. The CLI refuses an existing destination and never cleans it
up. A partial failed run is retained; choose another fresh destination. In the
controlled company environment, use only the assigned F:/G: temporary root,
verify the runtime's selected temp directory first and disable bytecode/caches.

`result.json` contains per-event outcomes, separate controller/World states,
simulated ticks and SHA-256 hashes of all six source/configuration files. Exit 0
means all manifest checks passed, 1 means a check failed, and 2 is an input or
I/O error. Record the exact Git commit, OS, Python version, UTC execution time,
command and result hash alongside a replay. No hosted/native efficacy is implied.

The first case approves and launches A, durably latches stop, reloads the
controller, refuses approvals/restarts/guest reset, disconnects local work,
observes that remote work is still running, separately cancels it, observes
stopped state, and permits human recovery. Recovery never launches work; a new
approval and start are required. B is outside A's selected boundary.

## State and trust contract

- Admission, stop request and observed execution are independent fields.
- The trusted scenario driver supplies the principal. There is no real
  authentication. A guest payload cannot declare its own principal or inject
  an observation through the command interface.
- Allocation ID, generation and stop epoch bind every command. Sequence
  high-water marks survive restart. Rename/replay cannot enrol another resource.
  Recovery advances the epoch, fencing even higher-sequence commands queued
  before reset. Exhausted epochs never wrap or automatically unlock.
- The latch is persisted before the fake adapter can act. Missing, malformed
  or failed storage blocks admission and yields unknown observations; it does
  not prove running work was stopped. Observations are not restored from disk.
- Only the independent fake World sampler establishes `VERIFIED_STOPPED`.
  It includes local and remote execution, exact generation/epoch/revision and a
  five-tick freshness limit. Lost control, failed observations and stale samples
  are `UNKNOWN`. This is synthetic observation, not real external verification.
- A disconnected remote job still runs until a separate fake cancellation.
- The controller is single-writer. Interleavings are serialised permutations,
  not a claim of thread-safe locking or distributed consensus.
- Audit storage is bounded per allocation; denial payloads are never recorded.
  Trimming audit entries never trims the latch or replay counters.

The run-owned parent, controller state and World are trusted. Same-process
Python callers can modify these objects; this experiment proves no protection
against malicious Python code, a compromised host, filesystem rollback or a
compromised controller. Atomic replacement and file fsync model restart
durability but are not qualified power-loss guarantees. A leftover `.pending`
file causes a subsequent write failure and inhibits admission; recovery is not
automatic and must not discard an unknown stop state.

## E0 comparison boundary and limits

[The versioned protocol](../experiments/counter_ai/protocol.v1.json) freezes
separate track acceptance, observable event semantics, arm configurations,
response timing, development/evaluation family reservations, seeds and scoring.
The CLI hashes that protocol and the
[development scenarios](../experiments/human_override/scenarios.v1.json).
Future replay commands in the protocol are `INTENDED`, not available commands.
The separate E1/E3 CLI below implements all-arm replay instead of those earlier
per-arm command placeholders. No detector advantage or AI attribution is assumed.

Six abstract protected-effect markers are reachable without a stop and blocked
after the fake adapter stops execution. They test state reachability only, not
six implemented access controls. A benign unrelated allocation remains active.
Harm reached before containment remains harm, even if work stops later.

E4 real human-stop work follows the small E2 model and concrete independent
Risk/technical acceptance of a dedicated disposable Linux boundary and separate
controller. Detector superiority is not a prerequisite. E1/E3 inert research
can continue under a subsequent exact scope while E4 prerequisites are resolved.
Windows feasibility follows useful Linux evidence; shared event semantics do
not establish Windows or macOS protection. Internal tests are not adoption,
independent installations or commercial evidence.

## Synthetic E1/E3 comparison

```text
python -B experiments/counter_ai/replay.py --output ABSOLUTE_FRESH_DEV --split development
python -B experiments/counter_ai/replay.py --output ABSOLUTE_FRESH_SEAL --freeze
python -B experiments/counter_ai/replay.py --output ABSOLUTE_FRESH_EVAL --split heldout --seal ABSOLUTE_FRESH_SEAL/seal.json
```

Development tests never evaluate the held-out recipes. The source seal binds
detector, generator, fixture/protocol, response model and test hashes, Git base
revision, interpreter path/hash and OS/Python build identity. Any change invalidates it. Freeze before evaluation;
do not tune after seeing results. Recipes are source-visible and predeclared,
not a blinded independently designed holdout.
The manifest specifies 3 development recipes and 24 reserved evaluation variants
(12 harmful, 12 benign), 5 seeded configurations and fast/slow pacing. These are
abstract toy patterns, not validated independent real-world scenario families.

Every trace has 16 generated actions. Sensor availability delay and telemetry
loss are separate from the judge's protected-effect time. A response at the same
tick as an effect is too late. Every protected arm has the same static ACL;
automatic detectors share the E2 fake adapter and one-tick response delay.
Alert-only uses an explicit 30-tick delay. Protection-disabled controls establish
effect reachability. B is a separately running unchanged canary in every arm.

`dataset.json` contains observable events plus separately named oracle effect
timing. Detectors receive only Event objects: opaque run identity, allocation,
generation, event ID, sensor, event/available ticks, action, resource and actor
identity. No harmful label, hidden reasoning or effect oracle enters detection.
Each detector binds one opaque run ID. Known gap markers clear its correlation
and rate history, retaining replay-ID memory; output reports gaps and the judge's
dropped-telemetry count rather than treating missing observations as safety.
`result.json` records paired raw outcomes, fast/slow counts, benign interruption
and completion, missing detections, detected-only latency, four-step explicit
recovery, and whole-family bootstrap intervals. Simulated workload-hour reporting
assumes one tick per second; it is not measured operating time. No runtime
overhead, real recovery latency or production false-positive claim follows.

The conventional rule fires on an explicit protected-resource denial or tamper.
Correlation retains it and additionally uses ordinary denials followed by changed
identity/resource; ablations remove timing, sequence or identity relationships.
Legitimate failed-access/retry workflows are included to expose collateral cost.
Keep null/negative results. Any apparent gain in these designed toy variants needs
a stronger independently designed evaluation before a general protection claim.
