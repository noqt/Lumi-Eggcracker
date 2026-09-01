# Changelog

## 1.0.6 (release candidate)

- Cache the last fully validated bounded incident store and use exact file
  metadata to detect any subsequent change, avoiding repeated parsing and
  integrity hashing on every discovery candidate and health query.
- Adopt successful root-owned atomic incident updates directly into that
  cache while retaining full fail-closed revalidation for external changes,
  overflow compaction and malformed records.
- Preserve the one-second discovery/watchdog health bound under the full
  256-record incident history used by the adaptive revocation-race campaign.

## 1.0.5 (release candidate)

- Retry bounded terminal-history pruning after exact offline-boundary teardown
  succeeds, preventing namespace identity reuse from leaving the store above
  its 128-record limit on a busy or rebooted host.
- Protect the just-completed run during the post-cleanup pass and continue to
  retain any terminal record whose namespace cleanup remains uncertain.

## 1.0.4 (release candidate)

- Serialize deterministic owned-cgroup containment against autonomous
  enforcement so an operator, tripwire or boundary kill cannot race a second
  detector kill and create a redundant lockdown incident while the approved
  process is disappearing.
- Preserve the 1.0.3 exact offline-boundary cleanup repair and bind both fixes
  to a new package identity and complete native/adaptive requalification.

## 1.0.3 (release candidate)

- Reclaim an Eggcracker-owned workload's exact offline namespace pair after an
  autonomous detector kill, after containment and receipt publication but
  without waiting for a supervisor restart.
- Fail `doctor` closed when a terminal run still retains either recorded
  namespace mount, while preserving the successful containment result and the
  identity needed for safe restart recovery.
- Support an in-place upgrade from the local 1.0.2 candidate and bind the repair
  to fresh native and adaptive qualification evidence before release.

## 1.0.2 (release candidate)

- Add opt-in fail-closed approval admission for protected starts: when
  `--require-approval` is selected, a missing or concurrently revoked exact
  approval rejects the request before any workload-side effect.
- Preserve ordinary unapproved starts as the deliberate path for autonomous
  supported-profile recognition and whole-tree containment.
- Reclaim exact recorded offline namespaces for terminal workloads during
  supervisor recovery, and fail health closed if identity-checked cleanup
  cannot complete. Retain any terminal run record while its namespace mounts
  still exist so history compaction cannot erase that cleanup authority.
- Bind the repair to a new artifact identity and require the complete native
  and adaptive qualification campaign before any release decision.

## 1.0.1 (release candidate)

- Treat root-owned launch provenance as proof of prior admission, not a
  perpetual authorization: revoking the exact approval generation makes a
  still-running supported AI workload eligible for autonomous containment.
- Reject same-named replacement approvals as authority for an already-running
  launch and serialize the detector's approval snapshot with root approval
  administration.
- Preserve the failed Daybreak revocation-race preflight as negative evidence
  and require the repaired native matrix before release.
- Serialize autonomous containment with owned-run completion so a cgroup made
  empty by detector enforcement cannot be transiently reported as an allowed
  benign completion before its terminal kill state is durable.
- Link a successful autonomous incident to the exact owned workload record
  after containment, allowing recovery tooling to identify the selected run
  without replacing the authoritative quarantine kill receipt.
- Never prune the terminal run record in the transaction that just persisted
  it, avoiding cross-boot monotonic-clock ordering from erasing the newest kill
  status under a full retained history.

## 1.0.0 (release candidate)

- Freeze the integrated four-profile native CPU product after the 0.7, 0.8,
  0.8.1 and 0.9 milestones.
- Bind the candidate to deterministic qualification, packaged-artifact
  verification and the adaptive campaign evidence plan.
- Make the public first-kill path default to `v1.0.0` and make the support
  helper use the installed, root-owned zipapp shipped by the verified bundle.
- Require a detached release-checksum signature from the pinned release key and
  reject duplicate, link, special, oversized and unsafe ZIP members before any
  bundled installer can reach root execution.
- Serialize install, upgrade and uninstall, and durably recover an interrupted
  first installation or removal when the exact public command is retried.
- Reject non-canonical ZIP member spellings and ambiguous trailing or
  concatenated archive data before privileged installation.
- Interpret duplicate Safetensors tensor names with the reference loader's
  final-value semantics, then validate the resulting exact layout, so a model
  accepted by the pinned loader cannot evade recognition by repeating a key.
- Keep publication, signing, tagging and external deployment as separate
  decisions.

## 0.6.0

- Add one root-controlled offline boundary for every explicitly selected workload.
- Allow loopback and count/drop all non-loopback IPv4/IPv6 output in a transient
  run-owned namespace; an authenticated counter increase automatically invokes
  the existing whole-tree `cgroup.kill` path.
- Bind namespace, veth, table, chain and counter identities to the active run,
  preserve fail-closed restart and observer handling, and expose only bounded
  boundary health and receipt summaries.
- Add the primitive-only native qualification harness and expand release,
  installer, watchdog, support-bundle and documentation checks for 0.6.0.

## 0.5.0

- Repair the independently reported Linux artifact-cache regression and test the supported Python 3.11, 3.12 and 3.13 runtimes in CI.
- Carry forward the Daybreak approval, containment-scope, runtime-authentication, descriptor-fairness, watchdog and lifecycle repairs on a new release identity; the immutable `v0.4.0` tag remains historical evidence only.
- Add portable, metadata-preserving release-evidence packaging and verification.
- Require the five focused P0 campaigns, exact 41-case adversarial replay and ordinary Ubuntu 24.04 qualification before publishing the engineering preview.

## 0.4.0

- Add bounded Safetensors structural validation and exact pinned CPU PyTorch/ATen build-ID-pair recognition.
- Migrate content catalogue groups to `MODEL_RUNTIME` in schema v3 while preserving GGUF/llama behavior.
- Contain unapproved complete Safetensors/PyTorch matches autonomously, including converters and inspectors; partial matches survive.
- Limit the active public catalogue to the two qualified content profiles; withhold unqualified name-only runtime entries.
- Bind approval consumption before exec to the exact protected `start` PID/start-time, owned cgroup and executable identity; never grant approval from mutable post-exec arguments.
- Bind supported CPython approvals to an immutable staged script and reject mutable or unsupported interpreter forms before launch.
- Capture the full bounded related evidence component and connector parent after a minimal complete match, preventing incomplete sibling-pair containment receipts.
- Tie supervisor heartbeats to recent successful scan completion and bound enforcement admission.
- Preflight and empty only exact stopped service cgroups before uninstall, and validate every published release checksum.

## 0.3.0

- Add bounded name-independent `content.gguf-llama` recognition from validated GGUF content and two ELF runtime markers.
- Keep exact approvals and immediate pidfd-stop/cgroup-kill enforcement for content matches.
- Add redacted content-path detection receipts and renamed-runner content smoke tooling.

## 0.2.0

- Add deterministic autonomous discovery of unapproved supported AI runtimes.
- Add exact operator approvals, pidfd stop, quarantine cgroup capture and post-containment detection receipts.
- Preserve selected-workload cgroup containment and exclude N1 networking from the product release path.

## 0.1.2

- Add a pinned, opt-in external asset preparation path and five-run real-AI smoke demonstration.
- Keep third-party runner and model binaries out of published release archives.

## 0.1.1

- Renamed the public product to Lumi Eggcracker.
- Repaired launch, watcher, lifecycle, receipt, identity, and release hygiene paths.

## 0.1.0

- Retained public engineering-preview predecessor; not rewritten by this release.
