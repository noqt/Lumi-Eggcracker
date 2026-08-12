# Eggcracker repository instructions

These instructions apply to the whole repository. A deeper `AGENTS.md` may add
narrower rules for its subtree, but it may not relax the safety, evidence,
rights, preservation, or publication boundaries below.

## Authority and source truth

1. Exact action-specific founder, legal, risk, and publication authority in the
   governing company control plane takes precedence.
2. An accepted bounded work order controls scope, branch, worktree, tests, and
   stop conditions.
3. This file controls repository-local execution. Current tracked source,
   tests, `README.md`, `SECURITY_MODEL.md`, `LIMITATIONS.md`, and
   `QUALIFICATION.md` are the product-behaviour evidence to reconcile, not
   permission to broaden an action.

The public source repository is
`https://github.com/noqt/Lumi-Eggcracker`. Bind work to an exact commit; do not
treat a local branch name, stale local `main`, tag, build, or worktree as proof
of current public state. On an instruction, source, documentation, or evidence
conflict, preserve the state and stop the affected claim or mutation until the
conflict is reconciled.

## Destructive enforcement boundary

Eggcracker is a privileged native-Linux enforcement daemon, not an alert-only
tool. An unapproved **complete** match to an active qualified profile is stopped,
captured into the exact delegated cgroup, and automatically killed with
`cgroup.kill`; it does not wait for operator confirmation. Root installation,
native discovery, containment, watchdog, cgroup, or uninstall tests may run only
under an explicit bounded assignment in a disposable supported Linux
environment whose loss is acceptable. Record the exact host/VM, kernel,
systemd/cgroup-v2 capabilities, operator, commit, artifacts, and cleanup result.
Never run destructive qualification on a workstation, server, shared host, or
non-disposable environment.

Exactly two profiles are active in version 0.4.0:

- `content.gguf-llama`: a bounded plausible GGUF v2/v3 header plus either the
  qualified llama.cpp/GGML ELF marker pair or the exact pinned launcher build
  ID.
- `content.safetensors-pytorch`: a structurally valid contiguous Safetensors
  artifact plus the exact pinned CPU PyTorch bridge-and-ATen ELF build-ID pair,
  observed in one process or the documented bounded related workload using the
  dedicated workload UID.

Name-only Ollama, vLLM, TGI, LocalAI, llamafile, agent-CLI, and other catalogue
entries are inactive research until separately qualified. Do not claim
universal or arbitrary AI/agent/runtime identification, proof of inference,
malware prevention or detection, IDS/EDR capability, sandboxing, network,
credential, or filesystem isolation, container/cloud/remote-API protection,
zero escape, or protection of unobserved or already-escaped processes. A receipt
proves only that the exact captured quarantine cgroup was empty at the recorded
point.

## Evidence and claims

Use only these evidence labels:

- `OBSERVED`: directly inspected fact, bound to source, time, and identity.
- `IMPLEMENTED_INTERNAL`: present in an exact commit or artifact and exercised
  by named internal checks; not independent use or market evidence.
- `INTENDED`: planned or designed but not demonstrated as implemented.
- `UNSUPPORTED`: absent, conflicting, stale, or insufficient evidence; do not
  present the claim as fact.

Bind every technical result to the exact commit and artifact hash, test command,
OS/host or VM, Python version, timestamp, and relevant skips or limitations.
Do not generalise a fixture, internal Windows control run, one Linux host, CI
run, or receipt into universal capability, native qualification on another
host, independent installation, adoption, demand, or safety assurance.

Current release snapshot, recorded 12 August 2026 and requiring revalidation
before any external use:

- public annotated `v0.4.0` and its CI run are bound to
  `418f877f0d450aeb26d4a1233257746808c490e5`; the recorded CI passed Ruff,
  69 unit tests, build, and release verification;
- no matching GitHub Release was observed; and
- local commit `a3ad746682c89599ce582cd97acf5a99742dc3aa` is an unpushed
  attribution-only descendant. Its exact candidate has **internal Windows
  control evidence** accepted by a separate internal control reviewer for Ruff,
  69 tests with three documented Windows skips, build/release verification,
  hashes, archive identity, and preservation. This was an internal control
  review, not an independent external audit or assessment. It is not public,
  native-Linux qualification, independent use, or market evidence.

## Proportional verification

Run only checks material to the change, and report what actually ran:

- documentation-only: instruction precedence, links and repository paths,
  evidence/claim vocabulary, prohibited-claim scan, one-file scope where
  applicable, and `git diff --check`;
- Python or behavioural change: Ruff and the complete unit-test suite;
- packaging or release-material change: Ruff, unit tests, release build, and
  `verify_release.py`, with exact artifact hashes; and
- detector, profile, approval, root boundary, cgroup, watchdog, containment,
  install/uninstall, or other security-material change: all applicable checks
  above plus the complete commit- and host-bound native qualification in
  `QUALIFICATION.md`, inside the disposable supported Linux environment.

A Windows pass cannot substitute for a native gate. Do not silently weaken a
test, skip, threshold, negative control, or qualification matrix to obtain PASS.

## Preservation, compatibility, and rights

Treat Git history, tags, untracked files, generated candidates, evidence packs,
receipts, manifests, checksum files, and release artifacts as protected. Before
mutation, inventory the original checkout and all worktrees; after mutation,
prove preservation. Never use destructive reset, clean, history rewrite,
force-push, tag replacement, bulk overwrite, or deletion without exact
authority. Write new evidence and artifacts to a fresh task- and commit-bound
location, hash them, and stage only an explicit intended file list.

Preserve established repository, package, command, socket, policy, receipt,
manifest, artifact, and schema identifiers unless an authorised compatibility
plan proves the transition. The project is Apache-2.0: retain `LICENSE` and all
applicable notices and third-party terms. Do not change legal holders,
copyright/attribution, licence posture, or add a materially licensed dependency
without the corresponding reserved review and authority. Do not invent,
introduce, or infer a current company brand; preserve existing product and
technical identifiers where compatibility or provenance requires them.

Local branches, permanent worktrees, commits, test artifacts, and release
preparation are not pushes, tags, GitHub Releases, deployments, publication, or
public claims. Perform any product-remote push, tag creation/change, release,
deployment, or publication only with exact action-specific authority for this
repository, after independent review. Silence, an existing public tag, passing
CI, or a locally accepted candidate is not publication authority.

## Runtime, privacy, and secrets

In the controlled local execution environment, operate only on F: and G:.
Before any runtime, test, or tool that may use temporary or cache storage, create
a task-specific `[TASK_TEMP]` on F: or G: with
`New-Item -Path [TASK_TEMP] -ItemType Directory -Force -ErrorAction Stop` (do
not substitute `-LiteralPath` on `New-Item`); resolve it, prove it exists as a
directory on exactly F: or G:, set `TEMP`, `TMP`, `TMPDIR`, and
`PYTHONDONTWRITEBYTECODE`, and start a fresh runtime that asserts its selected
temporary directory resolves exactly to `[TASK_TEMP]`. Abort before substantive
execution on creation, resolution, drive, or equality failure. Disable caches
or bind them explicitly to F: or G:.
`Environment-variable assignment alone is not evidence.`

Do not inspect credential stores, reveal secrets, commit machine-specific paths,
personal data, raw process arguments or environments, private external data, or
customer/user material. Use synthetic fixtures and redacted, bounded evidence.
Raw arguments and environment values do not belong in approvals, detections,
receipts, logs, or committed guidance.
