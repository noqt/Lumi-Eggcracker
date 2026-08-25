# Lumi Eggcracker

[![CI](https://github.com/noqt/Lumi-Eggcracker/actions/workflows/ci.yml/badge.svg)](https://github.com/noqt/Lumi-Eggcracker/actions/workflows/ci.yml)

[v0.5.0 Release](https://github.com/noqt/Lumi-Eggcracker/releases/tag/v0.5.0)
· [Check host compatibility](#check-host-compatibility)
· [Run the hosted containment probe](#run-it-in-a-disposable-github-hosted-fork)
· [Run the first kill](#run-the-first-kill)
· [Design-partner Discussions](https://github.com/noqt/Lumi-Eggcracker/discussions)
· [Private security report](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new)

## The kill switch outside the sandbox

Lumi Eggcracker is a Linux guard for local AI. It watches for a complete,
unapproved AI workload, stops it automatically, kills its whole cgroup-v2
process tree, and leaves a bounded receipt proving the tree is empty.

> **Run the kill. Find the miss.**
>
> On a disposable native Ubuntu host, the first-kill path verifies the signed
> v0.5.0 Release, launches a pinned real Qwen workload, and shows whether
> Eggcracker terminates the complete process tree while an unrelated canary
> survives. We are opening three design-partner places for people who will run
> it, challenge the two supported profiles, and report friction or a
> reproducible miss. There is no telemetry, paid plan or sales call.

**Start with the read-only host check.** It makes no network request and creates
no workspace, build, installation or service. [Check compatibility
now](#check-host-compatibility), then continue to the full demonstration only
on a disposable supported host. A passing preflight is not a containment result.

**Try the core kill primitive without installing Eggcracker or supplying a
host.** [Fork this public repository](https://github.com/noqt/Lumi-Eggcracker/fork),
then follow the [GitHub-hosted containment-probe
steps](#run-it-in-a-disposable-github-hosted-fork). The manually acknowledged
workflow uses a disposable `ubuntu-24.04` runner, kills only a bounded synthetic
two-process tree, uploads no artifact, and reports a redacted pass or safe
refusal. [NOQT's reviewed hosted run](https://github.com/noqt/Lumi-Eggcracker/actions/runs/32892727768)
passed; that is implementation evidence, not independent use, workload
recognition, adoption, or product-wide effectiveness.

## Run the first kill

The public demonstration launches a real Qwen model through a pinned
llama.cpp runner, shows it running, lets Eggcracker recognise the unapproved
workload, and prints the post-kill receipt. It also checks that an unrelated
canary survives.

The recorded 62-second run produced this bounded result:

```text
[eggcracker] signature and release identity verified: v0.5.0 -> eb342808f56cdc213c0861726d5309a146965bef
{
  "primitive": "pidfd-stop+cgroup.kill",
  "profile": "content.gguf-llama",
  "result": "TERMINATED",
  "root_populated": 0,
  "surviving_pids": [],
  "trigger_to_empty_ms": 35.426071
}
[eggcracker] first-kill demonstration passed: the real workload was terminated and its canary survived
[eggcracker] clean removal passed
```

The complete terminal capture is in
[`campaign/first-kill.typescript`](campaign/first-kill.typescript) with its
[`campaign/first-kill.timing`](campaign/first-kill.timing). Replay it on Linux
with `scriptreplay --timing=campaign/first-kill.timing campaign/first-kill.typescript`.

### Check host compatibility

Use a disposable, supported native Ubuntu machine whose loss is acceptable.
The demonstration requires root, systemd, unified cgroup v2 with `cgroup.kill`,
pidfds, Python 3.11+, Git, GnuPG, CMake, a native C/C++ build toolchain and
network access. It changes root-owned system services, compiles the pinned
llama.cpp runner, downloads signed release assets, and—only after the explicit
flag—downloads the third-party Qwen model. Do not begin on a workstation,
shared host, production server, or machine carrying private data.

Clone public `main` and run the read-only preflight:

```sh
git clone https://github.com/noqt/Lumi-Eggcracker.git
cd Lumi-Eggcracker
sudo /usr/bin/python3 -I -S scripts/first_kill.py \
  --operator "$USER" \
  --preflight-only
```

The preflight is read-only: it checks the operator, supported host features,
empty installation targets, required tool availability, and that the local
annotated `v0.5.0` tag resolves to the qualified commit. It makes no network
request and creates no workspace, GPG home, build, installation or service.
It does not verify the release signature, downloaded assets, functional build,
installation or containment; those checks happen only in the full run.

### Probe the containment primitive

To test the kill mechanism without downloading a model, installing Eggcracker,
or exercising workload recognition, use a regular Git clone at a public source
commit on a disposable native Ubuntu 24.04 host. The probe requires its `.git`
identity, root, systemd, unified cgroup v2, `cgroup.kill`, pidfds and the
released system Python:

```sh
sudo /usr/bin/python3 -I -S scripts/containment_probe.py \
  --i-understand-this-kills-a-test-tree
```

The command makes no network request and installs nothing. It creates one
random transient systemd service, places exactly two harmless sleeping test
processes in a dedicated child cgroup, holds their pidfds, applies Eggcracker's
production pidfd-stop plus `cgroup.kill` path, proves that cgroup hierarchy is
empty, verifies an outside canary survived, and removes the transient objects.
The transient service is capped at exactly three tasks: one fixed owner and the
two-process target tree.
Every worker also has a 45-second runtime ceiling if the orchestrator is killed.
The probe prints only a bounded redacted receipt, including the Git commit and
an executed-source digest. Systemd journal metadata may persist until normal
log rotation.

This is a proof of the deterministic containment primitive, not a test of AI
workload recognition, the two supported profiles, installation, or universal
product effectiveness. A pass does not replace the full first-kill path.

#### Run it in a disposable GitHub-hosted fork

If you do not already have a disposable Ubuntu 24.04 host, fork this public
repository, enable Actions in the fork, and ensure the fork's default branch
contains `.github/workflows/containment-probe.yml`. Open **Actions →
Containment probe (manual disposable runner) → Run workflow**, select the
default branch, and explicitly tick the acknowledgement that the workflow
kills a bounded synthetic test tree.

The workflow refuses self-hosted runners, private repositories, non-default
branches, unsupported or containerised hosts, and machines with Eggcracker
install targets already present. It has read-only repository permission,
references no configured repository or user secrets, persists no checkout
credential, uploads no artifact, and prints only a validated bounded receipt,
result code, and workflow blob identity. GitHub still creates an ephemeral
read-only repository token for checkout. Checkout and public Actions metadata
use GitHub's network; the containment probe itself makes no network request.

GitHub-hosted runners are disposable, but the same narrow evidence boundary
still applies: this exercises only the synthetic pidfd-stop plus cgroup-v2 kill
primitive. It does not install Eggcracker, download a model, recognise a
workload, qualify another host, or establish product-wide effectiveness or
safety. A public non-NOQT run is evidence only after its source digest and
workflow blob match the reviewed upstream versions. Share a pass, safe refusal,
or reproducible friction report through the
[redacted result form](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=first_kill_result.yml).

After a passing preflight, run the full demonstration:

```sh
sudo /usr/bin/python3 -I -S scripts/first_kill.py \
  --operator "$USER" \
  --accept-third-party-downloads
```

The command checks host compatibility, downloads and verifies the signed
release assets, installs the root-controlled supervisor, downloads the pinned
demo model only after the explicit acceptance flag, launches the real model,
prints the kill receipt, and offers clean removal. Use `--remove` for a
non-interactive removal or `--keep` to inspect the installation after the
demonstration. Share a passing, refused, or confusing supported-path run through
the [redacted result form](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=first_kill_result.yml).
If the supported path exposes a reproducible non-security defect, open a
[reproducible bug](https://github.com/noqt/Lumi-Eggcracker/issues/new?template=bug_report.yml)
with a redacted support bundle; route security-sensitive findings through
[private vulnerability reporting](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new).

## What Eggcracker does

- observes local Linux processes with a root supervisor;
- recognises the two qualified content profiles in this release:
  `content.gguf-llama` and `content.safetensors-pytorch`;
- treats a complete match without an exact root approval as a kill condition;
- enforces first with pidfds and direct cgroup-v2 `cgroup.kill`;
- proves the owned cgroup and descendants are empty before writing the receipt;
- keeps an unrelated canary outside the owned cgroup alive;
- supports exact root approvals for protected launches, plus operator-triggered
  kills and status, list, doctor, detections and version queries.

The product is intentionally a kill switch, not an alerting dashboard. It
does not wait for an operator after an unapproved complete match.

## Current boundary

This public alpha is deliberately narrow. It supports native Linux with
systemd, unified cgroup v2, `cgroup.kill`, pidfds and Python 3.11+. The
qualified content profiles are CPU-first and require the published runtime
and artifact evidence. It does not claim universal AI recognition, inference
proof, container or remote-service coverage, network isolation, credential
isolation, behavioural detection, malware prevention or EDR replacement.

Ollama, vLLM, TGI, LocalAI, llamafile and agent launchers are not claimed as
covered profiles yet. That is a qualification boundary, not an alert-only
fallback.

## Support bundle

To make a report reproducible, create a local JSON bundle containing host
compatibility, supervisor health, workload counts and redacted detection
summaries:

```sh
sudo /usr/bin/python3 -I -S scripts/support_bundle.py \
  --output ./eggcracker-support.json
```

The command performs no network upload and does not copy raw receipts,
arguments, model paths, process IDs, credentials or model data. Review the
file before attaching it to an issue or discussion.

## Install and remove

The first-kill command is the recommended campaign path. For a controlled
installation, use the signed Linux bundle and its `SHA256SUMS`, then run the
bundled installer as root with a non-root operator. Remove every product-owned
unit, socket, account and state file with:

```sh
sudo /usr/bin/python3 -I -S scripts/uninstall.py
```

Read [SECURITY_MODEL.md](SECURITY_MODEL.md), [LIMITATIONS.md](LIMITATIONS.md),
and [QUALIFICATION.md](QUALIFICATION.md) before installing on a machine that
matters.

## Develop and contribute

The source is [Apache-2.0](LICENSE). Run the unit suite with Python 3.11+ and
use a disposable native Ubuntu host for cgroup and real-model integration
tests. The project keeps recognition separate from deterministic containment
so a new detector cannot silently weaken the kill proof. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change.

Questions and design-partner reports belong in
[Discussions](https://github.com/noqt/Lumi-Eggcracker/discussions); reproducible
non-security defects belong in [Issues](https://github.com/noqt/Lumi-Eggcracker/issues).
Report security vulnerabilities privately through the
[repository security channel](https://github.com/noqt/Lumi-Eggcracker/security/advisories/new).
Do not post credentials, private model files, raw process arguments or exploit
details publicly.
