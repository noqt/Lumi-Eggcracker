# Lumi Eggcracker

[![CI](https://github.com/noqt/Lumi-Eggcracker/actions/workflows/ci.yml/badge.svg)](https://github.com/noqt/Lumi-Eggcracker/actions/workflows/ci.yml)

[v0.5.0 Release](https://github.com/noqt/Lumi-Eggcracker/releases/tag/v0.5.0)
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

### Prerequisites and safety

Use a disposable, supported native Ubuntu machine whose loss is acceptable.
The demonstration requires root, systemd, unified cgroup v2 with `cgroup.kill`,
pidfds, Python 3.11+, Git, GnuPG, CMake, a native C/C++ build toolchain and
network access. It changes root-owned system services, compiles the pinned
llama.cpp runner, downloads signed release assets, and—only after the explicit
flag—downloads the third-party Qwen model. Do not begin on a workstation,
shared host, production server, or machine carrying private data.

Clone public `main` and run:

```sh
git clone https://github.com/noqt/Lumi-Eggcracker.git
cd Lumi-Eggcracker
sudo /usr/bin/python3 -I -S scripts/first_kill.py \
  --operator "$USER" \
  --accept-third-party-downloads
```

The command checks host compatibility, downloads and verifies the signed
release assets, installs the root-controlled supervisor, downloads the pinned
demo model only after the explicit acceptance flag, launches the real model,
prints the kill receipt, and offers clean removal. Use `--remove` for a
non-interactive removal or `--keep` to inspect the installation after the
demonstration. If the supported path fails, open a
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
