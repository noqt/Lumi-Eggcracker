# Lumi Eggcracker

## The kill switch outside the sandbox

Eggcracker is a Linux guard for local AI. It watches for a complete,
unapproved AI workload, stops it automatically, kills its whole cgroup-v2
process tree, and leaves a bounded receipt proving the tree is empty.

> **Seeking three design partners**
>
> We are looking for three people or small teams running local models who will
> try Eggcracker on a disposable Ubuntu machine, tell us where it helps, and
> show us what it misses. There is no telemetry, no paid plan, and no sales
> call. Open a [design-partner discussion](https://github.com/noqt/Lumi-Eggcracker/discussions)
> with your Linux version and the local-AI workflow you want to protect.

### See the first kill

The public demonstration launches a real Qwen model through a pinned
llama.cpp runner, shows it running, lets Eggcracker recognise the unapproved
workload, and prints the post-kill receipt. It also checks that an unrelated
canary survives.

The 62-second terminal capture is in [`campaign/first-kill.typescript`](campaign/first-kill.typescript)
with [`campaign/first-kill.timing`](campaign/first-kill.timing). Replay it on
Linux with `scriptreplay --timing=campaign/first-kill.timing campaign/first-kill.typescript`.

Run it on a disposable native Ubuntu machine:

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
demonstration.

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

If a design partner needs help, create a local JSON bundle containing host
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

## Development

The source is Apache-2.0. Run the unit suite with Python 3.11+ and use a
native Ubuntu host for cgroup and real-model integration tests. The project
keeps recognition separate from deterministic containment so a new detector
cannot silently weaken the kill proof.

Questions, reproductions and design-partner reports belong in
[Discussions](https://github.com/noqt/Lumi-Eggcracker/discussions). Report
security vulnerabilities privately through the repository security channel;
do not post credentials, private model files or exploit details in a public
issue.
