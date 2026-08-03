# Lumi Nutcracker

**The local Linux kill switch for AI and agent workloads.**

Lumi Nutcracker launches a command you explicitly select under a dedicated no-login identity and inside a root-controlled cgroup-v2 boundary. The operator can terminate the complete workload tree, or configure a PID ceiling that triggers automatic containment when the workload starts creating too many processes.

> Lumi Nutcracker launches an explicitly selected AI or agent workload inside a root-controlled Linux cgroup and terminates the complete workload tree on operator command or when its configured PID-runaway tripwire fires.

This is a Linux engineering preview. Read [Limitations](LIMITATIONS.md) before relying on it.

## What it does

- launches one selected command in a Nutcracker-owned cgroup;
- runs that command as a dedicated unprivileged, no-login user;
- kills the complete owned cgroup with the kernel's `cgroup.kill` primitive;
- verifies that the cgroup and all descendants are empty before issuing a success receipt;
- automatically contains workloads that hit their configured PID limit;
- fails closed for active workloads when the supervisor restarts.

## What it does not do

Lumi Nutcracker does not discover AI processes, attach to existing processes, identify malware, detect unknown intrusions, isolate networks or credentials, prevent general malware, or replace endpoint security.

## Requirements

- Ubuntu 24.04 or a comparable Linux distribution using systemd;
- unified cgroup v2 with `cgroup.kill` and the PID controller;
- Python 3.11 or later;
- root access for installation;
- a non-root local operator account.

## Install a GitHub release

Download and extract `lumi-nutcracker-0.1.0-linux.zip`, then run:

```bash
cd lumi-nutcracker-0.1.0
sha256sum -c SHA256SUMS
sudo python3 scripts/install.py \
  --operator "$(id -un)" \
  --artifact ./lumi-nutcracker-0.1.0.pyz
nutcracker doctor
```

The installer creates the dedicated `lumi-nutcracker-workload` identity dynamically. It does not assume a particular operator UID.

## Build from source

```bash
python3 scripts/build_release.py --output dist
python3 scripts/verify_release.py \
  --artifact dist/lumi-nutcracker-0.1.0.pyz \
  --source-archive dist/lumi-nutcracker-0.1.0-source.zip \
  --release-bundle dist/lumi-nutcracker-0.1.0-linux.zip
sudo python3 scripts/install.py \
  --operator "$(id -un)" \
  --artifact dist/lumi-nutcracker-0.1.0.pyz
```

Release builds refuse a dirty Git tree so the embedded source commit remains meaningful.

## Quick start

```bash
nutcracker start --name local-agent --max-pids 64 -- /usr/bin/python3 agent.py
nutcracker status --name local-agent
nutcracker kill --name local-agent --receipt ./kill-receipt.json
```

The receipt is written only after direct cgroup kill and empty-hierarchy verification succeed.

## Commands

```text
nutcracker start --name NAME --max-pids LIMIT -- COMMAND [ARGS...]
nutcracker kill --name NAME --receipt FILE
nutcracker status --name NAME
nutcracker list
nutcracker doctor
nutcracker version
```

## Local AI smoke demonstration

With a locally installed `llama-cli` and a GGUF model readable by the workload identity:

```bash
python3 scripts/smoke_local_ai.py \
  --llama-cli /opt/llama/llama-cli \
  --model /opt/models/local.gguf \
  --output ai-smoke.json
```

The script waits for visible model output, kills that selected inference workload through Nutcracker, and verifies that an unrelated canary survives.

## Uninstall

Terminate active protected workloads first, then run from the extracted release or source tree:

```bash
sudo python3 scripts/uninstall.py
sudo python3 scripts/verify_uninstalled.py
```

## Qualification

The 0.1.0 native Ubuntu qualification completed:

- 100/100 complete fork-race workload-tree kills;
- 100/100 unrelated-canary survivals;
- zero successful control-socket accesses from the workload identity;
- zero successful replacement launches;
- automatic PID-tripwire containment;
- 50/50 bounded benign completions without a false kill;
- 20/20 fail-closed supervisor restart recoveries;
- measured p95 trigger-to-empty latency below 500 ms;
- a real local llama.cpp workload smoke test;
- clean installation and complete uninstallation;
- no firewall-rule objects or dependencies.

See [Security](SECURITY.md), [Limitations](LIMITATIONS.md), and [Release notes](RELEASE_NOTES.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
