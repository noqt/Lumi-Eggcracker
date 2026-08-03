# Lumi Eggcracker

Lumi Eggcracker is a small, local Linux kill switch for an AI or agent workload you explicitly select.

> Lumi Eggcracker launches one explicitly selected AI or agent workload inside a root-controlled Linux cgroup and terminates the complete workload tree on operator command or when its configured PID-runaway tripwire fires.

It uses one root-owned supervisor, direct cgroup-v2 `cgroup.kill`, and an exact empty-cgroup proof. The workload runs under a dedicated no-login account that cannot access the control socket.

## It does

- launch one selected command in an exact owned cgroup;
- kill its complete cgroup tree on `eggcracker kill`;
- kill it automatically when its PID limit trips;
- write a post-containment receipt only after an exact empty proof;
- provide `start`, `kill`, `status`, `list`, `doctor`, and `version`.

## It does not do

It does not identify AI automatically, find unknown processes, detect intrusions or malware, isolate networks or credentials, prevent general malware, replace EDR, or attach an existing process to its boundary.

## Requirements

- Linux with systemd and unified cgroup v2;
- `pids` controller and `cgroup.kill` on transient service cgroups;
- root for install/uninstall; a non-root local operator account;
- Python 3.11 or newer.

## Quick start

Download and extract `lumi-eggcracker-0.1.2-linux.zip`, then run as root:

```sh
cd lumi-eggcracker-0.1.2
sudo python3 scripts/install.py --operator "$USER" --artifact ./lumi-eggcracker-0.1.2.pyz
eggcracker doctor
eggcracker start --name demo --max-pids 8 -- /bin/sleep 60
eggcracker kill --name demo --receipt ./demo-receipt.json
sudo python3 scripts/uninstall.py
```

The selected command is launched through a systemd transient unit. It does not attach an interactive terminal, preserve your current working directory, or stream output to the CLI in this preview. Use absolute paths and redirect output in a wrapper script when needed.

## Real local AI smoke

The release bundle can prepare its pinned, external llama.cpp runner and Qwen GGUF model in a separate workspace. The assets are downloaded only after explicit acceptance, are verified by commit/revision and SHA-256, and are never included in the release archive. The smoke waits for visible model output, kills the explicitly selected inference workload, and verifies an unrelated canary survives:

```sh
sudo python3 scripts/prepare_ai_smoke.py --workspace /opt/lumi-eggcracker-ai-smoke --accept-third-party-downloads
sudo python3 scripts/smoke_local_ai.py --assets-manifest /opt/lumi-eggcracker-ai-smoke/ai-smoke-assets.json --repetitions 5 --output ./ai-smoke.json
```

The pinned runner is llama.cpp `b10240` (`0b14b87d7c20cb753b94b96854dd7b45306fc696`, MIT). The pinned model is Qwen2.5-0.5B-Instruct Q4_K_M (`9217f5db79a29953eb74d5343926648285ec7e67`, Apache-2.0). You may instead supply a local runner and model with `--llama-cli` and `--model`; that path is recorded as operator-supplied provenance.

See [SECURITY_MODEL.md](SECURITY_MODEL.md), [LIMITATIONS.md](LIMITATIONS.md), and [QUALIFICATION.md](QUALIFICATION.md) before using the preview.
