# Lumi Eggcracker

Lumi Eggcracker is a local Linux kill switch for unapproved, supported AI and agent runtimes.

> Eggcracker monitors a Linux host for processes matching its published AI-runtime fingerprints. When a matching process has no exact operator approval, it automatically stops the process, captures its discovered process tree in a root-owned cgroup, and kills that cgroup.

There is no alert-only phase for an unapproved catalogue match. Containment begins with a pidfd stop signal; the explanation and receipt are written only after cgroup containment completes.

## What it does

- continuously scans host processes and performs a startup scan before accepting control commands;
- detects published local-runtime profiles including llama.cpp, Ollama, vLLM, Text Generation Inference, LocalAI, llamafile and selected agent CLIs;
- lets the configured operator approve one exact executable, UID and invocation before it is run;
- automatically stops, captures and kills unapproved matches with `pidfd_send_signal` and cgroup-v2 `cgroup.kill`;
- preserves the existing protected `start` and operator `kill` workflow;
- records bounded post-containment receipts, status and detection summaries.

## What it does not do

Eggcracker does not identify every possible AI implementation. It does not claim to detect custom, obfuscated, containerised or remote AI workloads, general malware or intrusions. It does not use a behavioural model, isolate host networking, credentials or filesystems, or replace EDR.

A successful receipt proves the captured quarantine cgroup is empty. It does not prove that a process which escaped before detection never existed.

## Requirements

- native Linux with systemd and unified cgroup v2;
- `cgroup.kill`, delegated child cgroups, `pidfd_open` and `pidfd_send_signal`;
- root for install/uninstall and one non-root local operator;
- Python 3.11 or newer.

## Quick start

Download and extract `lumi-eggcracker-0.2.0-linux.zip`, then run as root:

```sh
cd lumi-eggcracker-0.2.0
sudo python3 scripts/install.py --operator "$USER" --artifact ./lumi-eggcracker-0.2.0.pyz
eggcracker doctor
eggcracker approvals
```

An unapproved supported runtime is killed automatically when it starts. To allow a known invocation, approve it before launch. The approval stores hashes, not its raw arguments:

```sh
eggcracker approve --name local-qwen --uid "$(id -u)" -- \
  /opt/llama.cpp/llama-cli -m /opt/models/qwen.gguf -p "Hello" -n 256
```

Inspect autonomous containment summaries with:

```sh
eggcracker detections
```

Remove an approval for future launches with `eggcracker revoke --name local-qwen`. Revocation does not kill a workload that was already approved and running.

The selected-workload command remains available for controlled tests and explicit workloads:

```sh
eggcracker start --name demo --max-pids 8 -- /bin/sleep 60
eggcracker kill --name demo --receipt ./demo-receipt.json
```

## Real local AI smoke

The release bundle can prepare a pinned external llama.cpp runner and Qwen GGUF model in a separate workspace. The assets are downloaded only after explicit acceptance, verified by commit/revision and SHA-256, and never included in the release archive.

```sh
sudo python3 scripts/prepare_ai_smoke.py --workspace /opt/lumi-eggcracker-ai-smoke --accept-third-party-downloads
sudo python3 scripts/smoke_autonomous_ai.py \
  --assets-manifest /opt/lumi-eggcracker-ai-smoke/ai-smoke-assets.json \
  --user "$USER" --repetitions 5 --output ./autonomous-ai-smoke.json
```

The smoke launches the model directly, outside `eggcracker start`, verifies that Eggcracker kills the unapproved invocation, then proves that the same exact invocation survives only when approved.

To remove Eggcracker completely:

```sh
sudo python3 scripts/uninstall.py
```

See [SECURITY_MODEL.md](SECURITY_MODEL.md), [LIMITATIONS.md](LIMITATIONS.md), and [QUALIFICATION.md](QUALIFICATION.md) before using this engineering preview.
