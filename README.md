# Lumi Eggcracker

**Deterministic containment for unapproved local AI workloads on Linux.**

Lumi Eggcracker is a privileged Linux enforcement daemon for a narrow,
published catalogue of locally observed AI workloads.

> Engineering preview: when a complete qualified match has no exact root approval,
> Eggcracker stops the process, captures the bounded related workload, and kills
> its root-owned cgroup. Validate this exact release in a disposable Ubuntu VM
> before installing it on a workstation or server.

There is no alert-only phase for an unapproved catalogue match. Containment begins with a pidfd stop signal; the explanation and receipt are written only after cgroup containment completes.

## What it does

- continuously scans host processes and performs a startup scan before accepting control commands;
- detects only the two contract-qualified content/runtime profiles below; unqualified name-only catalogue entries are not active in this release;
- recognises the qualified `content.gguf-llama` profile without depending on executable or model filename: a bounded plausible GGUF v2/v3 header and either two llama.cpp/GGML ELF runtime markers or the exact pinned llama.cpp launcher build ID are both required;
- recognises `content.safetensors-pytorch` when a structurally valid Safetensors artifact and the exact pinned CPU PyTorch bridge-plus-ATen ELF build-ID pair appear in one process or across a bounded related workload using the installed dedicated workload UID (a live direct parent/child or sibling relation, or one exact Eggcracker-owned workload cgroup); unrelated same-UID or common-init processes are not joined;
- lets the configured operator approve one exact executable, UID and invocation before it is run;
- automatically stops, captures and kills unapproved matches with `pidfd_send_signal` and cgroup-v2 `cgroup.kill`;
- preserves the existing protected `start` and operator `kill` workflow;
- records bounded post-containment receipts, status and detection summaries.

## What it does not do

Eggcracker does not identify every possible AI implementation. Content recognition currently excludes stripped or bespoke runtimes without the qualified markers, custom/encrypted model formats, containerised and remote API-only workloads. It does not guarantee detection of evidence that escaped before observation, an unobserved process, or a workload hidden behind a container or remote service. It does not claim general malware or intrusion detection. It does not use a behavioural model, isolate host networking, credentials or filesystems, or replace EDR.

A successful receipt proves the captured quarantine cgroup is empty. It does not prove that a process which escaped before detection never existed.

## Active contract-qualified profiles

The table states the exact profile contract implemented by this source. Project
records report that these profiles passed the native qualification gates for
commit `418f877f0d450aeb26d4a1233257746808c490e5` on one WSL2 Ubuntu host.
The corresponding checksum-bound native evidence pack is not retained in this
repository or a public GitHub Release, so that result is not independently
re-verifiable from the durable public surface. Run the qualification in
[QUALIFICATION.md](QUALIFICATION.md) on the exact commit and target host before
relying on it.

| Profile | Exact qualification | Active in 0.4.0 |
| --- | --- | --- |
| `content.gguf-llama` | Renamed llama.cpp runner, extensionless GGUF path, bounded GGUF header, qualified ELF identity | Yes |
| `content.safetensors-pytorch` | Pinned CPU PyTorch bridge-plus-ATen pair, valid contiguous Safetensors layout, real model smoke and ATen-only negative control | Yes |
| Ollama, vLLM, TGI, LocalAI, llamafile and agent CLIs | Invocation-specific fixtures and launcher identity still require qualification | No |

## Requirements

- native Linux with systemd and unified cgroup v2;
- `cgroup.kill`, delegated child cgroups, `pidfd_open` and `pidfd_send_signal`;
- root for install/uninstall and one non-root local operator;
- Python 3.11 or newer.

## Quick start

There is currently no v0.4.0 GitHub Release or durable anonymous download for
the Linux bundle. To evaluate the tagged source, build it locally in a disposable
Ubuntu VM:

```sh
git clone --branch v0.4.0 --depth 1 https://github.com/noqt/Lumi-Eggcracker.git
cd Lumi-Eggcracker
test "$(git rev-parse HEAD)" = "418f877f0d450aeb26d4a1233257746808c490e5"
python3 scripts/build_release.py --output dist/local
python3 scripts/verify_release.py \
  --artifact dist/local/lumi-eggcracker-0.4.0.pyz \
  --source-archive dist/local/lumi-eggcracker-0.4.0-source.zip \
  --release-bundle dist/local/lumi-eggcracker-0.4.0-linux.zip
```

Alternatively, a signed-in GitHub user may download the authenticated
`lumi-eggcracker-v0.4.0` artifact from the
[successful `v0.4.0` tag workflow](https://github.com/noqt/Lumi-Eggcracker/actions/runs/31472099403)
while GitHub retains it, then perform the same source-commit and
`verify_release.py` checks. A CI artifact is not a durable anonymous Release
channel. After validation, extract `lumi-eggcracker-0.4.0-linux.zip` and run as
root:

```sh
cd lumi-eggcracker-0.4.0
sudo python3 scripts/install.py --operator "$USER" --artifact ./lumi-eggcracker-0.4.0.pyz
eggcracker doctor
eggcracker approvals
```

An unapproved complete qualified content profile is killed automatically when it starts; Eggcracker does not pause for confirmation. To allow a known invocation, approve it before launch. The approval stores hashes, not its raw arguments:

```sh
sudo eggcracker approve --name local-qwen --uid "$(id -u)" -- \
  /opt/llama.cpp/llama-cli -m /opt/models/qwen.gguf -p "Hello" -n 256
```

Inspect autonomous containment summaries with:

```sh
eggcracker detections
```

Remove an approval for future launches with `sudo eggcracker revoke --name local-qwen`. Revocation does not kill a workload that was already approved and running.

The selected-workload command remains available for controlled tests and explicit workloads:

```sh
eggcracker start --name demo --max-pids 8 --max-memory-mib 256 --cpu-quota-percent 100 -- /bin/sleep 60
eggcracker kill --name demo --receipt ./demo-receipt.json
```

## Real local AI smoke

The release bundle can prepare a pinned external llama.cpp runner and Qwen GGUF model in a separate workspace. The assets are downloaded only after explicit acceptance, verified by commit/revision and SHA-256, and never included in the release archive.

```sh
sudo python3 scripts/prepare_ai_smoke.py --workspace /opt/lumi-eggcracker-ai-smoke --accept-third-party-downloads
sudo python3 scripts/prepare_safetensors_smoke.py --workspace /opt/lumi-eggcracker-safetensors-smoke --accept-third-party-downloads
sudo python3 scripts/smoke_autonomous_ai.py \
  --assets-manifest /opt/lumi-eggcracker-ai-smoke/ai-smoke-assets.json \
  --user "$USER" --repetitions 5 --output ./autonomous-ai-smoke.json
```

The smoke launches the model directly, outside `eggcracker start`, verifies that Eggcracker kills the unapproved invocation, then proves that the same exact invocation survives only when approved. The companion `smoke_content_ai.py` uses a renamed runner, unfamiliar wrapper and extensionless GGUF path to exercise the content profile.

To remove Eggcracker completely:

```sh
sudo python3 scripts/uninstall.py
```

## Local validation

Run a complete local qualification after installation. It uses the pinned external AI assets, takes several minutes, and writes a self-contained evidence directory; it does not publish anything.

```sh
sudo python3 scripts/self_validate.py \
  --operator "$USER" \
  --assets-manifest /opt/lumi-eggcracker-ai-smoke/ai-smoke-assets.json \
  --safetensors-assets-manifest /opt/lumi-eggcracker-safetensors-smoke/safetensors-ai-smoke-assets.json \
  --evidence-dir /opt/lumi-eggcracker-evidence
```

It runs the real-AI approval smoke, Safetensors approval smoke, ATen-only negative control, renamed content matrix, benign model-handling matrix, descendants/startup/restart checks, autonomous regression, selected-workload security regression, and the host-overhead benchmark. The resulting `overhead-benchmark.json` is included in the checksum-verified evidence pack.

Measure host cost separately in the disposable qualification VM:

```sh
sudo python3 scripts/benchmark_overhead.py \
  --policy /etc/lumi-eggcracker/policy.json \
  --output ./overhead-benchmark.json
```

This records scan duration, CPU time, read counters, resident memory and
context switches at approximately 50, 200 and 1,000 host processes.

On the qualification WSL2 Ubuntu environment, warmed-cache scan p95 was
approximately 251 ms with 50 synthetic children, 650 ms with 200, and 2.9
seconds with 1,000. Content inspection occurs on alternating scans, so high
process density can create multi-second observation delay. Results are
host-specific; run the bundled benchmark before deployment.

See [SECURITY_MODEL.md](SECURITY_MODEL.md), [LIMITATIONS.md](LIMITATIONS.md), and [QUALIFICATION.md](QUALIFICATION.md) before using this engineering preview.
