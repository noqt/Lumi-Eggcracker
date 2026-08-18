# Eggcracker

**Deterministic containment for unapproved local AI workloads on Linux.**

Eggcracker is a privileged Linux enforcement daemon for a narrow,
published catalogue of locally observed AI workloads.

> Engineering preview: when a complete qualified match has no exact root approval,
> Eggcracker stops the process, captures the bounded related workload, and kills
> its root-owned cgroup. Validate this exact release in a disposable Ubuntu VM
> before installing it on a workstation or server.

There is no alert-only phase for an unapproved catalogue match. Containment begins with a pidfd stop signal; the explanation and receipt are written only after cgroup containment completes.

## What it does

- continuously scans host processes and performs a startup scan before accepting control commands;
- distributes bounded descriptor inspection across each complete live descriptor table and advances its root-owned scan generation across supervisor recovery, so watchdog restart cannot permanently return a high-FD workload to the same uninspected window;
- detects only the two publicly qualified content/runtime profiles below; unqualified name-only catalogue entries are not active in this release;
- recognises the qualified `content.gguf-llama` profile without depending on executable or model filename: a bounded plausible GGUF v2/v3 header plus the full-file SHA-256-authenticated, structurally loadable qualified llama.cpp runtime observed as the running executable or an executable mapping;
- recognises `content.safetensors-pytorch` when a structurally valid Safetensors artifact and full-file SHA-256-authenticated, structurally loadable, executable-mapped members of the exact pinned CPU PyTorch bridge-plus-ATen pair appear in one process or across a bounded related workload using the installed dedicated workload UID (a live direct parent/child or sibling relation, or one exact Eggcracker-owned workload cgroup); unrelated same-UID or common-init processes are not joined;
- lets root approve one exact qualified native llama invocation or one root-owned CPython interpreter plus an absolute regular script, workload UID and invocation, then lets the configured operator consume that approval only through the protected pre-exec `start` gate;
- automatically stops, captures and kills unapproved matches with `pidfd_send_signal` and cgroup-v2 `cgroup.kill`;
- preserves the existing protected `start` and operator `kill` workflow;
- records bounded post-containment receipts, status and detection summaries; if a
  post-containment detection receipt cannot be made durable, health becomes
  `UNSUPPORTED` and supervisor heartbeats stop until root repairs storage and
  restarts the service.

## What it does not do

Eggcracker does not identify every possible AI implementation. Content recognition currently excludes stripped or bespoke runtimes without the qualified markers, custom/encrypted model formats, containerised and remote API-only workloads. It does not guarantee detection of evidence that escaped before observation, an unobserved process, or a workload hidden behind a container or remote service. It does not claim general malware or intrusion detection. It does not use a behavioural model, isolate host networking, credentials or filesystems, or replace EDR.

A successful receipt proves the captured quarantine cgroup is empty. It does not prove that a process which escaped before detection never existed.

## Active contract-qualified profiles

The table states the exact profile contract implemented by this source. A 0.5.0
package is qualified only when its `release-manifest.json`, installed policy,
receipts, source archive and portable evidence archive all name the same exact
source commit and the gates in [QUALIFICATION.md](QUALIFICATION.md) pass on the
target host. Do not transfer a qualification result between commits or hosts.

| Profile | Exact qualification | Active in 0.5.0 |
| --- | --- | --- |
| `content.gguf-llama` | Renamed full-file-pinned llama.cpp runner, extensionless GGUF path, bounded GGUF header, executable ELF identity | Yes |
| `content.safetensors-pytorch` | Full-file-pinned CPU PyTorch bridge-plus-ATen pair, valid contiguous Safetensors layout, real model smoke and ATen-only negative control | Yes |
| Ollama, vLLM, TGI, LocalAI, llamafile and agent CLIs | Invocation-specific fixtures and launcher identity still require qualification | No |

## Requirements

- native Linux with systemd and unified cgroup v2;
- `cgroup.kill`, delegated child cgroups, `pidfd_open` and `pidfd_send_signal`;
- root for install/uninstall and one non-root local operator;
- Python 3.11 or newer.

## Quick start

0.5.0 is published as a Linux engineering preview. The historical `v0.4.0`
tag is unchanged. The source tag and downloadable assets are bound to the
qualified candidate commit `eb342808f56cdc213c0861726d5309a146965bef`.

Clone the exact release tag and verify the durable release asset before
installing it in a disposable Ubuntu 24.04 VM:

```sh
git clone --branch v0.5.0 --depth 1 https://github.com/noqt/Lumi-Eggcracker.git
cd Lumi-Eggcracker
test "$(git rev-parse HEAD)" = "eb342808f56cdc213c0861726d5309a146965bef"
mkdir -p /tmp/eggcracker-0.5.0
cd /tmp/eggcracker-0.5.0
curl -fsSLO https://github.com/noqt/Lumi-Eggcracker/releases/download/v0.5.0/lumi-eggcracker-0.5.0-linux.zip
unzip -q lumi-eggcracker-0.5.0-linux.zip
cd lumi-eggcracker-0.5.0
curl -fsSLO https://github.com/noqt/Lumi-Eggcracker/releases/download/v0.5.0/SHA256SUMS
sha256sum -c SHA256SUMS
python3 scripts/verify_release.py \
  --artifact lumi-eggcracker-0.5.0.pyz \
  --source-archive lumi-eggcracker-0.5.0-source.zip \
  --release-bundle ../lumi-eggcracker-0.5.0-linux.zip
```

After validation, extract `lumi-eggcracker-0.5.0-linux.zip`, compare the
manifest commit to the reviewed source, and install through the isolated system
Python with the manifest-bound artifact digest:

```sh
cd lumi-eggcracker-0.5.0
artifact_sha=$(python3 -c 'import json; print(json.load(open("release-manifest.json"))["sha256"])')
sudo /usr/bin/python3 -I -S scripts/install.py \
  --operator "$USER" --artifact "$PWD/lumi-eggcracker-0.5.0.pyz" \
  --expected-sha256 "$artifact_sha"
eggcracker doctor
eggcracker approvals
```

An unapproved complete qualified content profile is killed automatically when it starts; Eggcracker does not pause for confirmation. To allow a known invocation, root must approve it and the operator must launch that exact command through `eggcracker start`. The approval stores hashes, not its raw arguments. Approval is deliberately limited to the qualified native llama runtime and CPython's single absolute-script form; Python `-c`, `-m`, relative paths, directories, symlinks and unsupported launchers are rejected. An approval by itself never exempts a process launched directly or by another tool:

```sh
sudo eggcracker approve --name local-qwen --uid "$(id -u lumi-eggcracker-workload)" -- \
  /opt/llama.cpp/llama-cli -m /opt/models/qwen.gguf -p "Hello" -n 256
eggcracker start --name local-qwen-run --max-pids 64 \
  --max-memory-mib 4096 --cpu-quota-percent 400 -- \
  /opt/llama.cpp/llama-cli -m /opt/models/qwen.gguf -p "Hello" -n 256
```

Inspect autonomous containment summaries with:

```sh
eggcracker detections
```

Remove an approval for future protected launches with `sudo eggcracker revoke --name local-qwen`. Revocation does not kill a workload that was already admitted and running. Approval is bound before exec to the exact Eggcracker-owned PID/start-time, executable identity and cgroup; mutable post-exec `/proc/<pid>/cmdline` data can never grant approval. For CPython, the approved script identity and digest are also bound, and the supervisor copies the same validated file descriptor into a root-owned per-run stage before releasing the gate. Script drift aborts `start`. Descendants and siblings do not inherit approval.

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

The smoke launches the model directly first and verifies that Eggcracker kills the unapproved invocation. It then proves that the same exact invocation survives only after root approval and protected operator launch, before revoking the approval and proving a direct relaunch is killed again. The companion `smoke_content_ai.py` uses a renamed runner, unfamiliar wrapper and extensionless GGUF path to exercise the content profile.

To remove Eggcracker completely:

```sh
sudo /usr/bin/python3 -I -S scripts/uninstall.py
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

The 0.5.0 closure additionally runs the bundled `run_p0_native.py` workload
campaign, `run_installer_p0.py` privileged-boundary campaign, deterministic
enforcement/receipt fault injection, the frozen 41-case Daybreak replay, and a
fresh no-history Daybreak assessment. Package the resulting evidence with
`package_evidence.py`; its tar archive preserves POSIX symlink and hardlink
semantics and is verified without extraction on a second host.

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
