# Lumi Eggcracker 1.0.1 — release candidate repair

This local 1.0.1 candidate repairs the qualified root-supervisor product after
the 0.7 runtime-topology, 0.8 execution-boundary, 0.8.1 deployment-hardening
and 0.9 bounded-local-lockdown milestones. It carries four exact native CPU
AI profiles, direct cgroup-v2 containment, offline selected-workload and
execution boundaries, watchdog recovery, and root-controlled exact relaunch
lockdown.

Root approvals now bind the selected PID, memory and CPU limits as part of the
exact launch specification. Changing one of those limits cannot inherit an
approval; older approval records remain administratively visible and revocable
but fail closed until root recreates them with the intended limits.

The public first-kill helper defaults to `v1.0.1`. The packaged support helper
delegates to the installed root-owned zipapp, so the documented command works
from the verified Linux release bundle without importing a mutable checkout.
The bootstrap now also requires a detached `SHA256SUMS.asc` signature from the
pinned release key and rejects duplicate, link, special, oversized and unsafe
ZIP members. A replaced release bundle plus self-recomputed unsigned checksums
can therefore no longer reach root execution.

The candidate is not tagged, signed or published. Its release decision is
bound to the exact commit, artifact hashes, disposable Ubuntu qualification
evidence and the internal black-box/source-informed campaign. Unsupported
formats, runtimes, containers, remote workloads, behavioural recognition,
host-wide isolation and remote retaliation remain outside the claim.

# Lumi Eggcracker 0.9.0 — bounded local lockdown

0.9.0 adds one post-containment response: after a successful unapproved-AI,
offline-boundary or execution-boundary kill, Eggcracker records a bounded
root-owned incident, revokes the exact affected approval when one exists, and
suppresses an exact protected relaunch until root clears the local lockdown and
creates a fresh approval. A bounded recurrence sweep reuses the existing
detector and cgroup.kill path; unrelated and partial matches remain outside
the response scope.

The original empty-cgroup receipt is always written before incident state,
approval revocation or recurrence work. Query and operator identities can only
see bounded incident summaries; show, acknowledge and clear require the
root-admin socket. Clearing an incident never restores its revoked approval.

This release does not add remote retaliation, hack-back behaviour, arbitrary
response hooks, host-wide UID/name quarantine, automatic expiry, a behavioural
model, attribution or universal AI recognition.

# Lumi Eggcracker 0.7.0 — native topology coverage

0.7.0 qualified two additional exact native CPU topology profiles:
`content.gguf-ollama` and `content.safetensors-vllm`. They require the pinned
launcher/worker identities, structurally validated model content and a bounded
relationship; process names, ports, package names and partial evidence never
trigger a kill. GPU, container, remote and unqualified runtime variants remain
outside the claim.

# Lumi Eggcracker 0.6.0 — The selected-workload offline kill boundary

0.6.0 extends the qualified kill switch with one deliberately narrow boundary:
every workload launched with `eggcracker start` runs in a transient,
run-owned Linux network namespace. Loopback remains available for local worker
communication. Every non-loopback IPv4 and IPv6 output packet is denied by a
namespace-local `nftables` rule and counted; the first authenticated counter
increase automatically kills the complete owned workload tree with direct
cgroup-v2 `cgroup.kill`, proves exact emptiness, and writes one bounded breach
receipt.

The host network namespace is not changed. The sink namespace has no uplink,
the workload identity has no network-admin/raw-packet/netlink authority, and
no host-wide firewall object is installed. The selected workload policy has no
networked or alert-only mode in this release. The primitive qualification
harness must pass on a disposable native Ubuntu VM before this version can be
called a release candidate; unit mocks or WSL results do not substitute for
that gate.

0.6.0 does not claim general host network isolation, universal AI recognition,
inference proof, remote/container coverage, credential or filesystem isolation,
malware prevention or EDR replacement. The release continues to recognise the
two exact CPU-first AI content profiles from 0.5.0, including unapproved
Safetensors/PyTorch converters and inspectors without requiring proof of a
forward pass.

## 0.5.0 — Historical release

0.5.0 is a public-alpha release line and does not move or replace
the historical `v0.4.0` tag. It closes the independent release-review items:
the Linux artifact-cache regression, exact artifact/source/manifest identity,
root-isolated installer execution, descriptor-bound installation, portable
POSIX evidence archives, Python 3.11/3.12/3.13 CI, ordinary Ubuntu 24.04 native
qualification, five Priority-0 adversarial campaigns, the frozen 41-case
Daybreak replay and a fresh no-history Daybreak assessment.

The release retains aggressive `content.safetensors-pytorch` recognition on the qualified control plane. A valid bounded, contiguous Safetensors layout and the exact full-file SHA-256-pinned CPU PyTorch bridge-plus-ATen ELF pair may appear in one process or across a bounded related workload using the installed dedicated workload UID: a live direct parent/child or sibling relation, or one exact Eggcracker-owned workload cgroup. Unrelated same-UID or common-init processes are not joined. There is no guarantee for evidence that escaped before observation, unobserved processes, or containerised or remote workloads. An unapproved complete match is automatically contained once a complete match is observed, without requiring proof of a forward pass. The three-socket approval boundaries, watchdog and direct cgroup.kill containment remain qualified release properties.

On the qualification WSL2 Ubuntu environment, warmed-cache scan p95 was approximately 251 ms with 50 synthetic children, 650 ms with 200, and 2.9 seconds with 1,000. Content inspection occurs on alternating scans, so high process density can create multi-second observation delay. Results are host-specific; run the bundled benchmark before deployment.

The active catalogue contains only the two content profiles qualified by native fixtures. Name-only entries for vLLM, Ollama, TGI, LocalAI, llamafile and agent CLIs are withheld until their normal launcher invocations and approval identities are tested. Executable identity is hashed through the live `/proc/<pid>/exe` descriptor, heartbeat emission requires recent scan completion, release verification derives the public version from release metadata, and uninstall refuses before stopping protection when owned cgroups are populated.

The release also applies bounded memory, CPU, I/O, task and descriptor limits to the supervisor, watchdog and selected workloads. Complete unapproved matches continue to use pidfd stop/capture and direct `cgroup.kill` as the authoritative complete-tree kill primitive.

Adversarial repair qualification binds approval consumption to the exact protected pre-exec `start` identity rather than mutable post-exec procfs arguments. Direct launches can no longer borrow a root approval, and descendants or siblings do not inherit one. Related-process detection now separates the minimal evidence witness from enforcement scope: the full bounded evidence component and connector parent are captured so a successful containment receipt cannot describe one killed pair while another complete sibling pair remains. Clean uninstall also empties only the two exact stopped Eggcracker service cgroups before requiring systemd to collect the units.

The final approval repair also prevents a non-root operator from replacing an argv-referenced interpreter script after root approval. CPython approval is limited to one absolute regular script; that script is bound by identity and digest and copied from the same validated descriptor into an immutable root-owned per-run stage before gate release. Mutable, relative, module, command, directory and unsupported interpreter forms fail closed.

The final containment-scope repair groups independently complete related siblings into one enforcement scope before the first receipt, including their live same-UID connector parent. Deleted WSL2 DrvFS model descriptors are inspected through an exact PID/start-time-bound `pidfd_getfd` duplicate when the ordinary procfs magic link cannot be reopened. Runtime recovery through a retained descriptor additionally requires an exact match to an executable mapping's kernel mount/inode identity. Arbitrary open ELF descriptors, read-only data mappings, ELF metadata without an executable load segment, and attacker-forged build IDs or marker symbols cannot become destructive runtime evidence: the complete runtime file must match the qualified release SHA-256 pin.

The pressure-recovery repair replaces contiguous descriptor prefixes with bounded stripes over the complete current descriptor and mapping tables. The root-owned stripe generation advances across supervisor/watchdog recovery, preventing repeated recovery from resetting a still-live high-FD supported workload to the same uninspected window.

Fresh independent-review repairs make post-containment detection-receipt persistence part of supervisor health: a failed durable write now latches `doctor` to `UNSUPPORTED` and stops watchdog heartbeats until root repair and restart. Control JSON integers are explicitly bounded and parser recursion/value errors are converted to bounded protocol errors instead of escaping the connection handler. Executable runtime mapping discovery now considers every mapping within the existing 8 MiB procfs byte ceiling rather than silently truncating after 4,096 lines.

A second fresh-review repair extends cgroup-only evidence correlation to the exact active `lumi-eggcracker-workload-<run-id>.service` selected unit. Split model/runtime holders remain bounded to that root-recorded unit identity even after reparenting; similarly named inactive or arbitrary systemd cgroups are not joined.

Installation now waits for every control socket to reach its final owner and mode. This closes a startup race where socket path creation could briefly precede the supervisor's metadata update.

The mandatory synchronous startup scan is now accounted as the first healthy completed scan and heartbeated as soon as the discovery worker is live. Repeated deliberate supervisor restarts therefore retain watchdog liveness while still requiring a completed scan before any heartbeat.

Native autonomous qualification now waits boundedly through truthful between-scan `UNSUPPORTED` responses after the restart matrix instead of misclassifying that fail-closed health window as a product failure.

The release remains a deliberately narrow Linux public alpha. It does not claim universal AI recognition, behavioural detection, network isolation, malware prevention or EDR replacement. The existing real-AI assets remain external and are not distributed in release archives.
