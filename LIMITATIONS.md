# Limitations

Lumi Eggcracker 1.0.0 autonomously acts on a complete match from its four active,
publicly qualified native content profiles and on a prohibited egress event from every
explicitly selected workload. Its content path supports a regular GGUF v2/v3
artifact combined with the exact SHA-256-pinned qualified llama.cpp ELF, or a
regular Safetensors artifact combined with the exact SHA-256-pinned CPU PyTorch
bridge-plus-ATen ELF pair, including the qualified native Ollama/GGUF and
vLLM/Safetensors topology forms. Runtime identity must be a structurally loadable ELF
observed as the running executable or an executable mapping; merely opening or
read-only mapping ELF bytes is not runtime evidence. This deliberate pinning
means other builds and versions are unsupported until their full-file identities
are added and qualified. The two evidence groups may be observed in one process
or across a bounded related workload using the installed dedicated workload UID:
a live direct parent/child or sibling relation, or one exact Eggcracker-owned
workload cgroup. Unrelated same-UID or common-init processes are not joined.
There is no guarantee for evidence that escaped before observation, unobserved
processes, or containerised or remote workloads. It does not recognise
arbitrary, custom, fully stripped, encrypted or otherwise unlisted AI/agent
workloads.

The qualification contract is published in `QUALIFICATION.md`. Qualification
is exact-commit and host bound. The release manifest, installed policy, native
receipts and portable evidence seal must agree; a prior 0.5.0, 0.6.0 or 0.9.0
result or CI pass does not qualify a 1.0.0 package or another host.

Ollama and vLLM are active only for the exact native CPU topology fixtures and
launcher identities in the candidate catalogue. Name-only profiles for TGI,
LocalAI, llamafile and agent CLIs remain inactive until separately qualified.

The observer uses bounded `/proc` polling. It has no kernel execution hook, eBPF programme or guarantee that a process which forks, daemonises or exits before discovery can be reconstructed as one complete historical tree. A successful receipt proves the exact captured quarantine cgroup is empty.

On the qualification WSL2 Ubuntu environment, warmed-cache scan p95 was approximately 251 ms with 50 synthetic children, 650 ms with 200, and 2.9 seconds with 1,000. Content inspection occurs on alternating scans, so high process density can create multi-second observation delay. Descriptor reads remain bounded and mapping reads have an 8 MiB per-process byte ceiling. Every mapping line inside that byte ceiling participates in fair inspection stripes; the stripe generation survives supervisor restart rather than repeatedly scanning one prefix. A maps or mount table exceeding the byte ceiling fails the discovery scan explicitly, makes health unsupported after the bounded failure threshold and stops watchdog heartbeats; it is never treated as a silently inspected process. Results are host-specific; run the bundled benchmark before deployment.

The supervisor service protects home directories. Model files held open by a workload can still be inspected through a stable process-descriptor duplicate when an ordinary procfs reopen is unavailable, including deleted files on the qualified WSL2 DrvFS path. Models discovered only by a pathname under a protected home or cache have not been qualified as a release path.

The product does not kill generic Python, Node.js, Java, shell, GPU-intensive or
memory-intensive processes based on those generic properties. It does not
require or claim proof of inference: an unapproved converter, inspector,
evaluator or trainer satisfying both evidence groups is an intended kill.
Selected workloads are offline-only in 1.0.0. Loopback is allowed; all
non-loopback IPv4/IPv6 output is kernel-denied in a transient run namespace and
trips whole-tree containment. This is not general host network isolation,
allowlisting, DNS policy, proxying, filesystem isolation, credential isolation,
behavioural modelling, telemetry upload, malware prevention or EDR.

Approvals are exact and deliberately narrow: only a qualified native llama runtime or root-owned CPython executing one absolute regular script is supported. Workload UID, resolved executable identity and complete argv digest must match at the protected pre-exec `start` gate. Python `-c`, `-m`, stdin/interactive, relative-script, package-directory, symlink and unsupported-interpreter forms are rejected. The Python script is identity/digest bound and launched from an immutable per-run root-owned stage; changing it aborts `start`. This does not claim a general dependency-closure analyser or make approved workloads a sandbox. A direct or third-party launch cannot consume an approval, and descendants or siblings do not inherit one. Revoking an approval affects future protected launches, not a workload already running under that approval.

The explicit `start` command remains non-interactive. It has no terminal attachment, current-working-directory forwarding, timeout or output streaming. It supports one active selected workload globally; PID, memory and CPU limits are explicit. Detection receipts are bounded to 1000 entries.
