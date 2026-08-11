# Limitations

Eggcracker 0.4.0 autonomously acts only on a complete match from its two active, publicly qualified content profiles. Its content path supports a regular GGUF v2/v3 artifact combined with a qualified llama.cpp/GGML ELF runtime, or a regular Safetensors artifact combined with the exact pinned CPU PyTorch bridge-plus-ATen ELF build-ID pair. The two evidence groups may be observed in one process or across a bounded related workload using the installed dedicated workload UID: a live direct parent/child or sibling relation, or one exact Eggcracker-owned workload cgroup. Unrelated same-UID or common-init processes are not joined. There is no guarantee for evidence that escaped before observation, unobserved processes, or containerised or remote workloads. It does not recognise arbitrary, custom, fully stripped, encrypted or otherwise unlisted AI/agent workloads.

Name-only profiles for Ollama, vLLM, TGI, LocalAI, llamafile and agent CLIs are intentionally not active in this release. They require exact invocation fixtures and launcher-identity qualification before they can become destructive profiles.

The observer uses bounded `/proc` polling. It has no kernel execution hook, eBPF programme or guarantee that a process which forks, daemonises or exits before discovery can be reconstructed as one complete historical tree. A successful receipt proves the exact captured quarantine cgroup is empty.

On the qualification WSL2 Ubuntu environment, warmed-cache scan p95 was approximately 251 ms with 50 synthetic children, 650 ms with 200, and 2.9 seconds with 1,000. Content inspection occurs on alternating scans, so high process density can create multi-second observation delay. Results are host-specific; run the bundled benchmark before deployment.

The supervisor service protects home directories. Model files held open by a workload can still be inspected through its procfs descriptor, but models discovered only by a pathname under a protected home or cache have not been qualified as a release path.

The product does not kill generic Python, Node.js, Java, shell, GPU-intensive, memory-intensive or networked processes based on those generic properties. It does not require or claim proof of inference: an unapproved converter, inspector, evaluator or trainer satisfying both evidence groups is an intended kill. It does not use behavioural modelling, telemetry upload, network isolation, credential isolation, filesystem isolation, malware prevention or EDR functions.

Approvals are exact: UID, resolved executable identity and complete argv digest must all match. Changing any argument requires a new approval. Revoking an approval affects future detections, not a workload already running under that approval.

The explicit `start` command remains non-interactive. It has no terminal attachment, current-working-directory forwarding, timeout or output streaming. It supports one active selected workload globally; PID, memory and CPU limits are explicit. Detection receipts are bounded to 1000 entries.
