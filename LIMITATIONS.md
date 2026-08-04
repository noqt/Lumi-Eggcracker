# Limitations

Lumi Eggcracker 0.2.0 autonomously acts only on a complete match from its installed deterministic AI-runtime catalogue. It does not recognise arbitrary, custom, obfuscated, containerised, remote or otherwise unlisted AI/agent workloads.

The observer uses bounded `/proc` polling. It has no kernel execution hook, eBPF programme or guarantee that a process which forks, daemonises or exits before discovery can be reconstructed as one complete historical tree. A successful receipt proves the exact captured quarantine cgroup is empty.

The product does not kill generic Python, Node.js, Java, shell, GPU-intensive, memory-intensive or networked processes based on those generic properties. It does not use behavioural modelling, telemetry upload, network isolation, credential isolation, filesystem isolation, malware prevention or EDR functions.

Approvals are exact: UID, resolved executable identity and complete argv digest must all match. Changing any argument requires a new approval. Revoking an approval affects future detections, not a workload already running under that approval.

The explicit `start` command remains non-interactive. It has no terminal attachment, current-working-directory forwarding, timeout, memory/CPU limit UX or output streaming. It supports one active selected workload globally. Detection receipts are bounded to 1000 entries.
