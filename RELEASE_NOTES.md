# Lumi Eggcracker 0.3.1

0.3.1 adds P0 self-protection to the existing qualified `content.gguf-llama` capability. The operator query/selected-workload plane and the root-only approval-administration plane now use separate Unix sockets. The workload identity is tested against all control sockets and cannot start a replacement workload. A separate root watchdog fail-closes Eggcracker-owned workload cgroups if supervisor heartbeats stop or installed-file digests drift.

The release also applies bounded memory, CPU, I/O, task and descriptor limits to the supervisor, watchdog and selected workloads. Complete unapproved matches continue to use pidfd stop/capture and direct `cgroup.kill` as the authoritative complete-tree kill primitive.

The release remains a Linux engineering preview. It does not claim universal AI recognition, behavioural detection, network isolation, malware prevention or EDR replacement. The existing real-AI assets remain external and are not distributed in release archives.
