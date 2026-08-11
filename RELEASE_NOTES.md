# Lumi Eggcracker 0.4.0

0.4.0 adds aggressive `content.safetensors-pytorch` recognition to the qualified 0.3.1 control plane. A valid bounded Safetensors header and the exact pinned CPU PyTorch/ATen ELF build-ID pair may appear in one process or across a bounded related workload: the same unprivileged UID with a live direct parent/child or sibling relation, or one exact Eggcracker-owned workload cgroup. Unrelated same-UID or common-init processes are not joined. There is no guarantee for evidence that escaped before observation, unobserved processes, or containerised or remote workloads. An unapproved complete match is immediately contained without requiring proof of a forward pass. The three-socket approval boundaries, watchdog and direct cgroup.kill containment remain qualified release properties.

The release also applies bounded memory, CPU, I/O, task and descriptor limits to the supervisor, watchdog and selected workloads. Complete unapproved matches continue to use pidfd stop/capture and direct `cgroup.kill` as the authoritative complete-tree kill primitive.

The release remains a Linux engineering preview. It does not claim universal AI recognition, behavioural detection, network isolation, malware prevention or EDR replacement. The existing real-AI assets remain external and are not distributed in release archives.
