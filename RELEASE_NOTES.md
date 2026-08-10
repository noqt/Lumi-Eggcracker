# Lumi Eggcracker 0.4.0

0.4.0 adds aggressive `content.safetensors-pytorch` recognition to the qualified 0.3.1 architecture. A valid bounded Safetensors header and the exact pinned CPU PyTorch/ATen ELF build-ID pair must coexist in one process snapshot; an unapproved complete match is immediately contained without requiring proof of a forward pass. The existing three-socket approval boundaries, watchdog and cgroup.kill containment remain unchanged.

The release also applies bounded memory, CPU, I/O, task and descriptor limits to the supervisor, watchdog and selected workloads. Complete unapproved matches continue to use pidfd stop/capture and direct `cgroup.kill` as the authoritative complete-tree kill primitive.

The release remains a Linux engineering preview. It does not claim universal AI recognition, behavioural detection, network isolation, malware prevention or EDR replacement. The existing real-AI assets remain external and are not distributed in release archives.
