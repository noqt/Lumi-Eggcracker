# Limitations

Lumi Eggcracker protects only commands explicitly launched through its local root supervisor on the qualified Linux/systemd/cgroup-v2 environment.

It does not discover AI processes, attach existing processes, identify malware, detect unknown intrusions, isolate networks, credentials or filesystems, provide general malware prevention, or replace EDR.

The `start` command is non-interactive in 0.1.2: there is no terminal attachment, current-working-directory forwarding, timeout, memory/CPU limit UX, or output streaming. The supervisor supports one active protected workload globally. Terminal records are retained locally up to 128 entries.
