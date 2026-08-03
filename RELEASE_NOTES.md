# Lumi Nutcracker 0.1.0

Lumi Nutcracker 0.1.0 is a Linux engineering preview of a deliberately small AI and agent workload kill switch.

## Supported claim

> Lumi Nutcracker launches an explicitly selected AI or agent workload inside a root-controlled Linux cgroup and terminates the complete workload tree on operator command or when its configured PID-runaway tripwire fires.

## Highlights

- One supported root-supervisor backend on systemd and unified cgroup v2.
- Dedicated no-login workload identity separated from the human operator.
- Direct `cgroup.kill` enforcement followed by exact empty-hierarchy verification.
- Operator kill, automatic PID tripwire, post-containment receipts and restart fail-closed recovery.
- Public commands: `start`, `kill`, `status`, `list`, `doctor` and `version`.

## Qualification

The release passed 100/100 fork-race kills, 100/100 unrelated-canary survivals, 100 denied workload socket attempts, zero replacement launches, five automatic PID-tripwire trials, 50 benign completions, 20 supervisor restart recoveries, clean install/uninstall and a real local AI smoke demonstration. Native p95 trigger-to-empty latency was below the precommitted 500 ms ceiling.

## Important limits

This release does not identify AI, discover unknown processes, attach to existing workloads, isolate network or credentials, detect malware, or replace EDR. See [LIMITATIONS.md](LIMITATIONS.md).
