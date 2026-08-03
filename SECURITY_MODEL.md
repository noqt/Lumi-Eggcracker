# Security model

The root-owned `lumi-eggcracker.service` is the only enforcement component. It accepts requests only from root or the configured operator UID over a root-owned Unix socket. A selected workload runs as a dedicated no-login unprivileged user with no supplementary groups; that identity cannot read, connect to, or invoke the socket.

Each workload is placed in an exactly identified systemd transient cgroup. On an operator request, PID-limit tripwire, watcher failure, or supervisor restart recovery, the supervisor validates that exact cgroup identity and writes `1` to its `cgroup.kill` control file. It then proves that the complete cgroup hierarchy is empty. Systemd stop is cleanup only.

This is not a general sandbox, host intrusion detector, malware detector, network isolator, credential isolator, or EDR replacement. The selected workload may still access everything normally available to its unprivileged account.
