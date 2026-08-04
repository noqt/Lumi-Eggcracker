# Security model

The root-owned `lumi-eggcracker.service` is the only enforcement component. It reads the root-owned detector catalogue, observes bounded process facts from `/proc`, and accepts control requests only from root or the configured operator UID over a root-owned Unix socket. A workload account remains a dedicated no-login unprivileged user with no supplementary groups and cannot access the control socket.

For an unapproved complete catalogue match, Eggcracker revalidates PID plus start-time identity, sends `SIGSTOP` through a pidfd, stops descendants, moves the discovered tree into an exact child cgroup delegated to the supervisor, and writes `1` to `cgroup.kill`. It proves that cgroup hierarchy is empty before writing the detection receipt. Individual pidfd signals are the initial stop/capture mechanism; direct cgroup-v2 `cgroup.kill` remains the authoritative complete-tree kill primitive.

An approval is an exact root-owned record of a UID, resolved executable device/inode and digest, plus complete argv digest. Raw process arguments and environment values are not written to approval or detection records.

This is not a general sandbox, universal AI detector, host intrusion detector, malware detector, network isolator, credential isolator or EDR replacement. An unapproved workload can evade a catalogue-based detector by using an unsupported or disguised runtime; that boundary is documented rather than hidden.
