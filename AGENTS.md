# Lumi Nutcracker repository rules

- This product supports only explicitly launched workloads on Linux with systemd and unified cgroup v2.
- Tests may affect only fresh Nutcracker-owned units and fixture processes they create. Never signal PID 1, the test runner, its ancestors, a pre-existing process or an unrelated cgroup.
- The root supervisor is the sole enforcement component. The workload identity must never gain control-socket access or root authority.
- Direct `cgroup.kill` is authoritative. Do not replace it with process ancestry, compatibility backends or service-stop-only proof.
- Keep a trigger-side path free of durable state, evidence, hash, model and networking operations until direct containment has been attempted.
- Do not add network isolation, behavioural models, AI identification, BPF, cloud services or unsupported-platform claims without a separately approved evidence boundary.
- Preserve unrelated user changes. Keep generated artifacts, models, VM images, keys and local evidence out of source control.
- A partial or ambiguous result must never be reported as a successful termination.
