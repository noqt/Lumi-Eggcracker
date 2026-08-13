# Qualification

This file defines the native qualification contract for an exact candidate and
host. Project records report a complete result for commit
`418f877f0d450aeb26d4a1233257746808c490e5` on one WSL2 Ubuntu host. The
corresponding checksum-bound native evidence pack is not retained in this
repository, a public GitHub Release, or current authorised durable evidence.
Treat that result as project-recorded and commit-bound, not as independently
re-verifiable native evidence or a qualification of another host. Re-run every
gate below on the exact source and target host before making a current native
qualification claim.

The 0.4.0 candidate is releasable only when its exact commit passes the complete 0.3.1 regression, strict Safetensors and PyTorch/ATen direct tests, the existing selected-workload matrix, the native autonomous-discovery matrix, the GGUF and Safetensors content-recognition matrices, the combined detector self-protection matrix, and the host-overhead benchmark on one Ubuntu VM.

Mandatory autonomous gates are: 100/100 unapproved fixture discoveries and complete tree kills, 100/100 unrelated-canary survivals, zero surviving bounded replacement attempts, zero reused-PID signals, 50/50 exact root-approved survivals launched through the protected pre-exec operator gate, zero direct-launch approval bypasses, zero mutable-script approval bypasses, fail-closed rejection of unsupported interpreter forms, zero complete related submatches surviving a successful receipt, zero kills in the benign and partial-match matrices, zero kills from arbitrary open runtime-looking descriptors, read-only runtime-looking mappings or non-loadable ELF metadata, zero workload policy/socket accesses, restart recovery, bounded high-FD pressure recovery without scan-window reset, p95 qualifying-snapshot-to-stop below 100 ms, and p95 trigger-to-empty below 500 ms. Full process-start-to-stop time is retained as diagnostic evidence because real model startup can occur before the runtime identity becomes observable; it is not a containment-latency gate.

The self-protection gates additionally require zero workload connections to each query, operator and administrative socket; zero workload replacement launches; root-only approval administration; restart recovery; a watchdog lost-heartbeat containment; a watchdog installed-file-digest containment; bounded supervisor/watchdog resources; and clean removal of both units and runtime directories.

The family-specific evidence is deliberately explicit: five renamed-runner, extensionless-model direct-unapproved/protected-approved/direct-unapproved real llama.cpp/Qwen sequences; five real pinned PyTorch/Safetensors protected-approval/revocation sequences; one five-case real ATen-only negative-control set with zero containment; 100 complete GGUF-profile kills, 100 GGUF canary survivals, 50 protected exact GGUF approvals, and at least 300 benign or partial model-handling launches with zero kills. It must cleanly install with discovery armed and completely uninstall. Evidence is specific to the tested commit and host; it does not establish universal AI identification or inference detection. Only the two content profiles listed in the README are active release claims; other catalogue ideas remain unqualified research work.

The host-overhead gate is measured with the bundled root-only benchmark. It
creates only sleeping disposable children and records scan duration, CPU time,
read counters (including kernel read characters), resident memory and context
switches at approximately 50, 200 and 1,000 host processes. The resulting JSON
is release evidence; it is not a
claim that every host will have the same cost.

```sh
sudo python3 scripts/benchmark_overhead.py \
  --policy /etc/lumi-eggcracker/policy.json \
  --output ./overhead-benchmark.json
```
