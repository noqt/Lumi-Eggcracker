# Qualification

This file defines the native qualification contract for one exact 1.0.3
candidate and host. The release manifest, source archive, embedded zipapp
identity, installed policy, all receipts and the evidence seal must name the
same source commit. Re-run every gate after any commit change; evidence from
0.5.0, another candidate or another host is not transferable.

The primary native host is a disposable ordinary Ubuntu 24.04 VM with systemd,
unified cgroup v2 and the released system Python. WSL2 may be used as a second
host and for DrvFS-specific cases, but it does not replace the ordinary-VM
gate. Direct unit tests and Ruff must pass on Linux, and GitHub CI must pass on
Python 3.11, 3.12 and 3.13. The exact candidate must then pass the complete
regression, selected-workload, autonomous-discovery, both real content-profile,
self-protection and overhead matrices.

The offline-boundary primitive probe is separately gated on the exact
public candidate. Before publication, Ruff and the complete unit suite must
pass on Python 3.11, 3.12 and 3.13, an independent code review must accept the
exact candidate, and a disposable ordinary native Ubuntu 24.04 host must
complete all of these gates:

- 100/100 exact two-process target-tree terminations under the verified
  three-task transient-service ceiling through the production pidfd-stop plus
  direct `cgroup.kill` path;
- 100/100 unrelated-canary survivals, zero non-target kills, zero target
  survivors and zero residual probe units or cgroups;
- concurrent and forced unit-name-collision cases with no identity ambiguity;
- interrupt and deterministic fault injection before and after owner capture,
  pidfd binding, stop, kill, empty proof and cleanup, with no false success;
- strict proof of `populated 0` and an empty recursive process set while the
  captured cgroup identity still exists; disappearance before proof is failure;
- a bounded public receipt containing no PID, path, account, environment,
  command line, host identifier or other private field, while binding the
  regular clone's exact Git HEAD and the SHA-256 of the executed source set;
- forced orchestrator termination at every stage, followed by proof that the
  45-second worker ceilings leave no target, canary, transient unit or cgroup.

Run an independent post-qualification review before pushing the probe or
describing it as publicly available. This gate proves only deterministic
containment of the synthetic tree. It does not qualify recognition,
installation, model handling, product-wide effectiveness or a new release.

Mandatory autonomous gates are: 100/100 unapproved fixture discoveries and complete tree kills, 100/100 unrelated-canary survivals, zero surviving bounded replacement attempts, zero reused-PID signals, 50/50 exact root-approved survivals launched through the protected pre-exec operator gate, zero direct-launch approval bypasses, zero mutable-script approval bypasses, fail-closed rejection of unsupported interpreter forms, zero complete related submatches surviving a successful receipt, zero kills in the benign and partial-match matrices, zero kills from arbitrary open runtime-looking descriptors, read-only runtime-looking mappings or non-loadable ELF metadata, zero workload policy/socket accesses, restart recovery, bounded high-FD pressure recovery without scan-window reset, 100/100 IPv4/IPv6 boundary kills, 100/100 same-host canary survivals, zero prohibited packets beyond the deny point, zero boundary rule/link/namespace modification attempts, observer and supervisor fail-closed recovery, p95 qualifying-snapshot-to-stop below 100 ms, and p95 authenticated-boundary-trigger-to-empty below 500 ms. Full process-start-to-stop time is retained as diagnostic evidence because real model startup can occur before the runtime identity becomes observable; it is not a containment-latency gate.

The self-protection gates additionally require zero workload connections to each query, operator and administrative socket; zero workload replacement launches; root-only approval administration; restart recovery; a watchdog lost-heartbeat containment; a watchdog installed-file-digest containment; bounded supervisor/watchdog resources; and clean removal of both units and runtime directories.

Five release-blocking Priority-0 campaigns are mandatory:

1. approval material substitution: rename, exchange, hardlink, symlink, bind
   mount and overlay copy-up, hostile Python loader/import environment, and an
   approved parent spawning an unapproved supported child;
2. pathless/deleted evidence and execution: memfd, sealed memfd, `O_TMPFILE`,
   deleted/open model and runtime evidence, `fexecve`, `execveat` and procfd
   model operands;
3. bounded saturation beyond the old 16-item boundary: 17/32/64 simultaneous
   independent matches, a 96-process related complete component, 512 related
   partials, 1,024 descriptors and 600 executable decoy mappings;
4. deterministic fault injection at pidfd binding, stop, descendant discovery,
   quarantine creation/move/kill/empty proof and receipt write/replace/fsync;
   no injected failure may return or publish success, and a failed autonomous
   receipt write must immediately make health unsupported and stop heartbeats;
5. privileged installer attacks: hostile Python import hooks, symlinked inputs,
   expected-digest/manifest/version/source drift, traversal archive, partial
   prior installation, pre-existing-install refusal and a pathname replacement
   after the installer binds its artifact descriptor. The public bootstrap must
   also reject an absent or invalid detached checksum signature, self-recomputed
   unsigned checksums, duplicate/normalized-duplicate members, archive links or
   special members and a bundle whose authenticated asset identity disagrees
   with the signed tag source identity.

Before publication, sign the final detached checksum list with the private key
corresponding to fingerprint
`53786DEB001459956A2E1B86A3F29F7A27636DC7`, publish `SHA256SUMS.asc` beside
`SHA256SUMS`, the Linux bundle and `eggcracker-release-key.asc`, and rerun the
public first-kill asset-authentication path against those exact uploaded bytes.
CI build artifacts without that detached signature are build outputs, not a
releasable distribution.

The control-plane parser must also reject, without replacing the supervisor,
a valid sub-32-KiB JSON request containing an integer beyond the supported
128-digit bound. Runtime qualification must reach an exact executable mapping
after more than 4,096 earlier mappings, provided the complete procfs maps input
remains within the 8 MiB byte ceiling.

The related-process matrix must also split valid model and runtime evidence
across stable PPID-1 holders whose only relation is one exact active
`lumi-eggcracker-workload-<run-id>.service` cgroup. The complete selected
workload must be contained with an exact-empty receipt; an identically named
inactive or unowned cgroup must not create a relation.

After deterministic qualification, replay the frozen 41-case Daybreak corpus
against the exact candidate. Then run a fresh no-history Daybreak campaign with
black-box, source-informed and adaptive T1/T2/T3 rounds. Any reproducible
approval bypass, supported-profile containment escape, false successful empty
receipt, control-plane privilege gain, self-protection defeat or destructive
false positive is a release blocker.

The family-specific evidence is deliberately explicit: five renamed-runner, extensionless-model direct-unapproved/protected-approved/direct-unapproved real llama.cpp/Qwen sequences; five real pinned PyTorch/Safetensors protected-approval/revocation sequences; one five-case real ATen-only negative-control set with zero containment; qualified native Ollama/GGUF and vLLM/Safetensors topology fixtures; 100 complete GGUF-profile kills, 100 GGUF canary survivals, 50 protected exact GGUF approvals, and at least 300 benign or partial model-handling launches with zero kills. One additional real unapproved GGUF/llama workload must run through the public protected-start path, reach `TERMINATED`, and leave zero exact namespace paths or PID 1 mount entries without restarting the supervisor. It must cleanly install with discovery armed and completely uninstall. Evidence is specific to the tested commit and host; it does not establish universal AI identification or inference detection. Only the four exact content/topology profiles listed in the README are active release claims; other catalogue ideas remain unqualified research work.

The host-overhead gate is measured with the bundled root-only benchmark. It
creates only sleeping disposable children and records scan duration, CPU time,
read counters (including kernel read characters), resident memory and context
switches at approximately 50, 200 and 1,000 host processes. The resulting JSON
is release evidence; it is not a
claim that every host will have the same cost.

The offline-boundary primitive gate is run before installation with:

```sh
sudo /usr/bin/python3 -I -S scripts/qualify_offline_boundary.py \
  --output ./offline-boundary.json
```

The result must prove loopback TCP/UDP completion, 100 synthetic IPv4 and
IPv6 TCP/UDP attempts counted and dropped, unchanged sink receive counters,
same-host canary survival, denial of unprivileged nftables/link/namespace
changes, unchanged host route/forwarding/link/ruleset digests, and removal of
both exact transient namespaces. The harness is primitive-only and does not
qualify the integrated supervisor until this result is bound to the candidate.

The integrated boundary matrix then repeats the same traffic through selected
workloads at burst sizes 1, 16, 64, 256 and 1,024. Every observed counter
increase must produce one `NETWORK_BOUNDARY` receipt only after the exact
owned-cgroup `cgroup.kill` and empty proof. A supervisor restart, observer
death, namespace/rule identity drift or receipt fault must either restore a
valid guard before release or fail closed by killing the exact workload.

The final evidence directory must be checksum sealed and packaged with
`package_evidence.py`. The resulting tar archive must preserve regular-file,
directory, symlink and hardlink semantics, pass `verify_evidence_archive.py`
without extraction, and pass again after transfer to a second host. A ZIP-only
copy is not portable release evidence.

```sh
sudo python3 scripts/benchmark_overhead.py \
  --policy /etc/lumi-eggcracker/policy.json \
  --output ./overhead-benchmark.json
```
