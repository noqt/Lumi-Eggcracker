# Boundary B1 Repair Brief — bounded multi-process AI workload correlation

Status: implementation brief
Baseline: Lumi Eggcracker 0.4.0, source commit `731262520ce39975d72e05e7a58c47f332caf63d`

## Problem

The B1 qualification harness passed its containment and safety checks but found
that the detector only joins model-content and AI-runtime evidence when both
appear in one PID/start-time snapshot. A native local workload whose artifact
and runtime roles are split between related processes or cgroups survives.

This is a product boundary, not a cgroup-kill failure.

## Objective

Recognise and contain a supported local AI workload when its model-content and
qualified-runtime evidence are distributed across a small, exact workload
boundary, without turning the supervisor into a broad host process-graph or
same-UID killer.

## Required design

1. Add bounded parent/process identity data sufficient to establish a workload
   relation. A relation is allowed only when all of the following hold:
   - the evidence-bearing processes use the same unprivileged workload UID;
   - they are directly related by a bounded parent/child or sibling lineage, or
     are members of one exact Eggcracker-owned workload cgroup;
   - the relation is established from live PID/start-time identities, not PID
     numbers alone;
   - unrelated processes with the same UID or a common init ancestor do not
     join the workload.
2. Aggregate only the two existing deterministic evidence groups:
   `MODEL_CONTENT` and `MODEL_RUNTIME`. A complete profile may be qualified
   across related processes, but partial or malformed evidence must survive.
3. Keep correlation bounded and in memory. No durable evidence, receipt,
   explanation, executable hash for the receipt, model call or network action
   may occur before containment begins.
4. Enforce the complete correlated workload. Stop and quarantine every
   evidence-bearing identity plus its descendants, then use direct
   cgroup-v2 `cgroup.kill` and prove the quarantine empty. Do not kill a broad
   common ancestor cgroup merely because it contains the candidates.
5. Approval remains exact per evidence-bearing process. Approval of one parent
   does not authorise an unapproved runtime child, replacement or changed
   executable/arguments. Any unapproved evidence-bearing role causes whole
   workload containment; all roles must be exactly approved to survive.
6. Extend the receipt without breaking existing fields. Record the correlated
   evidence-bearing identities and the bounded workload-boundary type so the
   post-containment proof explains why multiple processes were selected.

## Qualification matrix

The repaired B1 harness must run against the exact baseline candidate and
include:

- same-process FD and mmap positive controls;
- artifact-parent/runtime-child in one cgroup — terminate the workload;
- sibling artifact/runtime processes in one cgroup — terminate the workload;
- artifact-parent/runtime-child in separate child cgroups — terminate the
  workload;
- fork/exec helper split — terminate the workload;
- inherited-FD and shared-path children — terminate the child/workload;
- renamed and deleted-open artifacts — terminate the workload;
- artifact-only, runtime-only and malformed-runtime partials — survive;
- unrelated same-UID process in the same broad cgroup — survive;
- unrelated same-UID process in a separate cgroup — survive;
- concurrent replacement fork during qualification — no replacement survives;
- unrelated canary survival, three control-socket denial and exact approval
  non-broadening checks.

## Release gates

- all complete split-process cases produce `TERMINATED` receipts;
- every kill receipt proves `cgroup.kill`, `root_populated=0` and
  `surviving_pids=[]`;
- all partial, malformed and unrelated same-UID controls survive;
- canary survival is 100%;
- zero successful query/operator/admin socket accesses or replacement launches;
- trigger-to-empty p95 remains below 500 ms;
- watchdog heartbeat, supervisor restart/recovery and existing 0.4.0
  containment/benign/native suites remain green;
- no broad ancestor cgroup is selected and no unrelated process is captured;
- clean install, uninstall and release verification pass.

## Non-goals

This repair does not add arbitrary process-graph inference, same-UID host-wide
correlation, container or GPU discovery, remote-compromise detection, network
namespaces, network isolation, credential isolation or behavioural modelling.

If safe relation proof cannot be established for a topology, it remains outside
the supported claim rather than being joined heuristically.

## Stop conditions and deliverables

Stop before broadening the product if the repair needs host-wide process
correlation, kills an unrelated control/canary process, loses exact approval
semantics, or breaks containment ordering.

Deliver:

- focused product commit and source diff;
- direct unit tests for relation grouping and multi-target containment;
- repaired B1 native report and raw receipts;
- full 0.4.0 regression report;
- install/uninstall and SHA256 evidence pack;
- updated public limitation or release claim only after the gates pass.

