# Counter-AI v2 direct-Linux reproduction

This is a small, versioned, off-by-default source slice for the v2 native
demonstration. The harmless selected workload and package initializer remain
byte-identical to their pinned files under `experiments/counter_ai_v2/`. The
current `native_demo.py` keeps the same path and native gates, with a reporting
correction that requires consistent canary-continuation evidence and complete
cleanup before returning `PASS`.

## Historical source pin

The portable protocol and example manifests intentionally retain the historical
`native_demo.py` SHA256
`cb836ab6fcc4c0f0bd9108725810d1f3e89c9f9b84e4f15d526d2836e36d84a2`. The
retained native07 result and that pin describe the original source bytes; they
do not validate the current reporting repair. The manifests remain marked
`EXAMPLE_NOT_AUTHORIZATION`, are unchanged, and cannot authorize execution of
the current source. This reporting-only repair did not rerun or requalify the
native demonstration.

The current default native entry point is inert and prints a plan:

```text
python3 -I -B experiments/counter_ai_v2/native_demo.py
```

No command below is an acceptance record. Technical and Risk acceptance must be
completed separately, and the accepted record must bind a fresh run nonce to
the exact native and artifact hashes. The examples in this directory contain
placeholders and are rejected if passed unchanged. They never create an
approval, fabricate a run identity, or authorize execution.

## Direct disposable-Linux reproduction

An operator with an independently accepted envelope may materialize fresh
copies of the two examples, replace every `REPLACE_WITH_*` value, and place
them in root-controlled paths. The artifact manifest must be hashed after
materialization; its digest must be copied into both the accepted record and
the source manifest. The source manifest must bind the same fresh `run_id` and
32-hex `run_nonce`. The native and workload scripts, plus every ancestor used
to reach them, must be root-owned and not writable by the workload, group, or
other users; the frozen core rejects symlinks and unsafe ownership/permissions.

The direct route has no implicit path or host default. On a disposable Linux
root with cgroup-v2 and the two dedicated unprivileged accounts already
prepared, the explicit invocation is:

```text
python3 -I -B experiments/counter_ai_v2/native_demo.py --execute \
  --run-dir /absolute/fresh/v2-run-<id> \
  --workload-script /absolute/source/experiments/counter_ai_v2/workload.py \
  --native-script /absolute/source/experiments/counter_ai_v2/native_demo.py \
  --workload-user counter-v2 \
  --canary-user counter-v2-canary \
  --run-id v2-<fresh-id> \
  --nonce <fresh-32-lowercase-hex> \
  --hazard-acceptance /absolute/records/accepted-<nonce>.json \
  --source-manifest /absolute/records/source-manifest-<nonce>.json \
  --artifact-manifest /absolute/records/artifact-manifest-<nonce>.json \
  --result-path /absolute/fresh/v2-run-<id>/result.json
```

The accepted record, source manifest, artifact manifest, run directory, and
result path are separate explicit inputs. The native entry point enforces the
root-owned durable latch, selected cgroup-v2 allocation, trusted external
observer, forced stop, separate canary identity, relaunch refusal, reset
without auto-start, and cleanup accounting. Missing or contradictory evidence
is `UNKNOWN`; a whole-VM stop is not substituted for selected containment.

The direct route is not a VM or host-isolation boundary. It must run only in a
disposable Linux environment whose loss is acceptable, with no NIC, host share,
passthrough, credential, or third-party endpoint. The selected workload limits
are CPU 5 seconds, address space 256 MiB, 32 processes, and 16 MiB fake sink;
the observer stop proof timeout is 2 seconds. The retained QEMU limits (1 GiB,
2 vCPU, q35/TCG with 128 MiB translation cache, 600 seconds) remain part of
the frozen envelope, but this direct slice does not start QEMU.

The retained native07 result is evidence for the original pinned source only.
It does not validate this reporting repair as a new qualification, does not
promote a detector, and does not authorize production enforcement, holdout
access, or publication.
