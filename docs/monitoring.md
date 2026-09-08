# Reported health in an existing Prometheus workflow

Lumi Eggcracker operators with an already-supported installation can publish
the existing read-only `doctor` report to an existing node_exporter textfile
collector. This source-checkout integration adds no listener, daemon permission,
package dependency, scheduler or installation step. It reports supervisor health,
not measured containment effectiveness, protection, authenticated evidence or
independent adoption. Native support and qualification boundaries are unchanged.

## Collect once

Use Python 3.11 or newer from this reviewed source checkout, as an operator who
already has permission to query Eggcracker. Prepare an existing absolute output
directory owned by that operator and not writable by another user or group.
Configure an existing **same-UID** node_exporter to read that directory. Then, from the checkout:

```sh
python3 scripts/export_monitoring_metrics.py --output /var/lib/eggcracker-metrics/health.prom
```

The example path is illustrative; choose an explicit neutral path you own. The
collector does not create directories, grant access, install timers or change
socket permissions. Node_exporter needs read/traverse permission; the output is
created mode 0600, so this integration supports an existing same-UID exporter
with directory traversal permission. A differently-owned exporter is outside
this slice. Do not rely on chmod or ACL changes to an old output inode: atomic
replacement creates a new mode-0600 file each time.

Exit 0 means a valid report was published (which may report unhealthy); exit 1
means the query failed or selected fields were unavailable and fresh
query-invalid telemetry was published; exit 2 means publication failed. Errors
are bounded and do not include raw response, exception, workload or path details.
An existing output is replaced only if it is regular, single-link, operator-owned,
not group/world writable and starts with the exact collector ownership marker.
Never put that marker on an unrelated file. This is deliberate ownership
recognition, not cryptographic provenance. Symlink/reparse targets and parents,
unsafe parent ownership/permissions, and unrelated output are refused.

The output directory and ancestors must remain trusted and must not be concurrently
mutated. System sticky temporary ancestors are allowed, but the output directory
itself must be private. This is not protection against a hostile directory owner.
Writes use an exclusive same-directory non-`.prom` temporary file then atomic
replacement. A sibling `.prom.lock` is created exclusively **before the query**;
overlap is refused, not queued. After an interrupted process, an operator must
confirm no collector remains before removing its lock. Nothing automatically
removes another invocation's lock. Failed replacement retains the prior metrics,
whose age exposes publication failure; do not mistake that retained health for a
fresh collection.

## Wire into existing monitoring

Run the command every 60 seconds using your existing operator-controlled job
runner. No scheduler is installed here. The unchanged client timeout is 30 seconds
per operation, **not** a promised total deadline. Observe exit codes and arrange
job duration supervision in your existing runner; the exclusive lock prevents
overlap. Correct both collector and Prometheus clocks with your existing time
synchronisation. The rules allow 60 seconds of future skew; larger skew is unknown
freshness and suppresses health/query alerts.

Load [eggcracker.rules.yml](../integrations/prometheus/eggcracker.rules.yml) through
your existing Prometheus `rule_files` configuration. Opt in each intended
node_exporter scrape target with the target label `eggcracker_monitor: "true"`.
For example, merge these labels into your existing static target inventory:

```yaml
static_configs:
  - targets: ["node-one:9100", "node-two:9100"]
    labels:
      eggcracker_monitor: "true"
```

Use unique `(job, instance)` identities per exporter and do not drop or rewrite
these identity/opt-in labels on Eggcracker metrics. Keep expected targets in
inventory even if a collector has never run: removing a target also removes the
ability to alert on its absence. The rules use per-target `up` inventory, not
global `absent()`, so one reporting host cannot hide another missing host.
Exporter-down is a separate alert and suppresses Eggcracker missing/stale/health
alerts. Missing output on a reachable exporter, stale output and query failure
are distinct. These rules do not monitor Prometheus's own availability.

Rules evaluate every 30 seconds and require two minutes of continuous condition.
Collection is stale when older than 180 seconds, so stopping a fresh collector
normally alerts after more than five minutes plus scrape/evaluation latency.
Query-invalid, reported-unhealthy, missing and exporter-down conditions have the
same two-minute pending period. Recovery clears the matching condition on the
next relevant scrape/evaluation; no application restart is performed.

## Fixed metric contract

All metrics are gauges without Eggcracker labels; timestamps are **gauge values**,
never Prometheus sample timestamps. No names, PIDs, paths, arguments, environment
values, catalogue data, event labels or cumulative detection counts are exported.

| Metric prefix `eggcracker_` | Meaning |
| --- | --- |
| `query_valid` | 1 only if all selected fields have recognised types/values; otherwise 0 |
| `collection_timestamp_seconds` | Unix clock at the completed collection attempt |
| `reported_ready` | Exact boolean `autonomous_discovery` |
| `discovery_healthy` | Exact boolean `discovery.healthy` |
| `receipt_storage_healthy` | Exact boolean `discovery.receipt_persistence_healthy` |
| `installation_healthy` | 1 for HEALTHY; 0 for DRIFT, RECOVERY_REQUIRED or NOT_INSTALLED |

The four health gauges are absent when the query is invalid. Missing fields,
unknown installation enums and nonboolean health values are not false health or
healthy defaults. Freshness checks gate health/query alerts. This privacy contract
covers Eggcracker-produced metrics, **not the entire node_exporter endpoint**:
node_exporter's `node_textfile_mtime_seconds` includes a file-path label. Use neutral
paths, restrict the existing endpoint appropriately and sanitise shared evidence.

## Verification boundary

The unit journey uses the additive strict doctor-only length-framed client against a disposable
unprivileged Unix socket, asserting only `doctor` with empty arguments. It is not
a native daemon or containment test. The separate opt-in CI consumer test runs
exact pinned test-only node_exporter on loopback with default collectors disabled
and only textfile enabled, then real promtool evaluates these rules. Fixtures
cover healthy, query loss, stopped/stale collection, recovery, missing output,
two targets with one absent, exporter-down, clock skew and alert pending delays.
No user monitoring account, production endpoint, secret or additional proof run
is needed. Test-only upstream licences/notices remain with downloaded archives.
