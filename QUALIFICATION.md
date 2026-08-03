# Qualification

The 0.1.1 candidate is releaseable only when its exact commit passes the native Ubuntu matrix and produces the minimal evidence pack. Required gates include 100/100 fork-race workload-tree kills, 100/100 unrelated-canary survivals, zero workload control-socket accesses or replacement launches, PID-tripwire containment, benign near-limit completion, fail-closed supervisor restart recovery, and p95 trigger-to-empty latency below 500 ms.

Run the matrix only on a disposable or dedicated Linux test host:

```sh
sudo python3 scripts/run_native_matrix.py --fork-race-repetitions 100 --benign-repetitions 50 --restart-repetitions 20 --socket-attempts 100 --output ./native-matrix.json
```

The evidence establishes behavior only for the tested environment and commit. It does not establish universal Linux compatibility or any unsupported security claim.
