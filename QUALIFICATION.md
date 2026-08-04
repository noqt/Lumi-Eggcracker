# Qualification

The 0.3.0 candidate is releasable only when its exact commit passes direct tests, the existing selected-workload matrix, the native autonomous-discovery matrix, and the content-recognition matrix on one Ubuntu VM.

Mandatory autonomous gates are: 100/100 unapproved fixture discoveries and complete tree kills, 100/100 unrelated-canary survivals, zero surviving bounded replacement attempts, zero reused-PID signals, 50/50 exact approved survivals, zero kills in the benign and partial-match matrices, zero workload policy/socket accesses, restart recovery, p95 qualifying-snapshot-to-stop below 100 ms, p95 fixture-start-to-stop below 500 ms, and p95 trigger-to-empty below 500 ms.

The candidate must also run five renamed-runner, extensionless-model unapproved/approved/unapproved real llama.cpp/Qwen content sequences, 100 renamed content fixture kills, 100 canary survivals, 50 exact disguised approvals and at least 300 benign model-handling launches with zero kills. It must cleanly install with discovery armed and completely uninstall. Evidence is specific to the tested commit and host; it does not establish universal AI identification.
