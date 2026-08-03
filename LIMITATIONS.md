# Limitations

Lumi Nutcracker protects only commands explicitly launched through its local root supervisor. It does not inspect the host for AI, agent, malware or intrusion activity, and it cannot attach an existing process to its protected boundary.

The product terminates the exact cgroup it created. It does not provide network isolation, credential isolation, filesystem isolation, container isolation, virtual-machine isolation or host isolation. It is not an EDR, antivirus or general malware-prevention product.

The PID tripwire is a cgroup process-count ceiling. It is not behavioural detection, a resource-governance system or AI attribution. A supervisor restart intentionally fail-closed terminates active owned workloads rather than continuing them without a live watcher.

Qualification is limited to the published tested native Linux environment. Passing local tests does not establish universal Linux compatibility or production readiness for workloads outside that environment.
