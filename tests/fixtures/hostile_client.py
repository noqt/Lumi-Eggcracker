"""Run as the workload identity and attempt forbidden supervisor access."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

output = Path(sys.argv[1])
attempts = int(sys.argv[2])
socket_paths = (
    "/run/lumi-eggcracker/query.sock",
    "/run/lumi-eggcracker/operator.sock",
    "/run/lumi-eggcracker/admin.sock",
)
successes = {path: 0 for path in socket_paths}
replacement_successes = 0
for socket_path in socket_paths:
    for index in range(attempts):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.1)
                connection.connect(socket_path)
            successes[socket_path] += 1
        except OSError:
            pass
result = subprocess.run(["/usr/local/bin/eggcracker", "start", "--name", "replacement-hostile", "--max-pids", "4", "--", "/bin/sleep", "2"], capture_output=True, text=True, check=False)
if result.returncode == 0:
    replacement_successes += 1
output.write_text(json.dumps({"connection_successes": successes, "replacement_successes": replacement_successes, "uid": os.getuid()}) + "\n", encoding="utf-8")
