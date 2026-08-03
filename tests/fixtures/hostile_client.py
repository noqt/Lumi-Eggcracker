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
socket_path = "/run/lumi-nutcracker/control.sock"
successes = 0
replacement_successes = 0
for index in range(attempts):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.1)
            connection.connect(socket_path)
        successes += 1
    except OSError:
        pass
result = subprocess.run(["/usr/local/bin/nutcracker", "start", "--name", "replacement-hostile", "--max-pids", "4", "--", "/bin/sleep", "2"], capture_output=True, text=True, check=False)
if result.returncode == 0:
    replacement_successes += 1
output.write_text(json.dumps({"connection_successes": successes, "replacement_successes": replacement_successes, "uid": os.getuid()}) + "\n", encoding="utf-8")
