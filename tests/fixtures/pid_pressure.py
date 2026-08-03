"""Keep attempting forks until the cgroup PID controller reports a max event."""

from __future__ import annotations

import os
import time


end = time.monotonic() + 20
while time.monotonic() < end:
    try:
        child = os.fork()
    except OSError:
        time.sleep(0.002)
        continue
    if child == 0:
        time.sleep(20)
        os._exit(0)
    time.sleep(0.002)
