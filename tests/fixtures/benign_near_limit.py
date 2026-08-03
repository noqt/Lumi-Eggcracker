"""Create max_pids - 1 bounded processes and complete normally."""

from __future__ import annotations

import os
import sys
import time

children = max(0, int(sys.argv[1]) - 2)
pids: list[int] = []
for _ in range(children):
    child = os.fork()
    if child == 0:
        time.sleep(0.05)
        os._exit(0)
    pids.append(child)
for child in pids:
    os.waitpid(child, 0)
