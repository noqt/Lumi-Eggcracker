"""Bounded hostile workload that keeps creating descendants until killed."""

from __future__ import annotations

import os
import signal
import sys
import time

mode = sys.argv[1] if len(sys.argv) == 2 else "fork"
signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode.startswith("bounded"):
    for _ in range(8):
        child = os.fork()
        if child == 0:
            if mode == "bounded-session":
                try:
                    os.setsid()
                except OSError:
                    pass
            if mode == "bounded-replace":
                try:
                    if os.fork() == 0:
                        time.sleep(30)
                        os._exit(0)
                except OSError:
                    pass
            time.sleep(30)
            os._exit(0)
    time.sleep(30)
    os._exit(0)
end = time.monotonic() + 30
while time.monotonic() < end:
    try:
        child = os.fork()
    except OSError:
        time.sleep(0.001)
        continue
    if child == 0:
        if mode == "session":
            try:
                os.setsid()
            except OSError:
                pass
        if mode == "replace":
            for _ in range(1):
                try:
                    if os.fork() == 0:
                        time.sleep(30)
                        os._exit(0)
                except OSError:
                    pass
        time.sleep(30)
        os._exit(0)
    time.sleep(0.1)
