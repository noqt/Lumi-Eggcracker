"""Bounded unmanaged fixture that presents as a llama.cpp-style invocation."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

children: list[int] = []


def stop(*_: object) -> None:
    for child in children:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
    raise SystemExit(0)


signal.signal(signal.SIGTERM, stop)
for _ in range(32):
    child = os.fork()
    if child == 0:
        while True:
            time.sleep(1)
    children.append(child)
model = Path(sys.argv[-1]).with_suffix(".gguf")
with model.open("rb"):
    while True:
        time.sleep(1)
