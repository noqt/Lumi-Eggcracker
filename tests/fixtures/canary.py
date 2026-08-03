"""An unrelated process that stays alive until the root harness cleans it up."""

from __future__ import annotations

import signal
import time


signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(1)
