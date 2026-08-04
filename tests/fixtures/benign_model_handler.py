"""Hold a valid model artifact open without loading an inference runtime."""

from __future__ import annotations

import hashlib
import mmap
import shutil
import sys
import time
from pathlib import Path


def main() -> int:
    model, mode = Path(sys.argv[1]), sys.argv[2]
    if mode == "map":
        with (
            model.open("rb") as handle,
            mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
        ):
            mapped[:64]
            time.sleep(0.7)
    elif mode == "copy":
        with model.open("rb") as source, (Path(sys.argv[3])).open("wb") as destination:
            shutil.copyfileobj(source, destination, length=64 * 1024)
            time.sleep(0.7)
    elif mode == "hash":
        with model.open("rb") as handle:
            hashlib.sha256(handle.read(1 << 20)).hexdigest()
            time.sleep(0.7)
    else:
        with model.open("rb") as handle:
            handle.read(1 << 20)
            time.sleep(0.7)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
