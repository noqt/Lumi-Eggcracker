"""Tiny workload-side pre-exec gate; it has no supervisor privileges."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .seccomp_notify import install_exec_filter, send_listener


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="eggcracker internal-gate")
    parser.add_argument("--fifo", required=True, type=Path)
    parser.add_argument("--exec-socket", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise SystemExit("missing gated command")
    listener = -1
    if args.exec_socket is not None:
        try:
            # The filter is installed before the gate is opened.  This means
            # the first target image and every descendant are mediated by the
            # same listener; there is no post-exec observation gap.
            listener = install_exec_filter()
            send_listener(args.exec_socket, listener)
        except (OSError, RuntimeError) as error:
            raise SystemExit(f"execution boundary unavailable: {error}") from error
        finally:
            if listener >= 0:
                os.close(listener)
    with args.fifo.open("rb", buffering=0) as gate:
        if gate.read(3) != b"GO\n":
            raise SystemExit("invalid launch-gate release")
    os.execvp(command[0], command)
    return 127
