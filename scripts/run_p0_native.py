"""Run the release-blocking native Priority-0 adversarial campaigns.

The root controller is only an oracle and fixture coordinator.  Every target
process runs as the dedicated workload identity and wins only while it retains
a complete supported content/runtime profile.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
import pwd
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CLI = Path("/usr/local/bin/eggcracker")
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
POLICY = Path("/etc/lumi-eggcracker/policy.json")
INSTALLED_ARTIFACT = Path("/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz")
SCHEMA = "lumi-eggcracker.p0-native.v1"
PROFILE = "content.gguf-llama"
HOLD_SECONDS = 180


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def gguf(seed: int) -> bytes:
    # Plausible GGUF v3: one tensor, no metadata, plus the minimum tensor
    # prefix required by the bounded public validator.
    return b"GGUF" + (3).to_bytes(4, "little") + (1).to_bytes(
        8, "little"
    ) + (0).to_bytes(8, "little") + bytes([seed & 0xFF]) * 12


def write_all(descriptor: int, value: bytes) -> None:
    pending = memoryview(value)
    while pending:
        written = os.write(descriptor, pending)
        if written < 1:
            raise OSError("fixture write made no progress")
        pending = pending[written:]
    os.lseek(descriptor, 0, os.SEEK_SET)


def copy_to_descriptor(source: Path, descriptor: int) -> None:
    with source.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            write_all_at_current_offset(descriptor, block)
    os.lseek(descriptor, 0, os.SEEK_SET)


def write_all_at_current_offset(descriptor: int, value: bytes) -> None:
    pending = memoryview(value)
    while pending:
        written = os.write(descriptor, pending)
        if written < 1:
            raise OSError("fixture write made no progress")
        pending = pending[written:]


def wait_gate(path: Path, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.005)
    raise RuntimeError("fixture gate did not open")


def marker(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def map_runtime(descriptor: int) -> mmap.mmap:
    return mmap.mmap(
        descriptor,
        0,
        flags=mmap.MAP_PRIVATE,
        prot=mmap.PROT_READ | mmap.PROT_EXEC,
    )


def fixture_evidence(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--gate", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--pre-fds", type=int, default=0)
    parser.add_argument("--post-fds", type=int, default=0)
    parser.add_argument("--decoy-maps", type=int, default=0)
    args = parser.parse_args(argv)

    # CPython's mmap object retains its own duplicate of the backing
    # descriptor, so each decoy consumes two slots until teardown.
    required_descriptors = (
        args.pre_fds + args.post_fds + args.decoy_maps * 2 + 64
    )
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if required_descriptors > hard_limit:
        raise RuntimeError("fixture descriptor requirement exceeds the hard limit")
    if soft_limit < required_descriptors:
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (required_descriptors, hard_limit),
        )

    descriptors: list[int] = []
    mappings: list[mmap.mmap] = []
    for _ in range(args.pre_fds):
        descriptors.append(os.open("/dev/null", os.O_RDONLY))
    marker(args.ready, {"pid": os.getpid(), "state": "READY"})
    wait_gate(args.gate)

    if args.mode in {"regular", "high-fd", "high-maps"}:
        model_descriptor = os.open(args.model, os.O_RDONLY)
    elif args.mode in {"memfd-model", "sealed-memfd-model"}:
        flags = getattr(os, "MFD_ALLOW_SEALING", 2)
        model_descriptor = os.memfd_create("p0-model", flags=flags)
        write_all(model_descriptor, args.model.read_bytes())
        if args.mode == "sealed-memfd-model":
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0x0001)
                | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
            )
            fcntl.fcntl(model_descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
    elif args.mode == "otmpfile-model":
        model_descriptor = os.open(
            args.work,
            os.O_TMPFILE | os.O_RDWR,
            0o600,
        )
        write_all(model_descriptor, args.model.read_bytes())
    elif args.mode == "deleted-model":
        private = args.work / f"deleted-model-{os.getpid()}"
        private.write_bytes(args.model.read_bytes())
        model_descriptor = os.open(private, os.O_RDONLY)
        private.unlink()
    elif args.mode == "unlink-model":
        model_descriptor = os.open(args.model, os.O_RDONLY)
        args.model.unlink()
    else:
        model_descriptor = os.open(args.model, os.O_RDONLY)
    descriptors.append(model_descriptor)

    for _ in range(args.post_fds):
        descriptors.append(os.open("/dev/null", os.O_RDONLY))
    for index in range(args.decoy_maps):
        decoy = args.work / f"map-{os.getpid()}-{index}"
        descriptor = os.open(decoy, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.ftruncate(descriptor, 4096)
        mappings.append(
            mmap.mmap(
                descriptor,
                4096,
                flags=mmap.MAP_PRIVATE,
                prot=mmap.PROT_READ | mmap.PROT_EXEC,
            )
        )
        descriptors.append(descriptor)

    if args.mode in {"memfd-runtime", "otmpfile-runtime", "deleted-runtime", "unlink-runtime"}:
        if args.mode == "memfd-runtime":
            runtime_descriptor = os.memfd_create("p0-runtime", flags=0)
        elif args.mode == "otmpfile-runtime":
            runtime_descriptor = os.open(
                args.work,
                os.O_TMPFILE | os.O_RDWR,
                0o700,
            )
        elif args.mode == "unlink-runtime":
            runtime_descriptor = os.open(args.runtime, os.O_RDONLY)
        else:
            private_runtime = args.work / f"deleted-runtime-{os.getpid()}"
            shutil.copyfile(args.runtime, private_runtime)
            runtime_descriptor = os.open(private_runtime, os.O_RDONLY)
            private_runtime.unlink()
        if args.mode in {"memfd-runtime", "otmpfile-runtime"}:
            copy_to_descriptor(args.runtime, runtime_descriptor)
        mappings.append(map_runtime(runtime_descriptor))
        descriptors.append(runtime_descriptor)
        if args.mode == "unlink-runtime":
            args.runtime.unlink()
    else:
        runtime_descriptor = os.open(args.runtime, os.O_RDONLY)
        mappings.append(map_runtime(runtime_descriptor))
        descriptors.append(runtime_descriptor)

    marker(
        args.ready.with_suffix(".armed"),
        {
            "descriptors": len(descriptors),
            "maps": len(mappings),
            "pid": os.getpid(),
            "state": "ARMED",
        },
    )
    time.sleep(HOLD_SECONDS)
    return 0


def fixture_storm(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", required=True, type=int)
    parser.add_argument("--role", choices=("complete", "content"), required=True)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--gate", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    args = parser.parse_args(argv)
    children: list[int] = []
    for _ in range(args.count):
        pid = os.fork()
        if pid:
            children.append(pid)
            continue
        wait_gate(args.gate)
        descriptors = [os.open(args.model, os.O_RDONLY)]
        mappings: list[mmap.mmap] = []
        if args.role == "complete":
            runtime_descriptor = os.open(args.runtime, os.O_RDONLY)
            descriptors.append(runtime_descriptor)
            mappings.append(map_runtime(runtime_descriptor))
        time.sleep(HOLD_SECONDS)
        os._exit(0)
    marker(
        args.ready,
        {"children": children, "count": len(children), "pid": os.getpid(), "state": "READY"},
    )
    time.sleep(HOLD_SECONDS)
    return 0


def execveat(descriptor: int, command: list[str], environment: dict[str, str]) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    argv = (ctypes.c_char_p * (len(command) + 1))(
        *(item.encode() for item in command),
        None,
    )
    env_values = [f"{key}={value}".encode() for key, value in environment.items()]
    envp = (ctypes.c_char_p * (len(env_values) + 1))(*env_values, None)
    result = libc.syscall(
        322,  # x86-64 SYS_execveat
        descriptor,
        ctypes.c_char_p(b""),
        argv,
        envp,
        0x1000,  # AT_EMPTY_PATH
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    raise RuntimeError("execveat unexpectedly returned")


def runner_command(executable: str, model: str) -> list[str]:
    return [
        executable,
        "-m",
        model,
        "-p",
        "Name a Linux cgroup property.",
        "-n",
        "4096",
        "-t",
        "4",
        "-tb",
        "4",
        "-c",
        "512",
        "--simple-io",
        "--single-turn",
        "--no-warmup",
        "--no-display-prompt",
        "--ignore-eos",
        "--seed",
        "1234",
    ]


def fixture_exec(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--gate", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args(argv)
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }

    if args.mode in {"procfd-model", "sealed-procfd-model"}:
        flags = getattr(os, "MFD_ALLOW_SEALING", 2)
        model_descriptor = os.memfd_create("p0-real-model", flags=flags)
        copy_to_descriptor(args.model, model_descriptor)
        if args.mode == "sealed-procfd-model":
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0x0001)
                | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
            )
            fcntl.fcntl(model_descriptor, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
        os.set_inheritable(model_descriptor, True)
        marker(args.ready, {"pid": os.getpid(), "state": "READY"})
        wait_gate(args.gate)
        model = f"/proc/self/fd/{model_descriptor}"
        os.execve(args.runtime, runner_command(str(args.runtime), model), environment)

    copied = False
    if args.mode in {"memfd-exec", "execveat-memfd"}:
        runtime_descriptor = os.memfd_create("p0-executable", flags=0)
    elif args.mode == "otmpfile-exec":
        writer = os.open(args.work, os.O_TMPFILE | os.O_RDWR, 0o700)
        try:
            copy_to_descriptor(args.runtime, writer)
            os.fchmod(writer, 0o700)
            # A regular O_TMPFILE held open for writing cannot be executed
            # (ETXTBSY).  Reopen the same anonymous inode read-only through
            # procfs before dropping the writer, preserving its pathless
            # identity while producing a valid execution fixture.
            runtime_descriptor = os.open(f"/proc/self/fd/{writer}", os.O_RDONLY)
            copied = True
        finally:
            os.close(writer)
    elif args.mode == "deleted-exec":
        private = args.work / f"deleted-exec-{os.getpid()}"
        shutil.copyfile(args.runtime, private)
        os.chmod(private, 0o700)
        runtime_descriptor = os.open(private, os.O_RDONLY)
        private.unlink()
    else:
        raise RuntimeError("unknown pathless execution mode")
    if args.mode != "deleted-exec" and not copied:
        copy_to_descriptor(args.runtime, runtime_descriptor)
        os.fchmod(runtime_descriptor, 0o700)
    marker(args.ready, {"pid": os.getpid(), "state": "READY"})
    wait_gate(args.gate)
    command = runner_command("p0-pathless-runtime", str(args.model))
    if args.mode == "execveat-memfd":
        execveat(runtime_descriptor, command, environment)
    os.execve(runtime_descriptor, command, environment)
    raise RuntimeError("fexecve unexpectedly returned")


def control(argv: list[str], *, operator: str | None = None, environment: dict[str, str] | None = None) -> tuple[int, str, str]:
    command = [str(CLI), *argv]
    if operator is not None:
        command = ["/usr/sbin/runuser", "-u", operator, "--", *command]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env=environment,
    )
    return result.returncode, result.stdout, result.stderr


def json_control(argv: list[str], *, operator: str | None = None) -> dict[str, Any]:
    code, stdout, stderr = control(argv, operator=operator)
    if code:
        raise RuntimeError(stderr.strip() or stdout.strip() or "Eggcracker control failed")
    value = json.loads(stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker control response is invalid")
    return value


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def alive(pid: int) -> bool:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    except OSError:
        return False
    return len(fields) > 2 and fields[2] != "Z"


def wait_ready(path: Path, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            time.sleep(0.01)
            continue
        if isinstance(value, dict):
            return value
    raise RuntimeError(f"fixture readiness failed for {path.name}")


def receipts_after(before: set[Path]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in sorted(set(DETECTIONS.glob("*.json")) - before):
        result.append(json.loads(path.read_text(encoding="utf-8")))
    return result


def validate_receipts(
    values: list[dict[str, Any]],
    *,
    expected: int,
    source_commit: str,
) -> list[float]:
    if len(values) != expected:
        raise RuntimeError(f"expected {expected} receipts, observed {len(values)}")
    latencies: list[float] = []
    event_ids: set[str] = set()
    for value in values:
        containment = value.get("containment", {})
        if (
            value.get("result") != "TERMINATED"
            or value.get("source_commit") != source_commit
            or value.get("detector", {}).get("profile") != PROFILE
            or containment.get("root_populated") != 0
            or containment.get("surviving_pids") != []
            or "cgroup.kill" not in str(containment.get("primitive"))
        ):
            raise RuntimeError("receipt did not prove exact supported-profile containment")
        event_id = value.get("event_id")
        if not isinstance(event_id, str) or event_id in event_ids:
            raise RuntimeError("receipt event identity is invalid or duplicated")
        event_ids.add(event_id)
        latencies.append(float(containment["trigger_to_empty_ms"]))
    return latencies


def launch_fixture(
    script: Path,
    workload: str,
    subcommand: str,
    arguments: list[str],
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "/usr/sbin/runuser",
            "-u",
            workload,
            "--",
            "/usr/bin/python3",
            "-I",
            "-S",
            str(script),
            subcommand,
            *arguments,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_for_kills(
    target_pids: list[int],
    before: set[Path],
    expected: int,
    timeout: float,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        values = receipts_after(before)
        if len(values) >= expected and not any(alive(pid) for pid in target_pids):
            return values
        time.sleep(0.05)
    raise RuntimeError(
        f"containment timed out: receipts={len(receipts_after(before))}, "
        f"survivors={sum(alive(pid) for pid in target_pids)}"
    )


class Campaign:
    def __init__(
        self,
        *,
        script: Path,
        workload: str,
        operator: str,
        runtime: Path,
        real_model: Path,
        output: Path,
    ) -> None:
        self.workload = workload
        self.operator = operator
        self.runtime = runtime
        self.real_model = real_model
        self.output = output
        self.policy = json.loads(POLICY.read_text(encoding="utf-8"))
        token = secrets.token_hex(8)
        self.root = Path(f"/opt/lumi-eggcracker-p0-{token}")
        self.work = self.root / "work"
        self.root.mkdir(mode=0o755)
        self.work.mkdir(mode=0o733)
        os.chmod(self.work, 0o733)
        self.script = self.root / "fixture.py"
        shutil.copyfile(script, self.script)
        self.script.chmod(0o555)
        self.model = self.root / "synthetic.gguf"
        self.model.write_bytes(gguf(1))
        self.model.chmod(0o444)
        self.canary = subprocess.Popen(
            ["/usr/sbin/runuser", "-u", workload, "--", "/bin/sleep", "900"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.results: dict[str, Any] = {
            "approval_material_substitution": [],
            "pathless_deleted": [],
            "saturation": [],
        }

    def assert_canary(self) -> None:
        if self.canary.poll() is not None:
            raise RuntimeError("unrelated workload-identity canary was terminated")

    def doctor(self) -> dict[str, Any]:
        value = json_control(["doctor"])
        if value.get("result") != "PASS":
            raise RuntimeError("Eggcracker health did not recover to PASS")
        return value

    def one_evidence(
        self,
        mode: str,
        *,
        model: Path | None = None,
        runtime: Path | None = None,
        pre_fds: int = 0,
        post_fds: int = 0,
        decoy_maps: int = 0,
        timeout: float = 90,
    ) -> dict[str, Any]:
        token = secrets.token_hex(6)
        gate = self.root / f"gate-{token}"
        ready = self.work / f"ready-{token}.json"
        before = set(DETECTIONS.glob("*.json"))
        process = launch_fixture(
            self.script,
            self.workload,
            "fixture-evidence",
            [
                "--mode",
                mode,
                "--model",
                str(model or self.model),
                "--runtime",
                str(runtime or self.runtime),
                "--gate",
                str(gate),
                "--ready",
                str(ready),
                "--work",
                str(self.work),
                "--pre-fds",
                str(pre_fds),
                "--post-fds",
                str(post_fds),
                "--decoy-maps",
                str(decoy_maps),
            ],
        )
        try:
            identity = wait_ready(ready)
            gate.write_bytes(b"go\n")
            gate.chmod(0o444)
            receipts = wait_for_kills(
                [int(identity["pid"])],
                before,
                1,
                timeout,
            )
            latencies = validate_receipts(
                receipts,
                expected=1,
                source_commit=self.policy["source_commit"],
            )
            self.assert_canary()
            return {
                "case": mode,
                "result": "PASS",
                "trigger_to_empty_ms": latencies[0],
            }
        finally:
            stop(process)

    def one_exec(self, mode: str, timeout: float = 150) -> dict[str, Any]:
        token = secrets.token_hex(6)
        gate = self.root / f"gate-{token}"
        ready = self.work / f"ready-{token}.json"
        before = set(DETECTIONS.glob("*.json"))
        process = launch_fixture(
            self.script,
            self.workload,
            "fixture-exec",
            [
                "--mode",
                mode,
                "--model",
                str(self.real_model),
                "--runtime",
                str(self.runtime),
                "--gate",
                str(gate),
                "--ready",
                str(ready),
                "--work",
                str(self.work),
            ],
        )
        try:
            identity = wait_ready(ready, timeout=120)
            gate.write_bytes(b"go\n")
            gate.chmod(0o444)
            receipts = wait_for_kills(
                [int(identity["pid"])],
                before,
                1,
                timeout,
            )
            latencies = validate_receipts(
                receipts,
                expected=1,
                source_commit=self.policy["source_commit"],
            )
            self.assert_canary()
            return {
                "case": mode,
                "result": "PASS",
                "trigger_to_empty_ms": latencies[0],
            }
        finally:
            stop(process)

    def wave(self, count: int) -> dict[str, Any]:
        token = secrets.token_hex(6)
        gate = self.root / f"wave-gate-{token}"
        before = set(DETECTIONS.glob("*.json"))
        processes: list[subprocess.Popen[bytes]] = []
        ready_paths: list[Path] = []
        try:
            for index in range(count):
                ready = self.work / f"wave-{token}-{index}.json"
                ready_paths.append(ready)
                processes.append(
                    launch_fixture(
                        self.script,
                        self.workload,
                        "fixture-evidence",
                        [
                            "--mode",
                            "regular",
                            "--model",
                            str(self.model),
                            "--runtime",
                            str(self.runtime),
                            "--gate",
                            str(gate),
                            "--ready",
                            str(ready),
                            "--work",
                            str(self.work),
                        ],
                    )
                )
            identities = [wait_ready(path) for path in ready_paths]
            gate.write_bytes(b"go\n")
            gate.chmod(0o444)
            receipts = wait_for_kills(
                [int(item["pid"]) for item in identities],
                before,
                count,
                120,
            )
            latencies = validate_receipts(
                receipts,
                expected=count,
                source_commit=self.policy["source_commit"],
            )
            self.assert_canary()
            return {
                "case": f"unrelated-complete-wave-{count}",
                "max_trigger_to_empty_ms": max(latencies),
                "receipts": len(receipts),
                "result": "PASS",
            }
        finally:
            for process in processes:
                stop(process)

    def storm(self, count: int, role: str) -> dict[str, Any]:
        token = secrets.token_hex(6)
        gate = self.root / f"storm-gate-{token}"
        ready = self.work / f"storm-{token}.json"
        before = set(DETECTIONS.glob("*.json"))
        process = launch_fixture(
            self.script,
            self.workload,
            "fixture-storm",
            [
                "--count",
                str(count),
                "--role",
                role,
                "--model",
                str(self.model),
                "--runtime",
                str(self.runtime),
                "--gate",
                str(gate),
                "--ready",
                str(ready),
            ],
        )
        try:
            identity = wait_ready(ready)
            children = [int(item) for item in identity["children"]]
            if len(children) != count:
                raise RuntimeError("storm did not create the requested process count")
            gate.write_bytes(b"go\n")
            gate.chmod(0o444)
            if role == "complete":
                receipts = wait_for_kills(
                    [int(identity["pid"]), *children],
                    before,
                    1,
                    120,
                )
                validate_receipts(
                    receipts,
                    expected=1,
                    source_commit=self.policy["source_commit"],
                )
                if int(receipts[0].get("capture", {}).get("captured_processes", 0)) < count + 1:
                    raise RuntimeError("related component receipt omitted armed processes")
            else:
                time.sleep(12)
                if receipts_after(before) or not all(alive(pid) for pid in children):
                    raise RuntimeError("partial-profile storm was killed or produced a receipt")
            self.assert_canary()
            return {
                "case": f"related-{role}-storm-{count}",
                "processes": count,
                "receipts": len(receipts_after(before)),
                "result": "PASS",
            }
        finally:
            stop(process)

    def reject_mutation(self, kind: str) -> dict[str, Any]:
        root = self.root / f"approval-{kind}-{secrets.token_hex(4)}"
        root.mkdir(mode=0o755)
        model = root / "model.gguf"
        hostile = root / "hostile.gguf"
        model.write_bytes(gguf(10))
        hostile.write_bytes(gguf(20))
        model.chmod(0o444)
        hostile.chmod(0o444)
        name = f"p0-{kind}-{secrets.token_hex(4)}"
        run_name = f"p0-run-{kind}-{secrets.token_hex(4)}"
        command = [str(self.runtime), "-m", str(model), "--version"]
        json_control(
            [
                "approve",
                "--name",
                name,
                "--uid",
                str(self.policy["workload_uid"]),
                "--",
                *command,
            ]
        )
        mounted = False
        try:
            if kind == "rename":
                os.replace(hostile, model)
            elif kind == "hardlink":
                model.unlink()
                os.link(hostile, model)
            elif kind == "symlink":
                model.unlink()
                model.symlink_to(hostile)
            elif kind == "exchange":
                libc = ctypes.CDLL(None, use_errno=True)
                result = libc.renameat2(
                    -100,
                    os.fsencode(model),
                    -100,
                    os.fsencode(hostile),
                    2,
                )
                if result:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))
            elif kind == "bind":
                result = subprocess.run(
                    ["/usr/bin/mount", "--bind", str(hostile), str(model)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=30,
                )
                if result.returncode:
                    raise RuntimeError(result.stderr.strip() or "bind mount failed")
                mounted = True
            else:
                raise RuntimeError("unknown approval substitution")
            code, _stdout, _stderr = control(
                [
                    "start",
                    "--name",
                    run_name,
                    "--max-pids",
                    "32",
                    "--max-memory-mib",
                    "1024",
                    "--cpu-quota-percent",
                    "400",
                    "--",
                    *command,
                ],
                operator=self.operator,
            )
            if code == 0:
                raise RuntimeError(f"{kind} material substitution inherited approval")
            self.assert_canary()
            return {"case": f"model-{kind}-substitution", "result": "PASS"}
        finally:
            if mounted:
                subprocess.run(
                    ["/usr/bin/umount", str(model)],
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            control(["revoke", "--name", name])

    def overlay_mutation(self) -> dict[str, Any]:
        root = self.root / f"overlay-{secrets.token_hex(4)}"
        lower, upper, work, merged = (
            root / "lower",
            root / "upper",
            root / "work",
            root / "merged",
        )
        for path in (lower, upper, work, merged):
            path.mkdir(parents=True, mode=0o755)
        model = lower / "model.gguf"
        model.write_bytes(gguf(30))
        model.chmod(0o444)
        result = subprocess.run(
            [
                "/usr/bin/mount",
                "-t",
                "overlay",
                "overlay",
                "-o",
                f"lowerdir={lower},upperdir={upper},workdir={work}",
                str(merged),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "overlay mount failed")
        name = f"p0-overlay-{secrets.token_hex(4)}"
        run_name = f"p0-run-overlay-{secrets.token_hex(4)}"
        merged_model = merged / "model.gguf"
        command = [str(self.runtime), "-m", str(merged_model), "--version"]
        try:
            json_control(
                [
                    "approve",
                    "--name",
                    name,
                    "--uid",
                    str(self.policy["workload_uid"]),
                    "--",
                    *command,
                ]
            )
            merged_model.chmod(0o644)
            merged_model.write_bytes(gguf(31))
            merged_model.chmod(0o444)
            code, _stdout, _stderr = control(
                [
                    "start",
                    "--name",
                    run_name,
                    "--max-pids",
                    "32",
                    "--max-memory-mib",
                    "1024",
                    "--cpu-quota-percent",
                    "400",
                    "--",
                    *command,
                ],
                operator=self.operator,
            )
            if code == 0:
                raise RuntimeError("overlay material substitution inherited approval")
            return {"case": "model-overlay-copy-up-substitution", "result": "PASS"}
        finally:
            control(["revoke", "--name", name])
            subprocess.run(
                ["/usr/bin/umount", str(merged)],
                capture_output=True,
                check=False,
                timeout=30,
            )

    def environment_injection(self) -> dict[str, Any]:
        root = self.root / f"environment-{secrets.token_hex(4)}"
        inputs, outputs, hostile = root / "inputs", root / "outputs", root / "hostile"
        inputs.mkdir(parents=True, mode=0o755)
        outputs.mkdir(mode=0o733)
        hostile.mkdir(mode=0o755)
        os.chmod(outputs, 0o733)
        script = inputs / "approved.py"
        output = outputs / "result"
        marker_path = outputs / "sitecustomize-loaded"
        script.write_text(
            "import pathlib,time\n"
            "try:\n import p0_untrusted\n state='UNSAFE'\n"
            "except ModuleNotFoundError:\n state='SAFE'\n"
            f"pathlib.Path({str(output)!r}).write_text(state)\n"
            "time.sleep(120)\n",
            encoding="utf-8",
        )
        script.chmod(0o444)
        (hostile / "p0_untrusted.py").write_text("VALUE='hostile'\n", encoding="utf-8")
        (hostile / "sitecustomize.py").write_text(
            f"open({str(marker_path)!r},'w').write('loaded')\n",
            encoding="utf-8",
        )
        python = Path("/opt/lumi-eggcracker-torch-smoke/bin/python")
        command = [str(python), str(script), str(output)]
        name = f"p0-env-{secrets.token_hex(4)}"
        run_name = f"p0-run-env-{secrets.token_hex(4)}"
        json_control(
            [
                "approve",
                "--name",
                name,
                "--uid",
                str(self.policy["workload_uid"]),
                "--",
                *command,
            ]
        )
        started = False
        try:
            environment = dict(os.environ)
            environment.update(
                {
                    "BASH_ENV": str(hostile / "sitecustomize.py"),
                    "LD_AUDIT": "/definitely/absent.so",
                    "LD_LIBRARY_PATH": str(hostile),
                    "LD_PRELOAD": "/definitely/absent.so",
                    "PYTHONPATH": str(hostile),
                    "PYTHONSTARTUP": str(hostile / "sitecustomize.py"),
                    "PYTHONUSERBASE": str(hostile),
                }
            )
            code, stdout, stderr = control(
                [
                    "start",
                    "--name",
                    run_name,
                    "--max-pids",
                    "32",
                    "--max-memory-mib",
                    "1024",
                    "--cpu-quota-percent",
                    "400",
                    "--",
                    *command,
                ],
                operator=self.operator,
                environment=environment,
            )
            if code:
                raise RuntimeError(stderr.strip() or stdout.strip() or "approved start failed")
            started = True
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not output.is_file():
                time.sleep(0.02)
            if output.read_text(encoding="utf-8") != "SAFE" or marker_path.exists():
                raise RuntimeError("operator-controlled launch environment reached the workload")
            return {"case": "python-loader-and-import-environment-injection", "result": "PASS"}
        finally:
            if started:
                receipt = self.work / f"operator-{secrets.token_hex(6)}.json"
                control(
                    ["kill", "--name", run_name, "--receipt", str(receipt)],
                    operator=self.operator,
                )
                receipt.unlink(missing_ok=True)
            control(["revoke", "--name", name])

    def approved_parent_unapproved_child(self) -> dict[str, Any]:
        root = self.root / f"parent-child-{secrets.token_hex(4)}"
        root.mkdir(mode=0o755)
        gate = root / "gate"
        gate.write_bytes(b"go\n")
        gate.chmod(0o444)
        ready = self.work / f"parent-child-{secrets.token_hex(4)}.json"
        parent = root / "approved-parent.py"
        parent.write_text(
            "import subprocess,time\n"
            "subprocess.Popen("
            + repr(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    str(self.script),
                    "fixture-evidence",
                    "--mode",
                    "regular",
                    "--model",
                    str(self.model),
                    "--runtime",
                    str(self.runtime),
                    "--gate",
                    str(gate),
                    "--ready",
                    str(ready),
                    "--work",
                    str(self.work),
                ]
            )
            + ")\n"
            "time.sleep(120)\n",
            encoding="utf-8",
        )
        parent.chmod(0o444)
        python = Path("/opt/lumi-eggcracker-torch-smoke/bin/python")
        command = [str(python), str(parent)]
        name = f"p0-parent-{secrets.token_hex(4)}"
        run_name = f"p0-run-parent-{secrets.token_hex(4)}"
        json_control(
            [
                "approve",
                "--name",
                name,
                "--uid",
                str(self.policy["workload_uid"]),
                "--",
                *command,
            ]
        )
        before = set(DETECTIONS.glob("*.json"))
        started = False
        try:
            response = json_control(
                [
                    "start",
                    "--name",
                    run_name,
                    "--max-pids",
                    "64",
                    "--max-memory-mib",
                    "2048",
                    "--cpu-quota-percent",
                    "400",
                    "--",
                    *command,
                ],
                operator=self.operator,
            )
            started = True
            if response.get("state") != "RUNNING":
                raise RuntimeError("approved parent did not start")
            wait_ready(ready)
            deadline = time.monotonic() + 90
            receipts: list[dict[str, Any]] = []
            while time.monotonic() < deadline:
                receipts = receipts_after(before)
                if receipts:
                    break
                time.sleep(0.05)
            validate_receipts(
                receipts,
                expected=1,
                source_commit=self.policy["source_commit"],
            )
            status = json_control(["status", "--name", run_name], operator=self.operator)
            if status.get("state") != "TERMINATED":
                raise RuntimeError("approved parent survived its unapproved supported child")
            started = False
            self.assert_canary()
            return {"case": "approved-parent-unapproved-supported-child", "result": "PASS"}
        finally:
            if started:
                receipt = self.work / f"operator-{secrets.token_hex(6)}.json"
                control(
                    ["kill", "--name", run_name, "--receipt", str(receipt)],
                    operator=self.operator,
                )
                receipt.unlink(missing_ok=True)
            control(["revoke", "--name", name])

    def run(self) -> dict[str, Any]:
        self.doctor()
        for kind in ("rename", "exchange", "hardlink", "symlink", "bind"):
            self.results["approval_material_substitution"].append(
                self.reject_mutation(kind)
            )
        self.results["approval_material_substitution"].append(self.overlay_mutation())
        self.results["approval_material_substitution"].append(
            self.environment_injection()
        )
        self.results["approval_material_substitution"].append(
            self.approved_parent_unapproved_child()
        )

        for mode in (
            "memfd-model",
            "sealed-memfd-model",
            "otmpfile-model",
            "deleted-model",
            "memfd-runtime",
            "otmpfile-runtime",
            "deleted-runtime",
        ):
            self.results["pathless_deleted"].append(self.one_evidence(mode))
        for mode in (
            "memfd-exec",
            "execveat-memfd",
            "otmpfile-exec",
            "deleted-exec",
            "procfd-model",
            "sealed-procfd-model",
        ):
            self.results["pathless_deleted"].append(self.one_exec(mode))

        for count in (17, 32, 64):
            self.results["saturation"].append(self.wave(count))
        self.results["saturation"].append(self.storm(96, "complete"))
        self.results["saturation"].append(self.storm(512, "content"))
        self.results["saturation"].append(
            self.one_evidence("high-fd", pre_fds=700, post_fds=324, timeout=120)
        )
        self.results["saturation"].append(
            self.one_evidence("high-maps", decoy_maps=600, timeout=180)
        )
        final_doctor = self.doctor()
        self.assert_canary()
        return {
            "artifact_sha256": digest(INSTALLED_ARTIFACT),
            "doctor": final_doctor,
            "families": self.results,
            "result": "PASS",
            "schema_version": SCHEMA,
            "source_commit": self.policy["source_commit"],
            "version": self.policy["version"],
        }

    def close(self) -> None:
        stop(self.canary)
        if self.root.exists() and not self.root.is_symlink():
            shutil.rmtree(self.root)


def campaign_main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        raise SystemExit("P0 native campaign must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--workload-user", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--real-model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if (
        args.output.exists()
        or args.output.is_symlink()
        or not args.output.parent.is_dir()
        or any(path.is_symlink() or not path.is_file() for path in (args.runtime, args.real_model))
    ):
        raise SystemExit("P0 output must be new and fixtures must be regular files")
    pwd.getpwnam(args.workload_user)
    pwd.getpwnam(args.operator)
    campaign = Campaign(
        script=Path(__file__).resolve(),
        workload=args.workload_user,
        operator=args.operator,
        runtime=args.runtime,
        real_model=args.real_model,
        output=args.output,
    )
    try:
        value = campaign.run()
        args.output.write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"output": str(args.output), "result": "PASS"}, sort_keys=True))
        return 0
    except BaseException as error:
        if not args.output.exists():
            args.output.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "result": "FAIL",
                        "schema_version": SCHEMA,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        raise
    finally:
        campaign.close()


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "fixture-evidence":
        return fixture_evidence(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "fixture-storm":
        return fixture_storm(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "fixture-exec":
        return fixture_exec(sys.argv[2:])
    return campaign_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
