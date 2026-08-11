"""Boundary Brief 1 split-process qualification harness.

This harness is deliberately outside the Eggcracker product package.  It
launches bounded local fixtures against an installed 0.4.0 candidate and
qualifies bounded content/runtime correlation, multi-target containment and
unrelated same-UID survival.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CLI = "/usr/local/bin/eggcracker"
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
QUERY_SOCKET = Path("/run/lumi-eggcracker/query.sock")
OPERATOR_SOCKET = Path("/run/lumi-eggcracker/operator.sock")
ADMIN_SOCKET = Path("/run/lumi-eggcracker/admin.sock")
CGROUP_ROOT = Path("/sys/fs/cgroup")
WORKLOAD_PYTHON = "/opt/lumi-eggcracker-torch-smoke/bin/python"
EXPECTED_PROFILE = "content.safetensors-pytorch"
EXPECTED_TRIGGER = "UNAPPROVED_SAFETENSORS_PYTORCH"
WORKER_SOURCE = r'''#!/usr/bin/env python3
"""Unprivileged fixture worker used only by boundary_b1.py."""

from __future__ import annotations

import json
import mmap
import os
import subprocess
import sys
import time
from pathlib import Path


ROLE = sys.argv[1]
ARTIFACT = Path(sys.argv[2])
CONTROL = Path(sys.argv[3])
OUT = Path(sys.argv[4])
SCRIPT = Path(sys.argv[5])
MODE = sys.argv[6] if len(sys.argv) > 6 else ""


def mark(name: str, **extra: object) -> None:
    value = {"pid": os.getpid(), **extra}
    (OUT / name).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def wait_for_stop() -> None:
    while not CONTROL.exists():
        time.sleep(0.01)
    while CONTROL.read_text(encoding="ascii").strip() != "stop":
        time.sleep(0.01)


def runtime() -> None:
    import torch

    # Touch a tensor so the pinned libtorch/ATen objects are mapped.
    torch.tensor([1.0], dtype=torch.float32).sum().item()


def open_artifact() -> int:
    return os.open(ARTIFACT, os.O_RDONLY)


def helper_runtime() -> None:
    mark("child.started", inherited_fd=False)
    runtime()
    mark("child.ready", inherited_fd=False)
    wait_for_stop()


def sibling_split() -> None:
    """Create two same-UID evidence siblings under one live parent."""
    mark("parent.started", sibling=True)
    artifact = os.fork()
    if artifact == 0:
        descriptor = open_artifact()
        mark("artifact.started")
        mark("artifact.ready")
        wait_for_stop()
        os.close(descriptor)
        os._exit(0)
    runtime_child = os.fork()
    if runtime_child == 0:
        mark("runtime.started")
        runtime()
        mark("runtime.ready")
        wait_for_stop()
        os._exit(0)
    mark("parent.ready", artifact_pid=artifact, runtime_pid=runtime_child)
    wait_for_stop()
    for child in (artifact, runtime_child):
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass


def replacement_split() -> None:
    """Fork a runtime replacement while the parent retains model content."""
    mark("parent.started", replacement=True)
    descriptor = open_artifact()
    child = os.fork()
    if child == 0:
        mark("child.started", replacement=True)
        runtime()
        mark("child.ready", replacement=True)
        replacement = os.fork()
        if replacement == 0:
            runtime()
            mark("replacement.ready")
            wait_for_stop()
            os._exit(0)
        mark("replacement.pid", pid=replacement)
        wait_for_stop()
        try:
            os.waitpid(replacement, 0)
        except ChildProcessError:
            pass
        os._exit(0)
    mark("parent.ready", child_pid=child)
    wait_for_stop()
    try:
        os.waitpid(child, 0)
    except ChildProcessError:
        pass
    os.close(descriptor)


def parent_split(*, inherited: bool = False, shared: bool = False, exec_helper: bool = False) -> None:
    mark("parent.started", inherited_fd=inherited, shared_path=shared, exec_helper=exec_helper)
    descriptor = open_artifact()
    if inherited:
        os.set_inheritable(descriptor, True)
    child = os.fork()
    if child == 0:
        try:
            mark("child.started", inherited_fd=inherited, shared_path=shared)
            if exec_helper:
                # Python file descriptors are non-inheritable by default, so
                # this exec helper deliberately receives no model descriptor.
                os.execv(sys.executable, [sys.executable, str(SCRIPT), "helper_runtime", "-", str(CONTROL), str(OUT), str(SCRIPT)])
            if shared:
                child_descriptor = open_artifact()
            else:
                if not inherited:
                    # A fork inherits descriptors regardless of CLOEXEC;
                    # close the parent's artifact explicitly for split cases.
                    os.close(descriptor)
                child_descriptor = descriptor if inherited else -1
            runtime()
            mark("child.ready", inherited_fd=inherited, shared_path=shared)
            wait_for_stop()
            if child_descriptor >= 0:
                os.close(child_descriptor)
        finally:
            os._exit(0)
    mark("parent.ready", child_pid=child)
    wait_for_stop()
    try:
        os.waitpid(child, 0)
    except ChildProcessError:
        pass
    os.close(descriptor)


def main() -> int:
    try:
        if ROLE == "same_fd":
            mark("started", mode="fd")
            descriptor = open_artifact()
            runtime()
            mark("ready", mode="fd")
            wait_for_stop()
            os.close(descriptor)
        elif ROLE == "same_mmap":
            mark("started", mode="mmap")
            descriptor = open_artifact()
            mapped = mmap.mmap(descriptor, 0, access=mmap.ACCESS_READ)
            runtime()
            mark("ready", mode="mmap")
            wait_for_stop()
            mapped.close()
            os.close(descriptor)
        elif ROLE == "deleted_fd":
            mark("started", mode=MODE)
            descriptor = open_artifact()
            renamed = ARTIFACT.with_name(ARTIFACT.name + ".moved")
            os.rename(ARTIFACT, renamed)
            if MODE == "deleted":
                os.unlink(renamed)
            runtime()
            mark("ready", mode=MODE)
            wait_for_stop()
            os.close(descriptor)
        elif ROLE == "artifact_only":
            mark("started", mode="artifact-only")
            descriptor = open_artifact()
            mark("ready", mode="artifact-only")
            wait_for_stop()
            os.close(descriptor)
        elif ROLE == "runtime_only":
            mark("started", mode="runtime-only")
            runtime()
            mark("ready", mode="runtime-only")
            wait_for_stop()
        elif ROLE == "malformed_runtime":
            mark("started", mode="malformed")
            descriptor = open_artifact()
            runtime()
            mark("ready", mode="malformed")
            wait_for_stop()
            os.close(descriptor)
        elif ROLE == "parent_noinherit":
            parent_split(exec_helper=True)
        elif ROLE == "parent_split":
            parent_split()
        elif ROLE == "parent_inherit":
            parent_split(inherited=True)
        elif ROLE == "parent_shared":
            parent_split(shared=True)
        elif ROLE == "parent_cgroup":
            parent_split()
        elif ROLE == "helper_runtime":
            helper_runtime()
        elif ROLE == "sibling":
            sibling_split()
        elif ROLE == "replacement":
            replacement_split()
        else:
            raise RuntimeError(f"unknown fixture role: {ROLE}")
        return 0
    except BaseException as error:
        try:
            mark("error", error=repr(error))
        except BaseException:
            pass
        return 2


raise SystemExit(main())
'''


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_command(argv: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout)


def run_as(user: str, argv: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return run_command(["/usr/sbin/runuser", "-u", user, "--", *argv], timeout=timeout)


def stop_group(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def wait_marker(path: Path, *, timeout: float = 45) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict) and isinstance(value.get("pid"), int):
                    return value
            except (OSError, json.JSONDecodeError):
                pass
        time.sleep(0.02)
    raise RuntimeError(f"fixture marker did not appear: {path.name}")


def wait_started_or_ready(path: Path, *, timeout: float = 45) -> dict[str, Any]:
    """Return the PID marker even if autonomous containment races readiness."""
    deadline = time.monotonic() + timeout
    started = path.with_name(f"{path.stem}.started")
    generic_started = path.with_name("started")
    while time.monotonic() < deadline:
        for candidate in (path, started, generic_started):
            if candidate.is_file():
                try:
                    value = json.loads(candidate.read_text(encoding="utf-8"))
                    if isinstance(value, dict) and isinstance(value.get("pid"), int):
                        return value
                except (OSError, json.JSONDecodeError):
                    pass
        time.sleep(0.02)
    raise RuntimeError(f"fixture started/ready marker did not appear: {path.name}")


def new_cgroup(label: str, token: str, *, owned: bool = False) -> Path:
    base = CGROUP_ROOT / "system.slice" / "lumi-eggcracker.service" if owned else CGROUP_ROOT
    path = base / f"boundary-b1-{label}-{token}"
    path.mkdir(mode=0o755)
    required = ("cgroup.procs", "cgroup.events")
    if not all((path / item).is_file() for item in required):
        raise RuntimeError(f"cgroup controls unavailable: {path}")
    return path


def move_to_cgroup(pid: int, path: Path) -> None:
    (path / "cgroup.procs").write_text(f"{pid}\n", encoding="ascii")


def cgroup_name(pid: int) -> str:
    for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            return line[3:]
    return ""


def remove_cgroup(path: Path) -> None:
    if not path.exists():
        return
    try:
        populated = dict(
            line.split(" ", 1)
            for line in (path / "cgroup.events").read_text(encoding="ascii").splitlines()
            if " " in line
        ).get("populated")
        if populated == "0":
            path.rmdir()
    except (OSError, ValueError):
        pass


def receipt_after(before: set[Path], *, timeout: float = 30) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = set(DETECTIONS.glob("*.json")) - before
        if candidates:
            path = max(candidates, key=lambda item: item.stat().st_mtime_ns)
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                time.sleep(0.02)
                continue
            if isinstance(value, dict):
                return value
        time.sleep(0.02)
    raise RuntimeError("expected autonomous detection receipt did not appear")


def socket_checks(user: str) -> dict[str, Any]:
    attempts = {
        "query": ["status", "--name", "boundary-b1-hostile"],
        "operator": ["start", "--name", "boundary-b1-hostile", "--max-pids", "8", "--", "/bin/sleep", "30"],
        "admin": ["approve", "--name", "boundary-b1-hostile", "--uid", str(pwd.getpwnam(user).pw_uid), "--", "/bin/sleep", "30"],
    }
    values: dict[str, Any] = {}
    for key, argv in attempts.items():
        result = run_as(user, [CLI, *argv], timeout=20)
        values[key] = {
            "argv": argv,
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "stdout": result.stdout[-400:],
            "stderr": result.stderr[-400:],
        }
    metadata: dict[str, Any] = {}
    for key, path in (("query", QUERY_SOCKET), ("operator", OPERATOR_SOCKET), ("admin", ADMIN_SOCKET)):
        item = path.stat()
        metadata[key] = {"path": str(path), "mode": oct(stat.S_IMODE(item.st_mode)), "uid": item.st_uid, "gid": item.st_gid}
    values["socket_metadata"] = metadata
    values["all_denied"] = all(not item["success"] for name, item in values.items() if name in attempts)
    root_status = run_command([CLI, "doctor"], timeout=20)
    values["root_status_returncode"] = root_status.returncode
    return values


def fixture_command(worker: Path, role: str, artifact: Path, control: Path, case_dir: Path, mode: str) -> list[str]:
    return [WORKLOAD_PYTHON, str(worker), role, str(artifact), str(control), str(case_dir), str(worker), mode]


def launch_fixture(user: str, worker: Path, role: str, artifact: Path, control: Path, case_dir: Path, mode: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["/usr/sbin/runuser", "-u", user, "--", *fixture_command(worker, role, artifact, control, case_dir, mode)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def receipt_proof(receipt: dict[str, Any], expected_pids: set[int]) -> dict[str, Any]:
    containment = receipt.get("containment", {})
    observed = receipt.get("observed", {})
    capture = receipt.get("capture", {})
    proof = {
        "result_terminated": receipt.get("result") == "TERMINATED",
        "trigger": receipt.get("trigger", {}).get("kind") == EXPECTED_TRIGGER,
        "profile": receipt.get("detector", {}).get("profile") == EXPECTED_PROFILE,
        "primitive": containment.get("primitive") == "pidfd-stop+cgroup.kill",
        "root_populated_zero": containment.get("root_populated") == 0,
        "surviving_pids_empty": containment.get("surviving_pids") == [],
        "observed_pid_expected": observed.get("pid") in expected_pids,
        "captured_processes": capture.get("captured_processes"),
    }
    proof["complete"] = all(value for key, value in proof.items() if key not in {"captured_processes"})
    return proof


def one_case(spec: dict[str, Any], *, user: str, worker: Path, model: Path, malformed: Path, root: Path, token: str) -> dict[str, Any]:
    name = str(spec["name"])
    case_dir = root / name
    case_dir.mkdir(mode=0o733)
    os.chmod(case_dir, 0o733)
    control = case_dir / "control"
    artifact = model
    if spec.get("copy_model"):
        artifact = case_dir / "model.safetensors"
        shutil.copyfile(model, artifact)
        os.chmod(artifact, 0o644)
    if spec.get("malformed"):
        artifact = case_dir / "malformed.safetensors"
        shutil.copyfile(malformed, artifact)
        os.chmod(artifact, 0o644)
    canary = subprocess.Popen(["/bin/sleep", "120"], start_new_session=True)
    process: subprocess.Popen[bytes] | None = None
    cgroups: list[Path] = []
    before = set(DETECTIONS.glob("*.json"))
    started = time.monotonic_ns()
    values: dict[str, Any] = {"name": name, "expected": spec["expected"], "started_monotonic_ns": started}
    try:
        process = launch_fixture(user, worker, str(spec["role"]), artifact, control, case_dir, str(spec.get("mode", "")))
        if spec.get("sibling"):
            marker_wait = wait_marker if spec.get("expected") == "survive" else wait_started_or_ready
            parent = marker_wait(case_dir / "parent.ready")
            artifact_ready = marker_wait(case_dir / "artifact.ready")
            runtime_ready = marker_wait(case_dir / "runtime.ready")
            values["pids"] = {"parent": parent["pid"], "artifact": artifact_ready["pid"], "runtime": runtime_ready["pid"]}
            if spec.get("cgroup_same"):
                cgroups = [new_cgroup("owned-sibling", token, owned=True)]
                for pid in (artifact_ready["pid"], runtime_ready["pid"]):
                    move_to_cgroup(pid, cgroups[0])
                values["cgroup"] = cgroup_name(artifact_ready["pid"])
            expected_pids = set(values["pids"].values())
        elif spec.get("split"):
            marker_wait = wait_marker if spec.get("expected") == "survive" else wait_started_or_ready
            parent = marker_wait(case_dir / "parent.ready")
            child = marker_wait(case_dir / "child.ready")
            values["pids"] = {"parent": parent["pid"], "child": child["pid"]}
            if spec.get("cgroup_split"):
                cgroups = [new_cgroup("artifact", token), new_cgroup("runtime", token)]
                move_to_cgroup(parent["pid"], cgroups[0])
                move_to_cgroup(child["pid"], cgroups[1])
                values["cgroups"] = {"parent": cgroup_name(parent["pid"]), "child": cgroup_name(child["pid"])}
            expected_pids = {child["pid"]} if spec.get("expected") == "kill-child" else {parent["pid"], child["pid"]}
        else:
            ready = wait_marker(case_dir / "ready") if spec.get("expected") == "survive" else wait_started_or_ready(case_dir / "ready")
            values["pids"] = {"worker": ready["pid"]}
            expected_pids = {ready["pid"]}
        values["ready_monotonic_ns"] = time.monotonic_ns()
        if spec["expected"] in {"kill", "kill-child"}:
            receipt = receipt_after(before)
            values["receipt"] = receipt
            values["receipt_proof"] = receipt_proof(receipt, expected_pids)
            values["receipt_path"] = str(max(set(DETECTIONS.glob("*.json")) - before, key=lambda item: item.stat().st_mtime_ns))
            values["canary_alive_after_detection"] = canary.poll() is None
            if spec["expected"] == "kill-child":
                values["parent_alive_after_child_kill"] = alive(values["pids"]["parent"])
            control.write_text("stop\n", encoding="ascii")
            values["result"] = "PASS" if values["receipt_proof"]["complete"] and values["canary_alive_after_detection"] and (spec["expected"] != "kill-child" or values["parent_alive_after_child_kill"]) else "FAIL"
        else:
            time.sleep(float(spec.get("observe_seconds", 3.0)))
            values["new_receipts"] = len(set(DETECTIONS.glob("*.json")) - before)
            pids = set(values["pids"].values())
            values["workload_alive_during_observe"] = all(alive(pid) for pid in pids)
            values["canary_alive_during_observe"] = canary.poll() is None
            control.write_text("stop\n", encoding="ascii")
            values["result"] = "PASS" if values["new_receipts"] == 0 and values["workload_alive_during_observe"] and values["canary_alive_during_observe"] else "FAIL"
        return values
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        values["result"] = "FAIL"
        values["error"] = repr(error)
        try:
            control.write_text("stop\n", encoding="ascii")
        except OSError:
            pass
        return values
    finally:
        stop_group(process)
        stop_group(canary)
        for path in cgroups:
            remove_cgroup(path)


def unrelated_case(*, name: str, same_cgroup: bool, user: str, worker: Path, model: Path, root: Path, token: str) -> dict[str, Any]:
    """Keep partial same-UID controls alive without a proven workload relation."""
    case_dir = root / name
    case_dir.mkdir(mode=0o733)
    os.chmod(case_dir, 0o733)
    artifact_dir = case_dir / "artifact"
    runtime_dir = case_dir / "runtime"
    artifact_dir.mkdir(mode=0o733); runtime_dir.mkdir(mode=0o733)
    os.chmod(artifact_dir, 0o733); os.chmod(runtime_dir, 0o733)
    control = case_dir / "control"
    canary = subprocess.Popen(["/bin/sleep", "120"], start_new_session=True)
    artifact_proc: subprocess.Popen[bytes] | None = None
    runtime_proc: subprocess.Popen[bytes] | None = None
    cgroups: list[Path] = []
    before = set(DETECTIONS.glob("*.json"))
    value: dict[str, Any] = {"name": name, "expected": "survive", "same_broad_cgroup": same_cgroup}
    try:
        artifact_proc = launch_fixture(user, worker, "artifact_only", model, control, artifact_dir, "")
        runtime_proc = launch_fixture(user, worker, "runtime_only", model, control, runtime_dir, "")
        artifact_ready = wait_marker(artifact_dir / "ready")
        runtime_ready = wait_marker(runtime_dir / "ready")
        value["pids"] = {"artifact": artifact_ready["pid"], "runtime": runtime_ready["pid"]}
        if same_cgroup:
            cgroups = [new_cgroup("unrelated-broad", token)]
            for pid in value["pids"].values():
                move_to_cgroup(pid, cgroups[0])
        else:
            cgroups = [new_cgroup("unrelated-artifact", token), new_cgroup("unrelated-runtime", token)]
            move_to_cgroup(artifact_ready["pid"], cgroups[0]); move_to_cgroup(runtime_ready["pid"], cgroups[1])
        time.sleep(3.0)
        value["new_receipts"] = len(set(DETECTIONS.glob("*.json")) - before)
        value["workloads_alive_during_observe"] = alive(artifact_ready["pid"]) and alive(runtime_ready["pid"])
        value["canary_alive_during_observe"] = canary.poll() is None
        control.write_text("stop\n", encoding="ascii")
        value["result"] = "PASS" if value["new_receipts"] == 0 and value["workloads_alive_during_observe"] and value["canary_alive_during_observe"] else "FAIL"
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        value["result"] = "FAIL"; value["error"] = repr(error)
        try: control.write_text("stop\n", encoding="ascii")
        except OSError: pass
    finally:
        stop_group(artifact_proc); stop_group(runtime_proc); stop_group(canary)
        for path in cgroups: remove_cgroup(path)
    return value


def manifest_entries(root: Path) -> list[str]:
    lines: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "SHA256SUMS"):
        lines.append(f"{digest(path)}  {path.relative_to(root).as_posix()}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Boundary B1 harness must run as root")
    if not Path(WORKLOAD_PYTHON).is_file() or not os.access(WORKLOAD_PYTHON, os.X_OK):
        raise SystemExit(f"pinned workload interpreter is unavailable: {WORKLOAD_PYTHON}")
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit("output must be new")
    args.output.mkdir(mode=0o700, parents=True)
    raw = args.output / "raw"
    raw.mkdir(mode=0o700)
    # The unprivileged fixtures need traversal only; evidence remains
    # non-listable while they run and is tightened again before return.
    os.chmod(args.output, 0o711)
    os.chmod(raw, 0o711)
    token = os.urandom(5).hex()
    worker = raw / "boundary_b1_worker.py"
    worker.write_text(WORKER_SOURCE, encoding="utf-8")
    os.chmod(worker, 0o755)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    candidate = {
        "artifact": str(args.artifact),
        "artifact_sha256": digest(args.artifact),
        "manifest": manifest,
        "installed_policy": json.loads(Path("/etc/lumi-eggcracker/policy.json").read_text(encoding="utf-8")),
        "version_output": run_command([sys.executable, str(args.artifact), "version"], timeout=20).stdout.strip(),
    }
    if manifest.get("source_commit") != args.source_commit or candidate["installed_policy"].get("source_commit") != args.source_commit:
        raise SystemExit("candidate/source commit mismatch")
    model = args.model
    # The installed smoke asset is intentionally root-private.  Materialise
    # one read-only fixture under the bounded traversal-only raw directory so
    # the no-login workload identity can open it.
    model_fixture = raw / "model.safetensors"
    shutil.copyfile(model, model_fixture)
    os.chmod(model_fixture, 0o644)
    model = model_fixture
    malformed = raw / "malformed.safetensors"
    malformed.write_bytes((8).to_bytes(8, "little") + b"{}" + b"\0" * 16)
    os.chmod(malformed, 0o644)
    sockets = socket_checks(args.user)
    write_json(raw / "socket-check.json", sockets)
    specs = [
        {"name": "same-process-fd", "role": "same_fd", "expected": "kill"},
        {"name": "same-process-mmap", "role": "same_mmap", "expected": "kill"},
        {"name": "artifact-parent-runtime-child", "role": "parent_split", "expected": "kill", "split": True},
        {"name": "sibling-artifact-runtime", "role": "sibling", "expected": "kill", "sibling": True, "cgroup_same": True},
        {"name": "fork-exec-helper", "role": "parent_noinherit", "expected": "kill", "split": True},
        {"name": "inherited-fd-child", "role": "parent_inherit", "expected": "kill", "split": True},
        {"name": "shared-path-child", "role": "parent_shared", "expected": "kill", "split": True},
        {"name": "concurrent-replacement", "role": "replacement", "expected": "kill", "split": True},
        {"name": "renamed-artifact", "role": "deleted_fd", "mode": "renamed", "expected": "kill", "copy_model": True},
        {"name": "deleted-artifact", "role": "deleted_fd", "mode": "deleted", "expected": "kill", "copy_model": True},
        {"name": "split-across-cgroups", "role": "parent_cgroup", "expected": "kill", "split": True, "cgroup_split": True},
        {"name": "partial-artifact-only", "role": "artifact_only", "expected": "survive"},
        {"name": "partial-runtime-only", "role": "runtime_only", "expected": "survive"},
        {"name": "partial-malformed-runtime", "role": "malformed_runtime", "expected": "survive", "malformed": True},
    ]
    results: list[dict[str, Any]] = []
    for spec in specs:
        results.append(one_case(spec, user=args.user, worker=worker, model=model, malformed=malformed, root=raw, token=token))
    results.append(unrelated_case(name="unrelated-same-uid-broad-cgroup", same_cgroup=True, user=args.user, worker=worker, model=model, root=raw, token=token))
    results.append(unrelated_case(name="unrelated-same-uid-separate-cgroup", same_cgroup=False, user=args.user, worker=worker, model=model, root=raw, token=token))
    for value in results:
        write_json(raw / f"case-{value['name']}.json", value)
    case_pass = all(value.get("result") == "PASS" for value in results)
    socket_pass = bool(sockets.get("all_denied")) and sockets.get("root_status_returncode") == 0
    kill_values = [value for value in results if value.get("expected") in {"kill", "kill-child"}]
    proof_pass = all(value.get("receipt_proof", {}).get("complete") for value in kill_values)
    classification = {
        "harness": "PASS" if case_pass and socket_pass and proof_pass else "FAIL",
        "product_boundary": "QUALIFIED" if case_pass and socket_pass and proof_pass else "UNQUALIFIED",
        "blocker": "" if case_pass else "Qualification fixtures did not complete; inspect raw case evidence.",
    }
    report = {
        "schema_version": "lumi-eggcracker.boundary-b1.v1",
        "result": "PASS" if case_pass and socket_pass and proof_pass else "FAIL",
        "classification": classification,
        "candidate": candidate,
        "environment": {"user": args.user, "uid": pwd.getpwnam(args.user).pw_uid, "kernel": run_command(["uname", "-a"]).stdout.strip(), "external_hardware": False, "wan": False},
        "cases": {"total": len(results), "passed": sum(value.get("result") == "PASS" for value in results), "failed": sum(value.get("result") != "PASS" for value in results), "details": results},
        "socket_checks": sockets,
        "cgroup_empty_proofs": sum(bool(value.get("receipt_proof", {}).get("complete")) for value in kill_values),
        "product_logic_changed": False,
        "limitations": ["Correlation is bounded to live same-UID parent/child or sibling identities and exact supervisor-owned child cgroups; unrelated same-UID/common-init processes remain outside the workload.", "This brief does not test containers, remote APIs, GPU runtimes, network isolation or adaptive detection."],
        "evidence_dir": str(args.output),
    }
    write_json(args.output / "boundary-b1-report.json", report)
    (args.output / "SHA256SUMS").write_text("\n".join(manifest_entries(args.output)) + "\n", encoding="ascii")
    os.chmod(raw, 0o700)
    os.chmod(args.output, 0o700)
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
