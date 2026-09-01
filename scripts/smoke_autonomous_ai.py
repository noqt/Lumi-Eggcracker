"""Run a real unmanaged local AI invocation through autonomous Eggcracker containment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
ASSET_SCHEMA = "lumi-eggcracker.ai-smoke-assets.v1"
CLI = "/usr/local/bin/eggcracker"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def assets_from_manifest(path: Path) -> tuple[Path, Path, dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("asset manifest must be a regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"llama", "model", "platform", "schema_version"} or value.get("schema_version") != ASSET_SCHEMA:
        raise RuntimeError("AI smoke asset manifest schema is invalid")
    runner, model = Path(value["llama"]["path"]), Path(value["model"]["path"])
    if any(path.is_symlink() or not path.is_file() for path in (runner, model)) or not os.access(runner, os.X_OK):
        raise RuntimeError("AI smoke assets are invalid")
    if digest(runner) != value["llama"]["sha256"] or digest(model) != value["model"]["sha256"]:
        raise RuntimeError("AI smoke asset digest differs from manifest")
    return runner, model, value


def call(operator: str, argv: list[str]) -> dict[str, Any]:
    command = (
        [CLI, *argv]
        if argv and argv[0] in {"approve", "revoke"}
        else ["/usr/sbin/runuser", "-u", operator, "--", CLI, *argv]
    )
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Eggcracker control command failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker control command returned invalid JSON")
    return value


def root_control(argv: list[str]) -> dict[str, Any]:
    """Use root-admin only for bounded smoke-test incident cleanup."""
    result = subprocess.run(
        [CLI, *argv], capture_output=True, text=True, check=False, timeout=30
    )
    if result.returncode:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or "Eggcracker root control command failed"
        )
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker root control command returned invalid JSON")
    return value


def clear_new_incident(previous: set[str]) -> None:
    """Clear only the lockdown incident created by this smoke repetition."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        current = root_control(["incidents"]).get("incidents", [])
        if not isinstance(current, list):
            raise TypeError("Eggcracker incident response is invalid")
        new_active = [
            item["incident_id"]
            for item in current
            if (
                isinstance(item, dict)
                and item.get("state") == "ACTIVE"
                and isinstance(item.get("incident_id"), str)
                and item["incident_id"] not in previous
            )
        ]
        if len(new_active) == 1:
            root_control(["incident", "clear", new_active[0]])
            return
        if len(new_active) > 1:
            raise RuntimeError("autonomous smoke created multiple local incidents")
        time.sleep(0.05)
    raise RuntimeError("autonomous smoke incident was not persisted")


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def stop_selected(operator: str, name: str) -> None:
    receipt = Path(f"/tmp/lumi-autonomous-smoke-kill-{os.urandom(8).hex()}.json")
    try:
        call(operator, ["kill", "--name", name, "--receipt", str(receipt)])
    finally:
        receipt.unlink(missing_ok=True)


def journal_bytes(unit: str) -> int:
    result = subprocess.run(
        ["/usr/bin/journalctl", "--unit", unit, "--output=cat", "--no-pager"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise RuntimeError("cannot read protected workload output from the journal")
    return len(result.stdout)


def receipt_after(previous: set[Path], *, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        paths = set(DETECTIONS.glob("*.json"))
        created = paths - previous
        if created:
            path = max(created, key=lambda item: item.stat().st_mtime_ns)
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("result") == "TERMINATED":
                return value
            raise RuntimeError(f"autonomous containment failed: {value.get('error', value.get('result'))}")
        time.sleep(0.02)
    raise RuntimeError("autonomous detection receipt did not appear")


def generated(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and path.stat().st_size >= 32


def runner_argv(runner: Path, model: Path) -> list[str]:
    return [str(runner), "-m", str(model), "-p", "Explain one Linux cgroup property.", "-n", "4096", "-t", "12", "-tb", "12", "-c", "512", "--simple-io", "--single-turn", "--no-warmup", "--no-display-prompt", "--seed", "1234"]


def launch(user: str, argv: list[str], output: Path) -> subprocess.Popen[bytes]:
    handle = output.open("wb")
    try:
        return subprocess.Popen(["/usr/sbin/runuser", "-u", user, "--", *argv], stdout=handle, stderr=subprocess.DEVNULL, start_new_session=True)
    finally:
        handle.close()


def one(
    *,
    runner: Path,
    model: Path,
    user: str,
    operator: str,
    index: int,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    argv = runner_argv(runner, model)
    with tempfile.TemporaryDirectory(prefix="lumi-eggcracker-autonomous-", dir="/tmp") as raw:
        root = Path(raw)
        output = root / "generated.txt"
        os.chmod(root, 0o711)
        canary = subprocess.Popen(["/bin/sleep", "180"], start_new_session=True)
        unapproved: subprocess.Popen[bytes] | None = None
        allowed_started = False
        # Approval names must remain unique after an interrupted smoke.  A
        # fixed name can strand a prior exact approval and make the next
        # repetition fail before it exercises the product.
        name = f"real-qwen-{index}-{os.urandom(4).hex()}"
        run_name = f"real-qwen-run-{index}-{os.urandom(4).hex()}"
        try:
            before_incidents = {
                item["incident_id"]
                for item in root_control(["incidents"]).get("incidents", [])
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
            }
            before = set(DETECTIONS.glob("*.json"))
            unapproved = launch(user, argv, output)
            receipt = receipt_after(before)
            stop(unapproved)
            unapproved = None
            if (
                receipt.get("trigger", {}).get("kind") != "UNAPPROVED_AI_MATCH"
                or receipt.get("detector", {}).get("profile") != "content.gguf-llama"
                or canary.poll() is not None
            ):
                raise RuntimeError("unapproved real AI result or canary is invalid")
            # The first unapproved launch intentionally enters lockdown.  Use
            # root-admin to clear only this repetition's incident before the
            # independent exact-approval phase.
            clear_new_incident(before_incidents)
            approval = call(
                operator,
                [
                    "approve",
                    "--name",
                    name,
                    "--uid",
                    str(pwd.getpwnam(user).pw_uid),
                    "--max-pids",
                    "64",
                    "--max-memory-mib",
                    "4096",
                    "--cpu-quota-percent",
                    "1200",
                    "--",
                    *argv,
                ],
            )
            if approval.get("result") != "APPROVED":
                raise RuntimeError("exact real-AI approval failed")
            before_approved = set(DETECTIONS.glob("*.json"))
            response = call(
                operator,
                [
                    "start",
                    "--name",
                    run_name,
                    "--max-pids",
                    "64",
                    "--max-memory-mib",
                    "4096",
                    "--cpu-quota-percent",
                    "1200",
                    "--",
                    *argv,
                ],
            )
            allowed_started = True
            unit = response.get("unit")
            if response.get("state") != "RUNNING" or not isinstance(unit, str):
                raise RuntimeError("protected approved real AI did not start")
            deadline = time.monotonic() + 120
            approved_bytes = 0
            while time.monotonic() < deadline and approved_bytes < 32:
                approved_bytes = journal_bytes(unit)
                time.sleep(0.05)
            if (
                approved_bytes < 32
                or call(operator, ["status", "--name", run_name]).get("state")
                != "RUNNING"
                or set(DETECTIONS.glob("*.json")) - before_approved
            ):
                raise RuntimeError("approved real AI did not remain alive and generate output")
            stop_selected(operator, run_name)
            allowed_started = False
            call(operator, ["revoke", "--name", name])
            before_second_incidents = {
                item["incident_id"]
                for item in root_control(["incidents"]).get("incidents", [])
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
            }
            before = set(DETECTIONS.glob("*.json"))
            unapproved = launch(user, argv, output)
            receipt_after_revoke = receipt_after(before)
            stop(unapproved)
            unapproved = None
            if receipt_after_revoke.get("result") != "TERMINATED" or canary.poll() is not None:
                raise RuntimeError("revoked real AI was not autonomously terminated")
            clear_new_incident(before_second_incidents)
            return {"asset_model_sha256": provenance["model"]["sha256"], "asset_runner_sha256": provenance["llama"]["sha256"], "approved_generated_bytes": approved_bytes, "first_receipt": receipt, "result": "PASS", "second_receipt": receipt_after_revoke}
        finally:
            if unapproved is not None:
                stop(unapproved)
            if allowed_started:
                stop_selected(operator, run_name)
            stop(canary)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("autonomous real-AI smoke must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir() or args.repetitions != 5:
        raise SystemExit("output must be new and repetitions must equal five")
    try:
        pwd.getpwnam(args.user)
        runner, model, provenance = assets_from_manifest(args.assets_manifest)
        install = json.loads(
            Path("/var/lib/lumi-eggcracker/install-manifest.json").read_text(encoding="utf-8")
        )
        operator = str(install["operator"])
        values = [
            one(
                runner=runner,
                model=model,
                user=args.user,
                operator=operator,
                index=index,
                provenance=provenance,
            )
            for index in range(args.repetitions)
        ]
        args.output.write_text(json.dumps({"repetitions": values, "result": "PASS"}, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        if not args.output.exists():
            args.output.write_text(json.dumps({"error": str(error), "result": "FAIL"}, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"autonomous real-AI smoke failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
