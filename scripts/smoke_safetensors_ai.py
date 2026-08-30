"""Exercise autonomous Safetensors/PyTorch containment with a real causal model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CLI = "/usr/local/bin/eggcracker"
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
SCHEMA = "lumi-eggcracker.safetensors-ai-smoke-assets.v1"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def load_assets(path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != {"environment", "model", "platform", "schema_version"} or value["schema_version"] != SCHEMA:
        raise RuntimeError("Safetensors asset manifest is invalid")
    python = Path(value["environment"]["path"])
    model = Path(value["model"]["path"])
    config = Path(value["model"]["config"])
    if any(item.is_symlink() or not item.is_file() for item in (model, config)):
        raise RuntimeError("Safetensors smoke assets are not regular files")
    interpreter = python.resolve() if python.is_symlink() else python
    if interpreter.is_symlink() or not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise RuntimeError("Safetensors smoke interpreter is not executable")
    if digest(model) != value["model"]["sha256"] or digest(config) != value["model"]["config_sha256"]:
        raise RuntimeError("Safetensors smoke asset digest differs from manifest")
    return python, model, config, value


def control(argv: list[str], *, operator: str | None = None) -> dict[str, Any]:
    command = [CLI, *argv]
    if operator is not None:
        command = ["/usr/sbin/runuser", "-u", operator, "--", *command]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Eggcracker control failed")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Eggcracker control returned invalid JSON")
    return value


def clear_new_incident(previous: set[str]) -> str:
    """Clear only this smoke's incident before its approved phase."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        current = control(["incidents"]).get("incidents", [])
        if not isinstance(current, list):
            raise TypeError("Eggcracker incident response is invalid")
        new_active = [
            item["incident_id"]
            for item in current
            if isinstance(item, dict)
            and item.get("state") == "ACTIVE"
            and isinstance(item.get("incident_id"), str)
            and item["incident_id"] not in previous
        ]
        if len(new_active) == 1:
            control(["incident", "clear", new_active[0]])
            return new_active[0]
        if len(new_active) > 1:
            raise RuntimeError("Safetensors smoke created multiple local incidents")
        time.sleep(0.05)
    raise RuntimeError("Safetensors smoke incident was not persisted")


def rejected_control(argv: list[str], *, operator: str) -> dict[str, Any]:
    result = subprocess.run(
        ["/usr/sbin/runuser", "-u", operator, "--", CLI, *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode == 0 or "approved Python script" not in result.stderr:
        raise RuntimeError("mutable approved script was not rejected before launch")
    return {"returncode": result.returncode, "stderr": result.stderr.strip()}


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def stop_selected(operator: str, name: str) -> None:
    receipt = Path(f"/tmp/lumi-safetensors-kill-{secrets.token_hex(8)}.json")
    try:
        control(
            ["kill", "--name", name, "--receipt", str(receipt)],
            operator=operator,
        )
    finally:
        receipt.unlink(missing_ok=True)


def receipt_after(before: set[Path], *, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        paths = set(DETECTIONS.glob("*.json")) - before
        if paths:
            value = json.loads(max(paths, key=lambda item: item.stat().st_mtime_ns).read_text(encoding="utf-8"))
            if value.get("result") != "TERMINATED":
                raise RuntimeError(value.get("error", value.get("result", "containment failed")))
            return value
        time.sleep(0.02)
    raise RuntimeError("Safetensors/PyTorch detection receipt did not appear")


def wrapper_source() -> str:
    return """import sys, time
from pathlib import Path
import torch
from safetensors.torch import load_file
from transformers import AutoConfig, AutoModelForCausalLM

weights = Path(sys.argv[1])
config_path = Path(sys.argv[2])
output = Path(sys.argv[3])
hold = weights.open('rb')
config = AutoConfig.from_pretrained(config_path.parent, local_files_only=True)
model = AutoModelForCausalLM.from_config(config)
state = load_file(str(weights), device='cpu')
model.load_state_dict(state, strict=False)
model.eval()
with torch.no_grad():
    generated = model.generate(torch.tensor([[1, 2, 3]], dtype=torch.long), max_new_tokens=8)
output.write_bytes(generated.detach().cpu().numpy().tobytes())
time.sleep(45)
"""


def launch(python: Path, user: str, wrapper: Path, weights: Path, config: Path, output: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["/usr/sbin/runuser", "-u", user, "--", str(python), str(wrapper), str(weights), str(config), str(output)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def one(
    python: Path,
    model: Path,
    config: Path,
    user: str,
    operator: str,
    index: int,
) -> dict[str, Any]:
    # Keep the fixture below the root-controlled asset tree.  Safetensors
    # weights can be large, while /run is a small tmpfs on many native hosts;
    # the disk-backed asset parent avoids a staging-space false failure.
    with tempfile.TemporaryDirectory(
        prefix="lumi-safetensors-smoke-", dir=str(model.parent.parent)
    ) as raw:
        root = Path(raw)
        # Approval-bound inputs live below a root-controlled directory.  Only
        # the separate output directory is writable by the workload identity.
        os.chmod(root, 0o711)
        inputs = root / "inputs"
        outputs = root / "outputs"
        inputs.mkdir(mode=0o711)
        outputs.mkdir(mode=0o733)
        os.chmod(inputs, 0o711)
        os.chmod(outputs, 0o733)
        weights = inputs / "weights"
        config_copy = inputs / "config.json"
        wrapper = inputs / secrets.token_hex(12)
        output = outputs / "output"
        shutil.copyfile(model, weights)
        shutil.copyfile(config, config_copy)
        wrapper.write_text(wrapper_source(), encoding="utf-8")
        user_uid = pwd.getpwnam(user).pw_uid
        canary = subprocess.Popen(["/bin/sleep", "180"], start_new_session=True)
        first_process: subprocess.Popen[bytes] | None = None
        approved_started = False
        name = f"safetensors-{index}-{secrets.token_hex(4)}"
        run_name = f"safetensors-run-{index}-{secrets.token_hex(4)}"
        argv = [str(python), str(wrapper), str(weights), str(config_copy), str(output)]
        try:
            before_incidents = {
                item["incident_id"]
                for item in control(["incidents"]).get("incidents", [])
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
            }
            before = set(DETECTIONS.glob("*.json"))
            first_process = launch(python, user, wrapper, weights, config_copy, output)
            first = receipt_after(before)
            stop(first_process)
            first_process = None
            if (
                first.get("trigger", {}).get("kind") != "UNAPPROVED_SAFETENSORS_PYTORCH"
                or first.get("detector", {}).get("profile") != "content.safetensors-pytorch"
                or canary.poll() is not None
            ):
                raise RuntimeError("Safetensors/PyTorch profile or canary proof failed")
            if any(secret in json.dumps(first, sort_keys=True) for secret in (str(weights), str(wrapper))):
                raise RuntimeError("Safetensors receipt leaked local paths")
            output.unlink(missing_ok=True)
            clear_new_incident(before_incidents)
            approval = control(
                [
                    "approve", "--name", name, "--uid", str(user_uid),
                    "--max-pids", "64", "--max-memory-mib", "4096",
                    "--cpu-quota-percent", "1200", "--", *argv,
                ]
            )
            if approval.get("result") != "APPROVED":
                raise RuntimeError("exact Safetensors approval failed")
            approved_source = wrapper.read_bytes()
            try:
                wrapper.write_bytes(b"raise SystemExit('mutated after approval')\n")
                mutation_rejection = rejected_control(
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
                    operator=operator,
                )
            finally:
                wrapper.write_bytes(approved_source)
            response = control(
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
                operator=operator,
            )
            approved_started = True
            if response.get("state") != "RUNNING":
                raise RuntimeError("protected approved causal model did not start")
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and (not output.is_file() or output.stat().st_size < 32):
                time.sleep(0.05)
            if (
                not output.is_file()
                or output.stat().st_size < 32
                or control(["status", "--name", run_name], operator=operator).get("state")
                != "RUNNING"
            ):
                raise RuntimeError("approved causal model did not generate output")
            generated = output.stat().st_size
            stop_selected(operator, run_name)
            approved_started = False
            if any(Path("/run/lumi-eggcracker/staged").iterdir()):
                raise RuntimeError("approved script stage survived workload termination")
            control(["revoke", "--name", name])
            before_second_incidents = {
                item["incident_id"]
                for item in control(["incidents"]).get("incidents", [])
                if isinstance(item, dict) and isinstance(item.get("incident_id"), str)
            }
            before = set(DETECTIONS.glob("*.json"))
            first_process = launch(python, user, wrapper, weights, config_copy, output)
            second = receipt_after(before)
            stop(first_process)
            first_process = None
            if second.get("detector", {}).get("profile") != "content.safetensors-pytorch" or canary.poll() is not None:
                raise RuntimeError("revoked Safetensors/PyTorch model was not terminated")
            # Keep the next self-validation job independent while retaining
            # the receipt and relaunch-lockdown proof in this result.
            clear_new_incident(before_second_incidents)
            return {"approved_generated_bytes": generated, "first_receipt": first, "mutable_script_rejection": mutation_rejection, "result": "PASS", "second_receipt": second}
        finally:
            stop(first_process)
            if approved_started:
                stop_selected(operator, run_name)
            stop(canary)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Safetensors AI smoke must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.repetitions != 5 or args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise SystemExit("output must be new and repetitions must equal five")
    try:
        python, model, config, _manifest = load_assets(args.assets_manifest)
        install = json.loads(
            Path("/var/lib/lumi-eggcracker/install-manifest.json").read_text(encoding="utf-8")
        )
        operator = str(install["operator"])
        values = [
            one(python, model, config, args.user, operator, index)
            for index in range(args.repetitions)
        ]
        args.output.write_text(json.dumps({"repetitions": values, "result": "PASS"}, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        if not args.output.exists():
            args.output.write_text(json.dumps({"error": str(error), "result": "FAIL"}, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"Safetensors AI smoke failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
