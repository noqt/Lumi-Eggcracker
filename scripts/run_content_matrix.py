"""Run the 100-case renamed, extensionless real-AI content-recognition matrix."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from smoke_content_ai import assets, command, launch, receipt_after, stop

DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")


def percentile(values: list[float], point: int) -> float:
    if not values:
        raise RuntimeError("empty latency distribution")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, (len(ordered) * point + 99) // 100 - 1)]


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("content matrix must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets-manifest", required=True, type=Path)
    parser.add_argument("--user", required=True)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        args.repetitions != 100
        or args.output.exists()
        or args.output.is_symlink()
        or not args.output.parent.is_dir()
    ):
        raise SystemExit("output must be new and repetitions must equal 100")
    results: dict[str, object] = {"canary_survivals": 0, "kills": 0, "result": "FAIL"}
    try:
        runner, model, _manifest = assets(args.assets_manifest)
        starts: list[float] = []
        first_seen: list[float] = []
        qualification_delay: list[float] = []
        qualification: list[float] = []
        empties: list[float] = []
        with tempfile.TemporaryDirectory(prefix="lumi-content-matrix-", dir="/tmp") as raw:
            root = Path(raw)
            os.chmod(root, 0o755)
            disguised_runner = root / secrets.token_hex(12)
            disguised_model = root / secrets.token_hex(12)
            wrapper = root / f"{secrets.token_hex(8)}.py"
            shutil.copyfile(runner, disguised_runner)
            os.chmod(disguised_runner, 0o755)
            try:
                os.link(model, disguised_model)
            except OSError:
                shutil.copyfile(model, disguised_model)
            wrapper.write_text(
                "import os,sys\nos.execv(sys.argv[1], sys.argv[1:])\n", encoding="utf-8"
            )
            argv = command(disguised_runner, disguised_model)
            if any(item.endswith(".gguf") for item in argv):
                raise RuntimeError("matrix invocation accidentally exposes a model suffix")
            for _ in range(args.repetitions):
                canary = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
                process: subprocess.Popen[bytes] | None = None
                try:
                    before = set(DETECTIONS.glob("*.json"))
                    started = time.monotonic_ns()
                    process = launch(args.user, wrapper, argv, root / "out")
                    receipt = receipt_after(before)
                    stop(process)
                    process = None
                    if (
                        receipt.get("detector", {}).get("profile") != "content.gguf-llama"
                        or receipt.get("detector", {}).get("detection_path") != "CONTENT"
                        or canary.poll() is not None
                        or receipt.get("containment", {}).get("surviving_pids")
                    ):
                        raise RuntimeError("content containment or canary proof failed")
                    starts.append(
                        (receipt["containment"]["first_stop_monotonic_ns"] - started) / 1_000_000
                    )
                    observation = receipt.get("detector", {}).get("observation", {})
                    if observation.get("first_seen_monotonic_ns") is not None:
                        first_seen.append(
                            (observation["first_seen_monotonic_ns"] - started) / 1_000_000
                        )
                    if (
                        observation.get("qualified_monotonic_ns") is not None
                        and observation.get("first_seen_monotonic_ns") is not None
                    ):
                        qualification_delay.append(
                            (
                                observation["qualified_monotonic_ns"]
                                - observation["first_seen_monotonic_ns"]
                            )
                            / 1_000_000
                        )
                    qualification.append(
                        float(receipt["containment"]["qualification_to_first_stop_ms"])
                    )
                    empties.append(float(receipt["containment"]["trigger_to_empty_ms"]))
                    results["kills"] = int(results["kills"]) + 1
                    results["canary_survivals"] = int(results["canary_survivals"]) + 1
                finally:
                    stop(process)
                    stop(canary)
        results["latency_ms"] = {
            "process_start_to_first_seen_p95": percentile(first_seen, 95),
            "first_seen_to_qualified_p95": percentile(qualification_delay, 95),
            "process_start_to_first_stop_p95": percentile(starts, 95),
            "qualification_to_first_stop_p95": percentile(qualification, 95),
            "trigger_to_empty_p95": percentile(empties, 95),
        }
        # Process start-to-qualification is retained as diagnostic evidence:
        # a real model can spend seconds loading before its exact runtime ELF
        # identity is observable. The release gate is deterministic response
        # after qualification and the authoritative cgroup-empty proof.
        if percentile(qualification, 95) >= 100 or percentile(empties, 95) >= 500:
            raise RuntimeError("content latency gate failed")
        results["result"] = "PASS"
        args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as error:
        results["error"] = str(error)
        if not args.output.exists():
            args.output.write_text(json.dumps(results, sort_keys=True) + "\n", encoding="utf-8")
        raise SystemExit(f"content matrix failed: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
