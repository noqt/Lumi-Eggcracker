"""Controlled public-run fixtures; these never dispatch or perform containment."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import hosted_proof as proof

ROOT = Path(__file__).resolve().parents[1]
URL = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
HEAD = "a" * 40


def output(step: str, value: str) -> str:
    return f"containment-probe\t{step}\t2026-09-09T01:02:03.1234567Z {value}\n"


class PublicRun:
    def __init__(self) -> None:
        self.repository = {
            "id": 12, "full_name": "operator/Lumi-Eggcracker", "private": False,
            "visibility": "public", "fork": True,
            "parent": {"id": 1, "full_name": proof.UPSTREAM, "private": False},
        }
        self.state = {
            "id": 123, "html_url": URL, "event": "workflow_dispatch",
            "path": ".github/workflows/containment-probe.yml", "head_sha": HEAD,
            "run_attempt": 1, "status": "completed", "conclusion": "success",
            "repository": copy.deepcopy(self.repository),
            "head_repository": copy.deepcopy(self.repository),
        }
        self.receipt = json.loads(
            (ROOT / "schemas/examples/hosted-proof-receipt-v1-success.json").read_text()
        )
        self.receipt.update(source_commit=HEAD, source_tree_sha256=proof.QUALIFIED_SOURCE_SHA256)
        self.blob = proof.REVIEWED_WORKFLOW_BLOB
        self.log_override = None
        self.commands = []
        self.changed = False
        self.reads = 0
        self.failure = None
        self.tree = {"truncated": False, "tree": [
            {"path": path, "mode": "040000", "type": "tree"}
            for path in ("src", "src/lumi_eggcracker", "scripts")
        ] + [
            {"path": path, "mode": "100644", "type": "blob", "sha": sha}
            for path, sha in proof.REVIEWED_PROBE_BLOBS.items()
        ]}

    def log(self) -> str:
        return (
            output(proof.PREFLIGHT_STEP, f"FORK_PROBE_WORKFLOW_BLOB={self.blob}")
            + output(proof.PREFLIGHT_STEP, "FORK_PROBE_PREFLIGHT=PASS")
            + output(proof.PROBE_STEP, 'print("FORK_PROBE_RESULT=PASS")')
            + output(proof.PROBE_STEP, json.dumps(self.receipt))
            + output(proof.PROBE_STEP, "FORK_PROBE_RESULT=PASS")
        )

    def __call__(self, command):
        self.commands.append(tuple(command))
        if self.failure is not None:
            raise self.failure
        if command[1:3] == ("run", "view"):
            assert command[-3:] == ("--attempt", "1", "--log")
            value = self.log() if self.log_override is None else self.log_override
        elif any("/contents/" in part for part in command):
            assert f"ref={HEAD}" in command
            value = self.blob
        elif command[-1].endswith(f"/git/trees/{HEAD}?recursive=1"):
            value = json.dumps(self.tree)
        elif command[-1].endswith("/actions/runs/123"):
            self.reads += 1
            state = copy.deepcopy(self.state)
            if self.changed and self.reads > 1:
                state["run_attempt"] = 2
            value = json.dumps(state)
        elif command[-1] == f"repos/{self.repository['full_name']}":
            value = json.dumps(self.repository)
        else:
            raise AssertionError("Unexpected or mutating command")
        return subprocess.CompletedProcess(command, 0, value, "")


class ResumeTests(unittest.TestCase):
    def test_success_exports_validator_accepted_receipt(self):
        run = PublicRun()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            proof.resume_hosted_proof(URL, receipt_path=path, runner=run)
            validator = runpy.run_path(str(ROOT / "scripts/validate_hosted_proof_receipt.py"))
            with redirect_stdout(StringIO()):
                self.assertEqual(validator["main"]([str(path)]), 0)
            self.assertEqual(json.loads(path.read_text()), run.receipt)
        self.assertEqual(len(run.commands), 6)

    def test_read_only_without_output(self):
        proof.resume_hosted_proof(URL, runner=PublicRun())

    def test_canonical_public_run(self):
        run = PublicRun()
        run.repository.update(full_name=proof.UPSTREAM, fork=False)
        url = URL.replace("operator/", "noqt/")
        run.state.update(html_url=url, repository=copy.deepcopy(run.repository),
                         head_repository=copy.deepcopy(run.repository))
        proof.resume_hosted_proof(url, runner=run)

    def test_reviewed_pins_match_checked_in_sources(self):
        for name, expected in proof.REVIEWED_PROBE_BLOBS.items():
            data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(), expected)
        workflow = (ROOT / ".github/workflows/containment-probe.yml").read_text()
        self.assertIn(f"QUALIFIED_SOURCE_SHA256: {proof.QUALIFIED_SOURCE_SHA256}", workflow)

    def test_metadata_and_log_transport_refusals(self):
        for payload, status in (("{}", 1), ("{", 0), ("x" * 65_537, 0),
                                ('{"id":1,"id":2}', 0), ('{"id":NaN}', 0)):
            with self.subTest(payload=payload[:20]):
                def runner(command):
                    return subprocess.CompletedProcess(command, status, payload, "PRIVATE")
                with self.assertRaises(proof.HostedProofError) as caught:
                    proof.resume_hosted_proof(URL, runner=runner)
                self.assertNotIn("PRIVATE", str(caught.exception))
        run = PublicRun()
        def unavailable_log(command):
            if "--log" in command:
                return subprocess.CompletedProcess(command, 1, "PRIVATE", "PRIVATE")
            return run(command)
        with self.assertRaises(proof.HostedProofError) as caught:
            proof.resume_hosted_proof(URL, runner=unavailable_log)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_bad_urls_have_no_calls(self):
        for url in (URL + "?x=1", URL + "/", URL.replace("github.com", "evil.test"), "private"):
            with self.subTest(url=url):
                run = PublicRun()
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(url, runner=run)
                self.assertEqual(run.commands, [])

    def test_bad_repository_identity_before_logs(self):
        for key, value in (("private", True), ("visibility", "private"), ("fork", False),
                           ("parent", {}), ("full_name", "other/Lumi-Eggcracker")):
            with self.subTest(key=key):
                run = PublicRun()
                run.repository[key] = value
                def repository_response(command):
                    run.commands.append(tuple(command))
                    return subprocess.CompletedProcess(command, 0, json.dumps(run.repository), "")
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, runner=repository_response)
                self.assertEqual(run.commands, [
                    ("gh", "api", "--hostname", "github.com", "--method", "GET",
                     "repos/operator/Lumi-Eggcracker"),
                ])
                self.assertFalse(any("--log" in command for command in run.commands))

    def test_bad_run_identity_before_logs(self):
        for key, value in (
            ("id", 124), ("html_url", URL + "0"), ("event", "pull_request"),
            ("path", ".github/workflows/evil.yml"), ("head_sha", "main"),
            ("run_attempt", True), ("repository", {}), ("head_repository", {}),
            ("status", "in_progress"), ("conclusion", "failure"),
        ):
            with self.subTest(key=key):
                run = PublicRun()
                run.state[key] = value
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, runner=run)
                self.assertFalse(any("--log" in command for command in run.commands))

    def test_unreviewed_workflow_before_logs(self):
        run = PublicRun()
        run.blob = "b" * 40
        with self.assertRaises(proof.HostedProofError):
            proof.resume_hosted_proof(URL, runner=run)
        self.assertFalse(any("--log" in command for command in run.commands))

    def test_changed_source_and_shadow_paths_before_logs(self):
        variants = []
        tree = copy.deepcopy(PublicRun().tree)
        tree["tree"][-1]["sha"] = "f" * 40
        variants.append(tree)
        tree = copy.deepcopy(PublicRun().tree)
        tree["truncated"] = True
        variants.append(tree)
        for path, mode, kind in (
            ("src/lumi_eggcracker/containment_probe", "040000", "tree"),
            ("src/lumi_eggcracker/containment_probe.so", "100644", "blob"),
            ("src/lumi_eggcracker/containment_probe.pyc", "100644", "blob"),
            ("src/lumi_eggcracker/other.py", "120000", "blob"),
            ("src/json.py", "100644", "blob"),
        ):
            tree = copy.deepcopy(PublicRun().tree)
            tree["tree"].append({"path": path, "mode": mode, "type": kind})
            variants.append(tree)
        for tree in variants:
            with self.subTest(tree=tree):
                run = PublicRun()
                run.tree = tree
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, runner=run)
                self.assertFalse(any("--log" in command for command in run.commands))

    def test_invalid_receipts_and_source(self):
        for update in ({"source_commit": "b" * 40}, {"source_tree_sha256": "0" * 64},
                       {"target_survivors": 1}, {"extra": "secret"},
                       {"trigger_to_empty_ms": float("nan")}):
            with self.subTest(update=update):
                run = PublicRun()
                run.receipt.update(update)
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, runner=run)
        run = PublicRun()
        run.receipt = {"mode": "containment-primitive-probe", "result": "FAILED",
                       "reason_code": "INTERRUPTED"}
        with self.assertRaises(proof.HostedProofError):
            proof.resume_hosted_proof(URL, runner=run)

    def test_ambiguous_missing_echo_and_oversize_logs(self):
        run = PublicRun()
        baseline = run.log()
        receipt_line = output(proof.PROBE_STEP, json.dumps(run.receipt))
        for log in (
            "", "x" * (proof.FOLLOW_LOG_MAX_BYTES + 1), baseline + receipt_line,
            baseline.replace(receipt_line, ""), baseline.replace("FORK_PROBE_RESULT=PASS", "echo PASS"),
            baseline.replace(proof.PROBE_STEP, "wrong step"),
            baseline.replace(receipt_line, output(proof.PROBE_STEP, '{"result":1,"result":2}')),
            baseline.replace(receipt_line, output(proof.PROBE_STEP, "{" + "x" * 16_384)),
            baseline.replace(receipt_line, output(proof.PROBE_STEP, "{malformed}")),
            baseline + output(proof.PROBE_STEP, "FORK_PROBE_RESULT=FAIL"),
        ):
            with self.subTest(length=len(log)):
                run.log_override = log
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, runner=run)

    def test_huge_receipt_integers_are_redacted_without_output(self):
        for field in ("trigger_to_empty_ms", "descendant_cgroups_checked"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                run = PublicRun()
                run.receipt[field] = int("9" * 1000)
                path = Path(directory) / "receipt.json"
                stdout, stderr = StringIO(), StringIO()
                with (
                    redirect_stdout(stdout), redirect_stderr(stderr),
                    self.assertRaises(proof.HostedProofError) as caught,
                ):
                    proof.resume_hosted_proof(URL, receipt_path=path, runner=run)
                self.assertFalse(path.exists())
                self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
                self.assertNotIn("9" * 20, str(caught.exception))

    def test_rerun_during_read_refuses_output(self):
        run = PublicRun()
        run.changed = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with self.assertRaises(proof.HostedProofError):
                proof.resume_hosted_proof(URL, receipt_path=path, runner=run)
            self.assertFalse(path.exists())

    def test_existing_and_unwritable_output(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "existing.json"
            existing.write_text("preserve")
            for path in (existing, Path(directory), Path(directory) / "missing" / "out"):
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, receipt_path=path, runner=PublicRun())
            self.assertEqual(existing.read_text(), "preserve")

    def test_output_write_and_close_failure_preserves_new_file(self):
        original_open = Path.open
        for phase in ("write", "close"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "partial.json"
                class FailingFile:
                    def __enter__(self):
                        self.handle = original_open(path, "x", encoding="utf-8")
                        return self

                    def write(self, value):
                        self.handle.write(value[:8])
                        if phase == "write":
                            raise OSError("PRIVATE")

                    def __exit__(self, *_args):
                        self.handle.close()
                        if phase == "close":
                            raise OSError("PRIVATE")

                def opening(target, *args, **kwargs):
                    return FailingFile() if target == path else original_open(target, *args, **kwargs)

                with patch.object(Path, "open", opening), self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, receipt_path=path, runner=PublicRun())
                self.assertTrue(path.exists())
                self.assertEqual(len(path.read_text()), 8)

    def test_parent_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            metadata = parent.lstat()
            original_lstat = Path.lstat
            class ReparseDirectory:
                st_mode = metadata.st_mode
                st_file_attributes = 0x400
            with patch.object(Path, "lstat", lambda path:
                              ReparseDirectory() if path == parent else original_lstat(path)):
                with self.assertRaises(proof.HostedProofError):
                    proof.resume_hosted_proof(URL, receipt_path=parent / "receipt", runner=PublicRun())
            self.assertFalse((parent / "receipt").exists())

    def test_dangling_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "link"
            target = Path(directory) / "absent"
            try:
                path.symlink_to(target)
            except OSError:
                if os.name == "nt":
                    self.skipTest("Windows symlink privilege unavailable; Linux CI exercises this")
                raise
            with self.assertRaises(proof.HostedProofError):
                proof.resume_hosted_proof(URL, receipt_path=path, runner=PublicRun())
            self.assertTrue(path.is_symlink())
            self.assertFalse(target.exists())

    def test_timeouts_redacted(self):
        run = PublicRun()
        run.failure = subprocess.TimeoutExpired("private value", 1)
        with self.assertRaises(proof.HostedProofError) as caught:
            proof.resume_hosted_proof(URL, runner=run)
        self.assertNotIn("private value", str(caught.exception))

    def test_cli_refuses_mixed_modes_without_dispatch(self):
        for flags in (["--wait"], ["--sync-fork"], ["--show-log"],
                      ["--i-understand-this-kills-a-test-tree"]):
            with patch.object(proof, "start_hosted_proof") as start, redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit):
                    proof.main(["--resume", URL, *flags])
                start.assert_not_called()
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            proof.main(["--receipt", "receipt.json"])

    def test_originating_interrupted_wait_resume_documented_commands(self):
        docs = (ROOT / "TRY_IT.md").read_text()
        command = (
            "python3 scripts/start_hosted_proof.py --resume "
            "https://github.com/OWNER/Lumi-Eggcracker/actions/runs/RUN_ID --receipt receipt.json"
        )
        self.assertIn(command, docs)
        run = PublicRun()
        entry = runpy.run_path(str(ROOT / "scripts/start_hosted_proof.py"))["run"]
        starter_commands = []

        def interrupted_starter(command, **kwargs):
            command = tuple(command)
            starter_commands.append(tuple(command))
            if command[1:3] == ("auth", "status"):
                value = ""
            elif command[-1] == ".login":
                value = "operator"
            elif command[-1] == "[.fork,.parent.full_name,.default_branch] | @tsv":
                value = "true\tnoqt/Lumi-Eggcracker\tmain"
            elif command[-1] == ".sha":
                value = proof.REVIEWED_WORKFLOW_BLOB
            elif command[1:3] == ("workflow", "enable"):
                value = ""
            elif command[1:3] == ("workflow", "run"):
                value = URL
            elif command[1:3] == ("run", "watch"):
                raise subprocess.TimeoutExpired(command, 900)
            else:
                raise AssertionError("Unexpected originating fixture command")
            return subprocess.CompletedProcess(command, 0, value, "")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            with (
                patch.object(proof.shutil, "which", return_value="gh"),
                redirect_stderr(StringIO()), redirect_stdout(StringIO()),
            ):
                with (
                    patch.object(proof.subprocess, "run", side_effect=interrupted_starter),
                    patch.object(sys, "argv", ["scripts/start_hosted_proof.py",
                                               "--i-understand-this-kills-a-test-tree", "--wait"]),
                    self.assertRaises(SystemExit),
                ):
                    entry()
                self.assertEqual(sum(c[1:3] == ("workflow", "run") for c in starter_commands), 1)
                with patch.object(proof.subprocess, "run", side_effect=lambda command, **kw:
                                  run(tuple(command))):
                    args = command.replace("OWNER", "operator").replace("RUN_ID", "123").split()[2:]
                    args[-1] = str(path)
                    with patch.object(sys, "argv", ["scripts/start_hosted_proof.py", *args]):
                        self.assertEqual(entry(), 0)
                self.assertEqual(sum(c[1:3] == ("workflow", "run") for c in starter_commands), 1)
                self.assertFalse(any(c[1:3] == ("workflow", "run") for c in run.commands))
            validator = runpy.run_path(str(ROOT / "scripts/validate_hosted_proof_receipt.py"))
            with redirect_stdout(StringIO()):
                self.assertEqual(validator["main"]([str(path)]), 0)

    def test_readme_originating_corrections(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("Maintained by [noqt]", readme)
        self.assertNotIn("scadastrangelove", readme)
        self.assertEqual(readme.count("### Check host compatibility"), 1)
        self.assertIn("(#check-host-compatibility)", readme)


if __name__ == "__main__":
    unittest.main()
