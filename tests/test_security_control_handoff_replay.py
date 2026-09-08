"""Replay the published inert example, not a live Eggcracker control path."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "security-control-handoff.md"
CONTRACT = ROOT / "tests" / "test_security_control_handoff_contract.py"
EXPECTED_TESTS = frozenset({
    "test_valid_one_owned_fixture_and_two_identical_views",
    "test_malformed_never_echoes_raw_input",
    "test_expired_future_and_excessive_lifetime",
    "test_unknown_out_of_scope_and_unauthorized",
    "test_handle_expired_and_unsupported",
    "test_replace_between_request_creation_and_dispatch",
    "test_duplicate_and_conflicting_replay_do_not_redispatch",
    "test_duplicate_revalidates_authority_freshness_and_binding",
    "test_same_id_cannot_substitute_an_authorized_replacement",
    "test_fake_partial_unknown_failed_and_unexpected_never_stop",
    "test_receiver_failure_is_unconfirmed_and_not_retried",
    "test_accepted_without_dispatch_is_not_observed",
    "test_concurrent_duplicate_and_distinct_ids_dispatch_only_once",
})


def published_shell(text: str) -> str:
    blocks = re.findall(r"^```sh\n(.*?)^```[ \t]*$", text, re.MULTILINE | re.DOTALL)
    if len(blocks) != 1 or text.count("```sh") != 1 or not blocks[0].strip():
        raise ValueError("expected exactly one complete nonempty sh block")
    return blocks[0]


def require_nonroot_linux() -> int:
    if sys.platform != "linux" or not hasattr(os, "geteuid"):
        raise RuntimeError("the published shell replay requires Linux")
    uid = os.geteuid()
    if uid == 0:
        raise RuntimeError("the published shell replay refuses root")
    return uid


def verify_transcript(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0 or result.stdout:
        raise AssertionError("published shell failed or emitted unexpected stdout")
    lines = result.stderr.splitlines()
    successful = []
    for line in lines:
        match = re.fullmatch(
            r"(test_[a-z0-9_]+) \(__main__\.SecurityControlHandoffContractTests"
            r"(?:\.\1)?\) \.\.\. ok", line,
        )
        if match:
            successful.append(match[1])
    if len(successful) != 13 or set(successful) != EXPECTED_TESTS:
        raise AssertionError("expected all 13 distinct inert tests, each successful")
    summary = re.fullmatch(
        r"\n?" + r"[^\n]+\n" * 13
        + r"\n-+\nRan 13 tests in [0-9.]+s\n\nOK\n?",
        result.stderr,
    )
    if summary is None:
        raise AssertionError("incomplete or unexpected inert test transcript")


class HandoffReplayValidationTests(unittest.TestCase):
    def test_shell_extraction_preserves_exact_text(self):
        self.assertEqual("echo inert\n", published_shell("Before\n```sh\necho inert\n```\n"))

    def test_missing_duplicate_and_incomplete_shell_are_rejected(self):
        for text in ("", "```sh\n", "```sh\n```", "```sh\nx\n```\n```sh\ny\n```"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                published_shell(text)

    def test_root_is_refused_without_launch(self):
        with patch.object(sys, "platform", "linux"), patch.object(
            os, "geteuid", return_value=0, create=True,
        ), self.assertRaisesRegex(RuntimeError, "refuses root"):
            require_nonroot_linux()

    def test_incomplete_skipped_and_nonzero_results_are_rejected(self):
        lines = [
            f"{name} (__main__.SecurityControlHandoffContractTests.{name}) ... ok"
            for name in sorted(EXPECTED_TESTS)
        ]
        good = "\n".join(lines) + "\n\n" + "-" * 70 + "\nRan 13 tests in 0.010s\n\nOK\n"
        verify_transcript(subprocess.CompletedProcess([], 0, "", good))
        for status, stdout, stderr in (
            (1, "", good), (0, "unexpected", good), (0, "", "Ran 13 tests\nOK\n"),
            (0, "", good.replace("... ok", "... skipped 'fixture'", 1)),
            (0, "", good.replace(lines[0], lines[1])), (0, "", good.replace("OK\n", "")),
        ):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                verify_transcript(subprocess.CompletedProcess([], status, stdout, stderr))


class PublishedHandoffReplayTests(unittest.TestCase):
    def test_exact_published_linux_shell(self):
        uid = require_nonroot_linux()
        approved = os.environ.get("RUNNER_TEMP") if os.environ.get("GITHUB_ACTIONS") == "true" else os.environ.get("TMPDIR")
        if not approved or not Path(approved).is_dir():
            self.fail("set an existing approved RUNNER_TEMP or TMPDIR before replay")
        temp_root = Path(approved).resolve(strict=True)
        paths = (GUIDE, CONTRACT, Path(__file__).resolve())
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        shell = published_shell(GUIDE.read_text(encoding="utf-8"))
        # Do not inherit Python hooks, token variables or the parent test PYTHONPATH.
        search_path = os.pathsep.join((str(Path(sys.executable).parent), "/usr/bin", "/bin"))
        interpreter = shutil.which("python3", path=search_path)
        if interpreter is None or Path(interpreter).resolve() != Path(sys.executable).resolve():
            self.fail("python3 must resolve to the current CI interpreter")
        environment = {
            "PATH": search_path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "TEMP": str(temp_root), "TMP": str(temp_root), "TMPDIR": str(temp_root),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if os.environ.get("PYTHONPYCACHEPREFIX"):
            environment["PYTHONPYCACHEPREFIX"] = os.environ["PYTHONPYCACHEPREFIX"]
        print(
            f"INERT_REPLAY_BEGIN shell=/bin/sh cwd={ROOT} uid={uid} "
            f"TMPDIR={temp_root} guide_sha256={before[GUIDE]} "
            f"contract_sha256={before[CONTRACT]} harness_sha256={before[paths[2]]}",
            flush=True,
        )
        try:
            require_nonroot_linux()
            result = subprocess.run(
                ["/bin/sh"], input=shell, cwd=ROOT, env=environment,
                capture_output=True, text=True, check=False, timeout=30,
            )
            verify_transcript(result)
            print("INERT_REPLAY_PASS nested_tests=13 (separate from outer suite count)", flush=True)
        finally:
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            self.assertEqual(before, after, "guide/contract/harness changed during replay")


if __name__ == "__main__":
    unittest.main()
