from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import unittest
from collections.abc import Sequence
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from lumi_eggcracker import hosted_proof as hosted_proof_module
from lumi_eggcracker.hosted_proof import (
    REVIEWED_WORKFLOW_BLOB,
    HostedProofError,
)
from lumi_eggcracker.hosted_proof import start_hosted_proof as _start_hosted_proof

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "containment-probe.yml"
BOUND_PROBE_SOURCES = (
    Path("scripts/containment_probe.py"),
    Path("src/lumi_eggcracker/__init__.py"),
    Path("src/lumi_eggcracker/adoption.py"),
    Path("src/lumi_eggcracker/containment.py"),
    Path("src/lumi_eggcracker/containment_probe.py"),
    Path("src/lumi_eggcracker/discovery.py"),
    Path("src/lumi_eggcracker/jsonio.py"),
)
CORRELATION = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)
RUN_TITLE = f"Containment probe ({CORRELATION})"


def result(
    command: Sequence[str],
    *,
    returncode: int = 0,
    stdout: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(
        self,
        responses: list[subprocess.CompletedProcess[str] | BaseException],
    ) -> None:
        self.responses = responses
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(tuple(command))
        if not self.responses:
            raise AssertionError(f"unexpected command: {command}")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def start_hosted_proof(
    *,
    acknowledged: bool,
    runner: FakeRunner,
    **overrides: object,
) -> str:
    options = {
        "sleeper": lambda _seconds: None,
        "monotonic": lambda: 0.0,
        "utc_now": lambda: NOW,
        "token_factory": lambda size: CORRELATION if size == 16 else "",
        **overrides,
    }
    return _start_hosted_proof(
        acknowledged=acknowledged,
        runner=runner,
        **options,  # type: ignore[arg-type]
    )


def workflow_run(
    run_id: int,
    *,
    repository: str = "operator/Lumi-Eggcracker",
    actor: str = "operator",
    branch: str = "main",
    event: str = "workflow_dispatch",
    title: str = RUN_TITLE,
    created_at: datetime = NOW,
) -> dict[str, object]:
    return {
        "id": run_id,
        "html_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        "display_title": title,
        "event": event,
        "head_branch": branch,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "actor": {"login": actor},
        "repository": {"full_name": repository},
    }


def run_list(*runs: dict[str, object], returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return result(
        ("run-list",),
        returncode=returncode,
        stdout=json.dumps({"workflow_runs": list(runs)}),
    )


def existing_fork_responses(
    *after_dispatch: subprocess.CompletedProcess[str] | BaseException,
    dispatch_stdout: str = "",
) -> list[subprocess.CompletedProcess[str] | BaseException]:
    return [
        result(("auth",)),
        result(("identity",), stdout="operator\n"),
        result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
        result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
        result(("enable",)),
        result(("dispatch",), stdout=dispatch_stdout),
        *after_dispatch,
    ]


class HostedProofTests(unittest.TestCase):
    def test_cli_prints_run_and_result_route(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        output = StringIO()
        with (
            patch.object(hosted_proof_module.shutil, "which", return_value="gh"),
            patch.object(hosted_proof_module, "start_hosted_proof", return_value=url) as starter,
            redirect_stdout(output),
        ):
            status = hosted_proof_module.main(
                ["--i-understand-this-kills-a-test-tree"]
            )

        self.assertEqual(0, status)
        starter.assert_called_once_with(acknowledged=True)
        self.assertEqual(
            [
                f"Hosted proof dispatched: {url}",
                (
                    "Watch from this terminal: "
                    "gh run watch 123 --repo github.com/operator/Lumi-Eggcracker "
                    "--exit-status"
                ),
                (
                    "Read the bounded result: "
                    "gh run view 123 --repo github.com/operator/Lumi-Eggcracker --log"
                ),
                (
                    "After it finishes, share the public run or friction: "
                    f"{hosted_proof_module.RESULT_FORM_URL}"
                ),
            ],
            output.getvalue().splitlines(),
        )

    def test_cli_waits_for_exact_run_and_prints_bounded_log(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        output = StringIO()
        with (
            patch.object(hosted_proof_module.shutil, "which", return_value="gh"),
            patch.object(hosted_proof_module, "start_hosted_proof", return_value=url),
            patch.object(
                hosted_proof_module,
                "follow_hosted_proof",
                return_value=('{"result":"TERMINATED"}', True),
            ) as follower,
            redirect_stdout(output),
        ):
            status = hosted_proof_module.main(
                ["--i-understand-this-kills-a-test-tree", "--wait"]
            )

        self.assertEqual(0, status)
        follower.assert_called_once_with(url)
        self.assertEqual(
            [
                f"Hosted proof dispatched: {url}",
                "Hosted proof finished. Bounded public workflow log:",
                '{"result":"TERMINATED"}',
                (
                    "After it finishes, share the public run or friction: "
                    f"{hosted_proof_module.RESULT_FORM_URL}"
                ),
                f"Hosted proof result: PASS ({url})",
            ],
            output.getvalue().splitlines(),
        )
        self.assertEqual(
            f"Hosted proof result: PASS ({url})",
            output.getvalue().splitlines()[-1],
        )

    def test_follow_exact_run_waits_then_reads_bounded_log(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        runner = FakeRunner(
            [
                result(("watch",)),
                result(
                    ("status",),
                    stdout=json.dumps(
                        {"status": "completed", "conclusion": "success", "url": url}
                    ),
                ),
                result(("log",), stdout='{"result":"TERMINATED"}\n'),
            ]
        )

        self.assertEqual(
            ('{"result":"TERMINATED"}', True),
            hosted_proof_module.follow_hosted_proof(url, runner=runner),
        )
        self.assertEqual(
            [
                (
                    "gh",
                    "run",
                    "watch",
                    "123",
                    "--repo",
                    "github.com/operator/Lumi-Eggcracker",
                    "--exit-status",
                ),
                (
                    "gh",
                    "run",
                    "view",
                    "123",
                    "--repo",
                    "github.com/operator/Lumi-Eggcracker",
                    "--json",
                    "status,conclusion,url",
                ),
                (
                    "gh",
                    "run",
                    "view",
                    "123",
                    "--repo",
                    "github.com/operator/Lumi-Eggcracker",
                    "--log",
                ),
            ],
            runner.commands,
        )

    def test_follow_failed_run_still_returns_its_bounded_log(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        runner = FakeRunner(
            [
                result(("watch",), returncode=1),
                result(
                    ("status",),
                    stdout=json.dumps(
                        {"status": "completed", "conclusion": "failure", "url": url}
                    ),
                ),
                result(("log",), stdout='{"result":"FAILED"}\n'),
            ]
        )

        self.assertEqual(
            ('{"result":"FAILED"}', False),
            hosted_proof_module.follow_hosted_proof(url, runner=runner),
        )

    def test_follow_watch_timeout_is_not_reported_as_completion(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        runner = FakeRunner([subprocess.TimeoutExpired(cmd=("gh", "run", "watch"), timeout=900)])

        with self.assertRaisesRegex(HostedProofError, "could not complete.*wait"):
            hosted_proof_module.follow_hosted_proof(url, runner=runner)
        self.assertEqual(1, len(runner.commands))

    def test_follow_noncompleted_status_is_not_reported_as_finished(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        runner = FakeRunner(
            [
                result(("watch",), returncode=1),
                result(
                    ("status",),
                    stdout=json.dumps(
                        {"status": "in_progress", "conclusion": "", "url": url}
                    ),
                ),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "did not reach a completed state"):
            hosted_proof_module.follow_hosted_proof(url, runner=runner)
        self.assertEqual(2, len(runner.commands))

    def test_follow_rejects_unavailable_status_and_log(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        completed = json.dumps(
            {"status": "completed", "conclusion": "success", "url": url}
        )
        cases = (
            (
                [result(("watch",)), result(("status",), returncode=1)],
                "could not read the hosted-proof status",
            ),
            (
                [
                    result(("watch",)),
                    result(("status",), stdout=completed),
                    result(("log",), returncode=1),
                ],
                "log was unavailable",
            ),
            (
                [
                    result(("watch",)),
                    result(("status",), stdout=completed),
                    result(("log",), stdout=""),
                ],
                "log was empty",
            ),
        )
        for responses, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                HostedProofError, message
            ):
                hosted_proof_module.follow_hosted_proof(
                    url,
                    runner=FakeRunner(responses),
                )

    def test_follow_log_byte_bound_is_exact(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        completed = json.dumps(
            {"status": "completed", "conclusion": "success", "url": url}
        )
        exact = "x" * hosted_proof_module.FOLLOW_LOG_MAX_BYTES
        runner = FakeRunner(
            [
                result(("watch",)),
                result(("status",), stdout=completed),
                result(("log",), stdout=exact),
            ]
        )
        self.assertEqual(
            (exact, True),
            hosted_proof_module.follow_hosted_proof(url, runner=runner),
        )

        oversized = FakeRunner(
            [
                result(("watch",)),
                result(("status",), stdout=completed),
                result(
                    ("log",),
                    stdout="x" * (hosted_proof_module.FOLLOW_LOG_MAX_BYTES + 1),
                ),
            ]
        )
        with self.assertRaisesRegex(HostedProofError, "safe display bound"):
            hosted_proof_module.follow_hosted_proof(url, runner=oversized)

    def test_cli_wait_returns_failure_after_printing_failed_log(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        output = StringIO()
        with (
            patch.object(hosted_proof_module.shutil, "which", return_value="gh"),
            patch.object(hosted_proof_module, "start_hosted_proof", return_value=url),
            patch.object(
                hosted_proof_module,
                "follow_hosted_proof",
                return_value=('{"result":"FAILED"}', False),
            ),
            redirect_stdout(output),
        ):
            status = hosted_proof_module.main(
                ["--i-understand-this-kills-a-test-tree", "--wait"]
            )

        self.assertEqual(1, status)
        self.assertIn('{"result":"FAILED"}', output.getvalue().splitlines())
        self.assertIn(
            f"Hosted proof result: FAIL ({url})",
            output.getvalue().splitlines(),
        )
        self.assertIn(
            f"Hosted proof did not pass; inspect {url}.",
            output.getvalue().splitlines(),
        )
        self.assertEqual(
            f"Hosted proof result: FAIL ({url})",
            output.getvalue().splitlines()[-1],
        )

    def test_follow_refuses_non_exact_url_before_github_call(self) -> None:
        runner = FakeRunner([])
        with self.assertRaisesRegex(HostedProofError, "exact hosted-proof run URL"):
            hosted_proof_module.follow_hosted_proof(
                "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
                "containment-probe.yml",
                runner=runner,
            )
        self.assertEqual([], runner.commands)

    def test_watch_command_requires_exact_safe_github_run_url(self) -> None:
        self.assertEqual(
            (
                "gh run watch 123 --repo github.com/operator/Lumi-Eggcracker "
                "--exit-status"
            ),
            hosted_proof_module._watch_command(
                "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
            ),
        )
        self.assertEqual(
            "gh run view 123 --repo github.com/operator/Lumi-Eggcracker --log",
            hosted_proof_module._log_command(
                "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
            ),
        )
        rejected = (
            "http://github.com/operator/Lumi-Eggcracker/actions/runs/123",
            "https://gitlab.com/operator/Lumi-Eggcracker/actions/runs/123",
            "https://github.com/operator/other/actions/runs/123",
            "https://github.com/operator/Lumi-Eggcracker/actions/runs/0",
            "https://github.com/operator/Lumi-Eggcracker/actions/runs/123?x=1",
            "https://github.com/operator/Lumi-Eggcracker/actions/runs/123#fragment",
            "https://github.com/bad;name/Lumi-Eggcracker/actions/runs/123",
        )
        for url in rejected:
            with self.subTest(url=url):
                self.assertIsNone(hosted_proof_module._watch_command(url))
                self.assertIsNone(hosted_proof_module._log_command(url))

    def test_cli_omits_watch_command_for_fallback_workflow_page(self) -> None:
        url = (
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml"
        )
        output = StringIO()
        with (
            patch.object(hosted_proof_module.shutil, "which", return_value="gh"),
            patch.object(hosted_proof_module, "start_hosted_proof", return_value=url),
            redirect_stdout(output),
        ):
            status = hosted_proof_module.main(
                ["--i-understand-this-kills-a-test-tree"]
            )

        self.assertEqual(0, status)
        self.assertEqual(
            [
                f"Hosted proof dispatched: {url}",
                (
                    "After it finishes, share the public run or friction: "
                    f"{hosted_proof_module.RESULT_FORM_URL}"
                ),
            ],
            output.getvalue().splitlines(),
        )

    def test_cli_wait_fallback_does_not_guess_a_run(self) -> None:
        url = (
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml"
        )
        output = StringIO()
        with (
            patch.object(hosted_proof_module.shutil, "which", return_value="gh"),
            patch.object(hosted_proof_module, "start_hosted_proof", return_value=url),
            patch.object(hosted_proof_module, "follow_hosted_proof") as follower,
            redirect_stdout(output),
        ):
            status = hosted_proof_module.main(
                ["--i-understand-this-kills-a-test-tree", "--wait"]
            )

        self.assertEqual(1, status)
        follower.assert_not_called()
        self.assertIn(
            "Automatic wait unavailable because the exact run URL was not resolved.",
            output.getvalue().splitlines(),
        )

    def test_reviewed_workflow_blob_matches_current_workflow(self) -> None:
        raw = WORKFLOW.read_bytes()
        framed = f"blob {len(raw)}\0".encode("ascii") + raw
        self.assertEqual(
            hashlib.sha1(framed, usedforsecurity=False).hexdigest(),
            REVIEWED_WORKFLOW_BLOB,
        )

    def test_workflow_qualified_digest_matches_current_probe_sources(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        expected = re.findall(r"QUALIFIED_SOURCE_SHA256: ([0-9a-f]{64})", workflow)
        self.assertEqual(1, len(expected))

        digest = hashlib.sha256()
        for relative in BOUND_PROBE_SOURCES:
            raw = (ROOT / relative).read_bytes()
            name = relative.as_posix().encode("ascii")
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name)
            digest.update(len(raw).to_bytes(8, "big"))
            digest.update(raw)
        self.assertEqual(expected[0], digest.hexdigest())

    def test_qualified_source_set_covers_local_runtime_imports(self) -> None:
        bound_modules = {
            "lumi_eggcracker"
            if relative.name == "__init__.py"
            else ".".join(relative.with_suffix("").parts[1:])
            for relative in BOUND_PROBE_SOURCES
            if relative.parts[0] == "src"
        }

        imported_modules: set[str] = set()
        for relative in BOUND_PROBE_SOURCES:
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if node.level and node.module:
                        imported_modules.add(f"lumi_eggcracker.{node.module}")
                    elif node.level:
                        imported_modules.update(
                            f"lumi_eggcracker.{alias.name}" for alias in node.names
                        )
                    elif node.module:
                        imported_modules.add(node.module)

        local_imports = {
            module
            for module in imported_modules
            if module == "lumi_eggcracker" or module.startswith("lumi_eggcracker.")
        }
        self.assertLessEqual(local_imports, bound_modules)

    def test_workflow_does_not_pin_unrelated_source_trees(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("QUALIFIED_SRC_TREE", workflow)
        self.assertNotIn("QUALIFIED_SCRIPTS_TREE", workflow)

    def test_workflow_correlation_is_display_only_with_manual_browser_default(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        header, jobs = workflow.split("\njobs:\n", 1)
        self.assertIn(
            'run-name: "Containment probe (${{ inputs.run_correlation_id || \'manual\' }})"',
            header,
        )
        self.assertRegex(
            header,
            r"run_correlation_id:\n(?: {8}.+\n){3} {8}default: manual",
        )
        self.assertNotIn("run_correlation_id", jobs)

    def test_workflow_rejects_import_shadowing_before_path_insertion(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        guard = workflow.index("refuse SOURCE_IMPORT_PATH_UNQUALIFIED")
        path_insertion = workflow.index('sys.path.insert(0, str(Path.cwd() / "src"))')
        self.assertLess(guard, path_insertion)
        self.assertIn("len(entries) != 1", workflow)
        self.assertIn("entries[0] != expected", workflow)
        self.assertIn("entries[0].is_symlink()", workflow)
        self.assertIn("not entries[0].is_dir()", workflow)

    def test_acknowledgement_is_required_before_any_github_call(self) -> None:
        runner = FakeRunner([])
        with self.assertRaisesRegex(HostedProofError, "acknowledgement"):
            start_hosted_proof(acknowledged=False, runner=runner)
        self.assertEqual([], runner.commands)

    def test_existing_expected_fork_is_enabled_and_dispatched(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/123"
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
                result(("enable",)),
                result(("dispatch",), stdout=f"{url}\n"),
            ]
        )

        self.assertEqual(url, start_hosted_proof(acknowledged=True, runner=runner))
        self.assertEqual(
            (
                "gh",
                "workflow",
                "run",
                "containment-probe.yml",
                "--repo",
                "github.com/operator/Lumi-Eggcracker",
                "--ref",
                "main",
                "--raw-field",
                "i_understand_this_kills_a_test_tree=true",
                "--raw-field",
                f"run_correlation_id={CORRELATION}",
            ),
            runner.commands[-1],
        )

    def test_dispatch_time_is_captured_immediately_before_dispatch(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/124"
        runner = FakeRunner(existing_fork_responses(dispatch_stdout=f"{url}\n"))
        observations: list[tuple[str, ...]] = []

        def utc_now() -> datetime:
            observations.append(runner.commands[-1])
            return NOW

        self.assertEqual(
            url,
            start_hosted_proof(
                acknowledged=True,
                runner=runner,
                utc_now=utc_now,
            ),
        )
        self.assertEqual(1, len(observations))
        self.assertEqual(("workflow", "enable"), observations[0][1:3])

    def test_missing_fork_is_created_without_a_clone(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), returncode=1),
                result(("fork",)),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\ttrunk\n"),
                result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
                result(("enable",)),
                result(("dispatch",)),
                run_list(returncode=1),
            ]
        )

        url = start_hosted_proof(acknowledged=True, runner=runner)
        self.assertEqual(
            (
                "gh",
                "repo",
                "fork",
                "github.com/noqt/Lumi-Eggcracker",
                "--clone=false",
                "--default-branch-only",
            ),
            runner.commands[3],
        )
        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/containment-probe.yml",
            url,
        )

    def test_new_fork_metadata_propagation_is_retried_before_dispatch(self) -> None:
        sleeps: list[float] = []
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), returncode=1),
                result(("fork",)),
                result(("metadata",), returncode=1),
                result(("metadata",), returncode=1),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
                result(("enable",)),
                result(("dispatch",)),
                run_list(returncode=1),
            ]
        )

        url = start_hosted_proof(
            acknowledged=True,
            runner=runner,
            sleeper=sleeps.append,
        )

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/containment-probe.yml",
            url,
        )
        self.assertEqual([1.0, 1.0], sleeps)

    def test_new_fork_metadata_readiness_wait_is_bounded(self) -> None:
        sleeps: list[float] = []
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), returncode=1),
                result(("fork",)),
                *[result(("metadata",), returncode=1) for _ in range(5)],
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "not ready"):
            start_hosted_proof(
                acknowledged=True,
                runner=runner,
                sleeper=sleeps.append,
            )

        self.assertEqual([1.0, 1.0, 1.0, 1.0], sleeps)

    def test_unrelated_repository_collision_is_refused(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="false\t\tmain\n"),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "not a fork"):
            start_hosted_proof(acknowledged=True, runner=runner)
        self.assertEqual(3, len(runner.commands))

    def test_diverged_fork_workflow_is_refused_before_enable_or_dispatch(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmodified-default\n"),
                result(("workflow-identity",), stdout="0123456789abcdef0123456789abcdef01234567\n"),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "does not match"):
            start_hosted_proof(acknowledged=True, runner=runner)
        self.assertEqual(4, len(runner.commands))
        self.assertEqual("api", runner.commands[-1][1])

    def test_exotic_branch_is_encoded_for_verification_and_reused_for_dispatch(self) -> None:
        branch = "release&proof#1"
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(
                    ("metadata",),
                    stdout=f"true\tnoqt/Lumi-Eggcracker\t{branch}\n",
                ),
                result(
                    ("workflow-identity",),
                    stdout=f"{REVIEWED_WORKFLOW_BLOB}\n",
                ),
                result(("enable",)),
                result(("dispatch",)),
                run_list(returncode=1),
            ]
        )

        start_hosted_proof(acknowledged=True, runner=runner)

        self.assertEqual(
            (
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "repos/operator/Lumi-Eggcracker/contents/.github/workflows/containment-probe.yml",
                "--raw-field",
                f"ref={branch}",
                "--jq",
                ".sha",
            ),
            runner.commands[3],
        )
        dispatch = next(command for command in runner.commands if command[1:3] == ("workflow", "run"))
        self.assertEqual(branch, dispatch[7])

    def test_already_active_workflow_is_safe_after_enable_error(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
                result(("enable",), returncode=1),
                result(("state",), stdout="active\n"),
                result(("dispatch",)),
                run_list(returncode=1),
            ]
        )

        start_hosted_proof(acknowledged=True, runner=runner)
        self.assertEqual("gh", runner.commands[-1][0])

    def test_unique_correlated_run_is_returned_with_exact_query_scope(self) -> None:
        url = "https://github.com/operator/Lumi-Eggcracker/actions/runs/321"
        runner = FakeRunner(existing_fork_responses(run_list(workflow_run(321))))

        self.assertEqual(url, start_hosted_proof(acknowledged=True, runner=runner))
        self.assertEqual(
            (
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "repos/operator/Lumi-Eggcracker/actions/workflows/containment-probe.yml/runs",
                "--raw-field",
                "actor=operator",
                "--raw-field",
                "branch=main",
                "--raw-field",
                "event=workflow_dispatch",
                "--raw-field",
                "created=>=2026-08-31T23:55:00Z",
                "--raw-field",
                "per_page=20",
            ),
            runner.commands[-1],
        )

    def test_wrong_direct_url_is_ignored_before_unique_correlation(self) -> None:
        expected = "https://github.com/operator/Lumi-Eggcracker/actions/runs/322"
        wrong = "https://github.com/other/Lumi-Eggcracker/actions/runs/999\n"
        runner = FakeRunner(
            existing_fork_responses(run_list(workflow_run(322)), dispatch_stdout=wrong)
        )

        self.assertEqual(expected, start_hosted_proof(acknowledged=True, runner=runner))

    def test_zero_run_id_from_dispatch_is_not_accepted(self) -> None:
        zero = "https://github.com/operator/Lumi-Eggcracker/actions/runs/0\n"
        runner = FakeRunner(existing_fork_responses(run_list(returncode=1), dispatch_stdout=zero))

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(acknowledged=True, runner=runner),
        )

    def test_correlation_must_be_128_bit_lowercase_hex(self) -> None:
        runner = FakeRunner([])
        with self.assertRaisesRegex(HostedProofError, "correlation"):
            start_hosted_proof(
                acknowledged=True,
                runner=runner,
                token_factory=lambda _size: "NOT-SAFE",
            )
        self.assertEqual([], runner.commands)

    def test_zero_correlated_runs_retries_then_returns_workflow_page(self) -> None:
        runner = FakeRunner(existing_fork_responses(run_list(), run_list(), run_list()))

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(acknowledged=True, runner=runner),
        )
        self.assertEqual(
            3,
            sum(
                command[1] == "api"
                and len(command) > 6
                and command[6].endswith("/actions/workflows/containment-probe.yml/runs")
                for command in runner.commands
            ),
        )

    def test_multiple_exact_matches_return_workflow_page_without_guessing(self) -> None:
        runner = FakeRunner(
            existing_fork_responses(run_list(workflow_run(323), workflow_run(324)))
        )

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(acknowledged=True, runner=runner),
        )

    def test_concurrent_unrelated_run_does_not_hide_unique_exact_match(self) -> None:
        runner = FakeRunner(
            existing_fork_responses(
                run_list(
                    workflow_run(325, title="Containment probe (another-caller)"),
                    workflow_run(326),
                )
            )
        )

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/runs/326",
            start_hosted_proof(acknowledged=True, runner=runner),
        )

    def test_stale_and_implausibly_future_titles_return_workflow_page(self) -> None:
        stale = workflow_run(327, created_at=NOW - timedelta(minutes=6))
        future = workflow_run(328, created_at=NOW + timedelta(minutes=2))
        runner = FakeRunner(
            existing_fork_responses(
                run_list(stale, future),
                run_list(stale, future),
                run_list(stale, future),
            )
        )

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(acknowledged=True, runner=runner),
        )

    def test_wrong_scope_entries_return_workflow_page(self) -> None:
        wrong_repository = workflow_run(328, repository="other/Lumi-Eggcracker")
        wrong_actor = workflow_run(329, actor="other")
        wrong_branch = workflow_run(330, branch="other")
        wrong_event = workflow_run(331, event="push")
        wrong_url = workflow_run(332)
        wrong_url["html_url"] = "https://github.com/operator/other/actions/runs/332"
        entries = (wrong_repository, wrong_actor, wrong_branch, wrong_event, wrong_url)
        runner = FakeRunner(
            existing_fork_responses(run_list(*entries), run_list(*entries), run_list(*entries))
        )

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(acknowledged=True, runner=runner),
        )

    def test_malformed_or_failed_listing_returns_workflow_page(self) -> None:
        for response in (
            result(("malformed",), stdout="{"),
            run_list(returncode=1),
            subprocess.TimeoutExpired(cmd=("gh", "api"), timeout=5),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte"),
        ):
            with self.subTest(response=type(response).__name__):
                runner = FakeRunner(existing_fork_responses(response))
                self.assertEqual(
                    "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
                    "containment-probe.yml",
                    start_hosted_proof(acknowledged=True, runner=runner),
                )

    def test_recursive_json_failure_returns_workflow_page(self) -> None:
        runner = FakeRunner(existing_fork_responses(result(("listing",), stdout="{}")))

        with patch(
            "lumi_eggcracker.hosted_proof.json.loads",
            side_effect=RecursionError("synthetic nested JSON"),
        ):
            self.assertEqual(
                "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
                "containment-probe.yml",
                start_hosted_proof(acknowledged=True, runner=runner),
            )

    def test_late_unique_lookup_result_is_not_accepted(self) -> None:
        ticks = iter((0.0, 0.0, 17.1))
        runner = FakeRunner(existing_fork_responses(run_list(workflow_run(333))))

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(
                acknowledged=True,
                runner=runner,
                monotonic=lambda: next(ticks),
            ),
        )

    def test_overall_lookup_deadline_bounds_calls_and_sleep(self) -> None:
        ticks = iter((0.0, 0.0, 0.0, 16.5, 17.0))
        delays: list[float] = []
        runner = FakeRunner(existing_fork_responses(run_list()))

        self.assertEqual(
            "https://github.com/operator/Lumi-Eggcracker/actions/workflows/"
            "containment-probe.yml",
            start_hosted_proof(
                acknowledged=True,
                runner=runner,
                monotonic=lambda: next(ticks),
                sleeper=delays.append,
            ),
        )
        self.assertEqual([0.5], delays)
        self.assertEqual(1, sum("/actions/workflows/" in " ".join(command) for command in runner.commands))

    def test_disabled_workflow_after_enable_error_is_refused(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("workflow-identity",), stdout=f"{REVIEWED_WORKFLOW_BLOB}\n"),
                result(("enable",), returncode=1),
                result(("state",), stdout="disabled_manually\n"),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "could not enable"):
            start_hosted_proof(acknowledged=True, runner=runner)


if __name__ == "__main__":
    unittest.main()
