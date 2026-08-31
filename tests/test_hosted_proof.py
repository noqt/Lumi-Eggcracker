from __future__ import annotations

import subprocess
import unittest
from collections.abc import Sequence

from lumi_eggcracker.hosted_proof import HostedProofError, start_hosted_proof


def result(
    command: Sequence[str],
    *,
    returncode: int = 0,
    stdout: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


class FakeRunner:
    def __init__(self, responses: list[subprocess.CompletedProcess[str]]) -> None:
        self.responses = responses
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(tuple(command))
        if not self.responses:
            raise AssertionError(f"unexpected command: {command}")
        return self.responses.pop(0)


class HostedProofTests(unittest.TestCase):
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
            ),
            runner.commands[-1],
        )

    def test_missing_fork_is_created_without_a_clone(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), returncode=1),
                result(("fork",)),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\ttrunk\n"),
                result(("enable",)),
                result(("dispatch",)),
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

    def test_already_active_workflow_is_safe_after_enable_error(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("enable",), returncode=1),
                result(("state",), stdout="active\n"),
                result(("dispatch",)),
            ]
        )

        start_hosted_proof(acknowledged=True, runner=runner)
        self.assertEqual("gh", runner.commands[-1][0])

    def test_disabled_workflow_after_enable_error_is_refused(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("enable",), returncode=1),
                result(("state",), stdout="disabled_manually\n"),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "could not enable"):
            start_hosted_proof(acknowledged=True, runner=runner)


if __name__ == "__main__":
    unittest.main()
