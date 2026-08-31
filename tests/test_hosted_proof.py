from __future__ import annotations

import ast
import hashlib
import re
import subprocess
import unittest
from collections.abc import Sequence
from pathlib import Path

from lumi_eggcracker.hosted_proof import (
    REVIEWED_WORKFLOW_BLOB,
    HostedProofError,
    start_hosted_proof,
)

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
                result(("workflow-identity",), stdout="d96a286b5ee811845262fedef42aba96cedeb955\n"),
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
                result(("workflow-identity",), stdout="d96a286b5ee811845262fedef42aba96cedeb955\n"),
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
                    stdout="d96a286b5ee811845262fedef42aba96cedeb955\n",
                ),
                result(("enable",)),
                result(("dispatch",)),
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
        self.assertEqual(branch, runner.commands[-1][7])

    def test_already_active_workflow_is_safe_after_enable_error(self) -> None:
        runner = FakeRunner(
            [
                result(("auth",)),
                result(("identity",), stdout="operator\n"),
                result(("metadata",), stdout="true\tnoqt/Lumi-Eggcracker\tmain\n"),
                result(("workflow-identity",), stdout="d96a286b5ee811845262fedef42aba96cedeb955\n"),
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
                result(("workflow-identity",), stdout="d96a286b5ee811845262fedef42aba96cedeb955\n"),
                result(("enable",), returncode=1),
                result(("state",), stdout="disabled_manually\n"),
            ]
        )

        with self.assertRaisesRegex(HostedProofError, "could not enable"):
            start_hosted_proof(acknowledged=True, runner=runner)


if __name__ == "__main__":
    unittest.main()
