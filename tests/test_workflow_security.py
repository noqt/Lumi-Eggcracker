from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
USES_LINE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(?P<value>.+?)\s*$")
FULL_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def mutable_external_action_references(workflow: str) -> list[tuple[int, str]]:
    mutable: list[tuple[int, str]] = []
    for line_number, line in enumerate(workflow.splitlines(), start=1):
        match = USES_LINE.match(line)
        if match is None:
            continue

        reference = match.group("value").split(" #", maxsplit=1)[0].strip()
        if len(reference) >= 2 and reference[0] == reference[-1] and reference[0] in "\"'":
            reference = reference[1:-1]
        if reference.startswith(("./", "docker://")):
            continue

        action, separator, revision = reference.rpartition("@")
        if not separator or len(action.split("/")) < 2 or FULL_COMMIT_SHA.fullmatch(revision) is None:
            mutable.append((line_number, reference))
    return mutable


class WorkflowSecurityTests(unittest.TestCase):
    def test_repository_workflows_pin_external_actions_to_full_commit_shas(self) -> None:
        workflows = sorted(WORKFLOW_DIRECTORY.glob("*.yml"))
        workflows.extend(sorted(WORKFLOW_DIRECTORY.glob("*.yaml")))
        self.assertTrue(workflows)

        violations = {
            path.relative_to(ROOT).as_posix(): mutable_external_action_references(
                path.read_text(encoding="utf-8")
            )
            for path in workflows
        }
        self.assertEqual({}, {path: refs for path, refs in violations.items() if refs})

    def test_mutable_external_action_tag_is_rejected(self) -> None:
        workflow = "steps:\n  - uses: actions/checkout@v6\n"
        self.assertEqual([(2, "actions/checkout@v6")], mutable_external_action_references(workflow))

    def test_full_commit_sha_and_local_action_are_allowed(self) -> None:
        workflow = (
            "steps:\n"
            "  - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803\n"
            "  - uses: ./.github/actions/local-check\n"
        )
        self.assertEqual([], mutable_external_action_references(workflow))


if __name__ == "__main__":
    unittest.main()
