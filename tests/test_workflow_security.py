from __future__ import annotations

import unittest
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIRECTORY = ROOT / ".github" / "workflows"
FULL_COMMIT_SHA_LENGTH = 40


def mapping_values(node: Node, name: str) -> list[Node]:
    if not isinstance(node, MappingNode):
        return []
    return [
        value
        for key, value in node.value
        if isinstance(key, ScalarNode) and key.value == name
    ]


def uses_references(node: Node) -> list[tuple[int, str]]:
    references: list[tuple[int, str]] = []
    if not isinstance(node, MappingNode):
        return references
    for key, value in node.value:
        if isinstance(key, ScalarNode) and key.value == "uses":
            reference = value.value if isinstance(value, ScalarNode) else "<non-scalar>"
            references.append((key.start_mark.line + 1, reference))
    return references


def step_action_references(node: Node, active_nodes: set[int] | None = None) -> list[tuple[int, str]]:
    if not isinstance(node, MappingNode):
        return []
    active = set() if active_nodes is None else active_nodes
    identity = id(node)
    if identity in active:
        return []

    active.add(identity)
    references = uses_references(node)
    for parallel in mapping_values(node, "parallel"):
        if isinstance(parallel, SequenceNode):
            for child in parallel.value:
                references.extend(step_action_references(child, active))
    active.remove(identity)
    return references


def action_references(document: Node) -> list[tuple[int, str]]:
    references: list[tuple[int, str]] = []
    for jobs in mapping_values(document, "jobs"):
        if not isinstance(jobs, MappingNode):
            continue
        for _, job in jobs.value:
            references.extend(uses_references(job))
            for steps in mapping_values(job, "steps"):
                if isinstance(steps, SequenceNode):
                    for step in steps.value:
                        references.extend(step_action_references(step))
    return references


def mutable_external_action_references(workflow: str) -> list[tuple[int, str]]:
    mutable: list[tuple[int, str]] = []
    for document in yaml.compose_all(workflow):
        if document is None:
            continue
        for line_number, reference in action_references(document):
            if reference.startswith(("./", "$/", "docker://")):
                continue

            action, separator, revision = reference.rpartition("@")
            components = action.split("/")
            full_sha = len(revision) == FULL_COMMIT_SHA_LENGTH and all(
                character in "0123456789abcdefABCDEF" for character in revision
            )
            if (
                not separator
                or len(components) < 2
                or any(not part for part in components)
                or not full_sha
            ):
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

    def test_mutable_external_action_tags_are_rejected_across_yaml_styles(self) -> None:
        workflow = (
            "jobs:\n"
            "  inline: {uses: noqt/reusable/.github/workflows/check.yml@main}\n"
            "  quoted:\n"
            '    steps: [{"uses": actions/checkout@v6}]\n'
        )
        self.assertEqual(
            [
                (2, "noqt/reusable/.github/workflows/check.yml@main"),
                (4, "actions/checkout@v6"),
            ],
            mutable_external_action_references(workflow),
        )

    def test_mutable_action_in_parallel_step_group_is_rejected(self) -> None:
        workflow = (
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - parallel:\n"
            "          - uses: actions/checkout@v6\n"
            "          - uses: example/action@0123456789abcdef0123456789abcdef01234567\n"
        )
        self.assertEqual(
            [(5, "actions/checkout@v6")],
            mutable_external_action_references(workflow),
        )

    def test_full_commit_sha_local_action_and_script_text_are_allowed(self) -> None:
        workflow = (
            "jobs:\n"
            "  reusable:\n"
            "    uses: noqt/reusable/.github/workflows/check.yml@0123456789abcdef0123456789abcdef01234567\n"
            "  same-repository:\n"
            "    uses: $/.github/workflows/check.yml\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6\n"
            "      - uses: ./.github/actions/local-check\n"
            "      - uses: $/.github/actions/local-check\n"
            "      - run: |\n"
            "          printf 'uses: actions/checkout@v6'\n"
            "      - env: {uses: actions/checkout@v6}\n"
            "        run: echo safe\n"
        )
        self.assertEqual([], mutable_external_action_references(workflow))

    def test_only_exactly_40_hexadecimal_revision_characters_are_allowed(self) -> None:
        revisions = {
            "39": "a" * 39,
            "40": "b" * 40,
            "41": "c" * 41,
            "non-hex": "g" * 40,
        }
        workflow = "jobs:\n  test:\n    steps:\n" + "".join(
            f"      - uses: example/action@{revision}\n" for revision in revisions.values()
        )
        self.assertEqual(
            [
                (4, f"example/action@{revisions['39']}"),
                (6, f"example/action@{revisions['41']}"),
                (7, f"example/action@{revisions['non-hex']}"),
            ],
            mutable_external_action_references(workflow),
        )


if __name__ == "__main__":
    unittest.main()
