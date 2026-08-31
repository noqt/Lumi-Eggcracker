"""Start the reviewed hosted containment proof in a caller-owned GitHub fork."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence

HOST = "github.com"
UPSTREAM = "noqt/Lumi-Eggcracker"
REPOSITORY_NAME = "Lumi-Eggcracker"
WORKFLOW = "containment-probe.yml"
REVIEWED_WORKFLOW_BLOB = "7f3526bcd3aad11c70fe20cf997881908b0b64ad"
ACKNOWLEDGEMENT = "i_understand_this_kills_a_test_tree=true"
RUN_URL = re.compile(r"^https://github\.com/[^/]+/[^/]+/actions/runs/[0-9]+$")

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class HostedProofError(RuntimeError):
    """A bounded, user-actionable hosted-proof startup failure."""


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        env={**os.environ, "GH_PROMPT_DISABLED": "1"},
        text=True,
        timeout=60,
    )


def _call(
    runner: Runner,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(("gh", *arguments))
    except (OSError, subprocess.SubprocessError) as error:
        raise HostedProofError("GitHub CLI failed before dispatch completed.") from error


def _fork_metadata(
    runner: Runner,
    repository: str,
) -> subprocess.CompletedProcess[str]:
    return _call(
        runner,
        "api",
        "--hostname",
        HOST,
        f"repos/{repository}",
        "--jq",
        "[.fork,.parent.full_name,.default_branch] | @tsv",
    )


def _parse_metadata(output: str) -> tuple[bool, str, str]:
    fields = output.strip().split("\t")
    if len(fields) != 3 or fields[0] not in {"true", "false"}:
        raise HostedProofError("GitHub returned an unexpected fork description.")
    parent, branch = fields[1:]
    if not branch or any(character.isspace() for character in branch):
        raise HostedProofError("GitHub returned an unsafe or incomplete fork description.")
    return fields[0] == "true", parent, branch


def start_hosted_proof(
    *,
    acknowledged: bool,
    runner: Runner = _default_runner,
) -> str:
    """Create or reuse the caller's exact fork and dispatch the reviewed workflow."""

    if not acknowledged:
        raise HostedProofError(
            "Explicit acknowledgement is required because the workflow kills a bounded test tree."
        )

    auth = _call(runner, "auth", "status", "--hostname", HOST)
    if auth.returncode != 0:
        raise HostedProofError(
            "GitHub CLI is not authenticated for github.com; run `gh auth login` first."
        )

    identity = _call(runner, "api", "--hostname", HOST, "user", "--jq", ".login")
    login = identity.stdout.strip()
    if identity.returncode != 0 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login):
        raise HostedProofError("GitHub CLI could not return a valid account login.")

    repository = f"{login}/{REPOSITORY_NAME}"
    metadata = _fork_metadata(runner, repository)
    if metadata.returncode != 0:
        fork = _call(
            runner,
            "repo",
            "fork",
            f"{HOST}/{UPSTREAM}",
            "--clone=false",
            "--default-branch-only",
        )
        metadata = _fork_metadata(runner, repository)
        if fork.returncode != 0 and metadata.returncode != 0:
            raise HostedProofError("GitHub could not find or create the expected personal fork.")
    if metadata.returncode != 0:
        raise HostedProofError("The new fork was not ready for workflow dispatch.")

    is_fork, parent, branch = _parse_metadata(metadata.stdout)
    if not is_fork or parent.casefold() != UPSTREAM.casefold():
        raise HostedProofError(f"Refusing to use {repository}: it is not a fork of {UPSTREAM}.")

    workflow_identity = _call(
        runner,
        "api",
        "--hostname",
        HOST,
        "--method",
        "GET",
        f"repos/{repository}/contents/.github/workflows/{WORKFLOW}",
        "--raw-field",
        f"ref={branch}",
        "--jq",
        ".sha",
    )
    if (
        workflow_identity.returncode != 0
        or workflow_identity.stdout.strip() != REVIEWED_WORKFLOW_BLOB
    ):
        raise HostedProofError(
            "Refusing to dispatch: the fork workflow does not match the reviewed workflow."
        )

    repository_selector = f"{HOST}/{repository}"
    enabled = _call(
        runner,
        "workflow",
        "enable",
        WORKFLOW,
        "--repo",
        repository_selector,
    )
    if enabled.returncode != 0:
        state = _call(
            runner,
            "api",
            "--hostname",
            HOST,
            f"repos/{repository}/actions/workflows/{WORKFLOW}",
            "--jq",
            ".state",
        )
        if state.returncode != 0 or state.stdout.strip() != "active":
            raise HostedProofError("GitHub could not enable the reviewed hosted-proof workflow.")

    dispatched = _call(
        runner,
        "workflow",
        "run",
        WORKFLOW,
        "--repo",
        repository_selector,
        "--ref",
        branch,
        "--raw-field",
        ACKNOWLEDGEMENT,
    )
    if dispatched.returncode != 0:
        raise HostedProofError("GitHub rejected the hosted-proof workflow dispatch.")

    for line in dispatched.stdout.splitlines():
        candidate = line.strip()
        if RUN_URL.fullmatch(candidate):
            return candidate
    return f"https://github.com/{repository}/actions/workflows/{WORKFLOW}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="fork Lumi Eggcracker and start its reviewed disposable hosted proof"
    )
    parser.add_argument(
        "--i-understand-this-kills-a-test-tree",
        action="store_true",
        help="acknowledge that the hosted workflow kills a bounded synthetic process tree",
    )
    arguments = parser.parse_args(argv)

    if shutil.which("gh") is None:
        parser.error("GitHub CLI (`gh`) is required")
    try:
        url = start_hosted_proof(
            acknowledged=arguments.i_understand_this_kills_a_test_tree,
        )
    except HostedProofError as error:
        parser.error(str(error))
    print(f"Hosted proof dispatched: {url}")
    return 0
