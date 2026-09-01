"""Start the reviewed hosted containment proof in a caller-owned GitHub fork."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

HOST = "github.com"
UPSTREAM = "noqt/Lumi-Eggcracker"
REPOSITORY_NAME = "Lumi-Eggcracker"
WORKFLOW = "containment-probe.yml"
RESULT_FORM_URL = (
    "https://github.com/noqt/Lumi-Eggcracker/issues/new?template=hosted_probe_result.yml"
)
REVIEWED_WORKFLOW_BLOB = "2f823c41f487e36196700262f80c8504ed2b885f"
ACKNOWLEDGEMENT = "i_understand_this_kills_a_test_tree=true"
RUN_URL = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"Lumi-Eggcracker/actions/runs/(?P<run_id>[1-9][0-9]*)$"
)
CORRELATION_ID = re.compile(r"^[0-9a-f]{32}$")
RUN_NAME_PREFIX = "Containment probe"
FORK_READY_ATTEMPTS = 5
FORK_READY_DELAY_SECONDS = 1.0
RUN_LOOKUP_ATTEMPTS = 3
RUN_LOOKUP_DELAY_SECONDS = 1.0
RUN_LOOKUP_COMMAND_TIMEOUT_SECONDS = 5.0
RUN_LOOKUP_DEADLINE_SECONDS = 17.0
RUN_LOOKUP_MAX_BYTES = 262_144
RUN_LOOKUP_RECENCY = timedelta(minutes=5)
RUN_LOOKUP_FUTURE_TOLERANCE = timedelta(minutes=1)
FOLLOW_TIMEOUT_SECONDS = 900.0
FOLLOW_STATUS_MAX_BYTES = 4_096
FOLLOW_LOG_MAX_BYTES = 262_144

Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]
Monotonic = Callable[[], float]
UtcNow = Callable[[], datetime]
TokenFactory = Callable[[int], str]


class HostedProofError(RuntimeError):
    """A bounded, user-actionable hosted-proof startup failure."""


def _watch_command(url: str) -> str | None:
    """Return a copyable command only for an exact validated hosted-proof run URL."""

    match = RUN_URL.fullmatch(url)
    if match is None:
        return None
    repository = f"{HOST}/{match.group('owner')}/{REPOSITORY_NAME}"
    return f"gh run watch {match.group('run_id')} --repo {repository} --exit-status"


def _log_command(url: str) -> str | None:
    """Return a bounded-result command only for an exact hosted-proof run URL."""

    match = RUN_URL.fullmatch(url)
    if match is None:
        return None
    repository = f"{HOST}/{match.group('owner')}/{REPOSITORY_NAME}"
    return f"gh run view {match.group('run_id')} --repo {repository} --log"


def _default_runner(
    command: Sequence[str],
    *,
    timeout_seconds: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        env={**os.environ, "GH_PROMPT_DISABLED": "1"},
        text=True,
        timeout=timeout_seconds,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _call(
    runner: Runner,
    *arguments: str,
    timeout_seconds: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    try:
        command = ("gh", *arguments)
        if runner is _default_runner:
            return _default_runner(command, timeout_seconds=timeout_seconds)
        return runner(command)
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise HostedProofError("GitHub CLI failed before dispatch completed.") from error


def follow_hosted_proof(
    url: str,
    *,
    runner: Runner = _default_runner,
) -> tuple[str, bool]:
    """Wait for one exact run and return its bounded public log and pass state."""

    match = RUN_URL.fullmatch(url)
    if match is None:
        raise HostedProofError("Automatic wait requires an exact hosted-proof run URL.")
    repository = f"{HOST}/{match.group('owner')}/{REPOSITORY_NAME}"
    run_id = match.group("run_id")
    try:
        _call(
            runner,
            "run",
            "watch",
            run_id,
            "--repo",
            repository,
            "--exit-status",
            timeout_seconds=FOLLOW_TIMEOUT_SECONDS,
        )
    except HostedProofError as error:
        raise HostedProofError("GitHub CLI could not complete the hosted-proof wait.") from error
    try:
        status_result = _call(
            runner,
            "run",
            "view",
            run_id,
            "--repo",
            repository,
            "--json",
            "status,conclusion,url",
        )
    except HostedProofError as error:
        raise HostedProofError("GitHub CLI could not verify hosted-proof completion.") from error
    if status_result.returncode != 0:
        raise HostedProofError("GitHub CLI could not read the hosted-proof status.")
    try:
        encoded_status = status_result.stdout.encode("utf-8")
        if len(encoded_status) > FOLLOW_STATUS_MAX_BYTES:
            raise HostedProofError("GitHub returned an oversized hosted-proof status.")
        state = json.loads(status_result.stdout)
    except (HostedProofError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise HostedProofError("GitHub CLI could not verify hosted-proof completion.") from error
    if not isinstance(state, dict) or state.get("url") != url:
        raise HostedProofError("GitHub returned a mismatched hosted-proof status.")
    if state.get("status") != "completed":
        raise HostedProofError(f"Hosted proof did not reach a completed state; inspect {url}.")
    conclusion = state.get("conclusion")
    if not isinstance(conclusion, str) or not re.fullmatch(r"[a-z_]{1,32}", conclusion):
        raise HostedProofError("GitHub returned an invalid hosted-proof conclusion.")

    try:
        log_result = _call(
            runner,
            "run",
            "view",
            run_id,
            "--repo",
            repository,
            "--log",
        )
        encoded_log = log_result.stdout.encode("utf-8")
    except (HostedProofError, UnicodeError) as error:
        raise HostedProofError("GitHub CLI could not read the hosted-proof result.") from error
    if log_result.returncode != 0:
        raise HostedProofError(f"Hosted proof finished but its log was unavailable; inspect {url}.")
    if len(encoded_log) > FOLLOW_LOG_MAX_BYTES:
        raise HostedProofError(f"Hosted-proof log exceeded the safe display bound; inspect {url}.")
    log = log_result.stdout.rstrip()
    if not log:
        raise HostedProofError(f"Hosted-proof log was empty; inspect {url}.")
    return log, conclusion == "success"


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


def _workflow_identity(
    runner: Runner,
    repository: str,
    branch: str,
) -> subprocess.CompletedProcess[str]:
    return _call(
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


def _parse_metadata(output: str) -> tuple[bool, str, str]:
    fields = output.strip().split("\t")
    if len(fields) != 3 or fields[0] not in {"true", "false"}:
        raise HostedProofError("GitHub returned an unexpected fork description.")
    parent, branch = fields[1:]
    if not branch or any(character.isspace() for character in branch):
        raise HostedProofError("GitHub returned an unsafe or incomplete fork description.")
    return fields[0] == "true", parent, branch


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp is not timezone-aware")
    return value.astimezone(UTC)


def _github_timestamp(value: datetime) -> str:
    return _as_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_github_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("timestamp is not text")
    parsed = datetime.fromisoformat(value)
    return _as_utc(parsed)


def _workflow_run_candidates(
    runner: Runner,
    *,
    repository: str,
    login: str,
    branch: str,
    expected_title: str,
    not_before: datetime,
    now: datetime,
    timeout_seconds: float,
) -> list[str] | None:
    try:
        listed = _call(
            runner,
            "api",
            "--hostname",
            HOST,
            "--method",
            "GET",
            f"repos/{repository}/actions/workflows/{WORKFLOW}/runs",
            "--raw-field",
            f"actor={login}",
            "--raw-field",
            f"branch={branch}",
            "--raw-field",
            "event=workflow_dispatch",
            "--raw-field",
            f"created=>={_github_timestamp(not_before)}",
            "--raw-field",
            "per_page=20",
            timeout_seconds=timeout_seconds,
        )
    except HostedProofError:
        return None
    if listed.returncode != 0:
        return None
    try:
        if len(listed.stdout.encode("utf-8")) > RUN_LOOKUP_MAX_BYTES:
            return None
        payload = json.loads(listed.stdout)
    except (UnicodeEncodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        return None

    lower_bound = _as_utc(not_before)
    upper_bound = _as_utc(now) + RUN_LOOKUP_FUTURE_TOLERANCE
    expected_repository = repository.casefold()
    expected_actor = login.casefold()
    matches: list[str] = []
    for run in payload["workflow_runs"]:
        if not isinstance(run, dict):
            return None
        actor = run.get("actor")
        run_repository = run.get("repository")
        if not isinstance(actor, dict) or not isinstance(run_repository, dict):
            return None
        run_id = run.get("id")
        url = run.get("html_url")
        try:
            created_at = _parse_github_timestamp(run.get("created_at"))
        except (TypeError, ValueError):
            return None
        if type(run_id) is not int or run_id < 1 or not isinstance(url, str):
            return None
        canonical_url = f"https://{HOST}/{repository}/actions/runs/{run_id}"
        if (
            str(run_repository.get("full_name", "")).casefold() != expected_repository
            or str(actor.get("login", "")).casefold() != expected_actor
            or run.get("event") != "workflow_dispatch"
            or run.get("head_branch") != branch
            or run.get("display_title") != expected_title
            or created_at < lower_bound
            or created_at > upper_bound
            or url != canonical_url
            or not RUN_URL.fullmatch(url)
        ):
            continue
        matches.append(url)
    return matches


def _discover_run_url(
    runner: Runner,
    *,
    repository: str,
    login: str,
    branch: str,
    correlation_id: str,
    dispatch_started_at: datetime,
    sleeper: Sleeper,
    monotonic: Monotonic,
    utc_now: UtcNow,
) -> str | None:
    expected_title = f"{RUN_NAME_PREFIX} ({correlation_id})"
    not_before = _as_utc(dispatch_started_at) - RUN_LOOKUP_RECENCY
    deadline = monotonic() + RUN_LOOKUP_DEADLINE_SECONDS
    for attempt in range(RUN_LOOKUP_ATTEMPTS):
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        try:
            now = _as_utc(utc_now())
        except (TypeError, ValueError):
            return None
        candidates = _workflow_run_candidates(
            runner,
            repository=repository,
            login=login,
            branch=branch,
            expected_title=expected_title,
            not_before=not_before,
            now=now,
            timeout_seconds=min(RUN_LOOKUP_COMMAND_TIMEOUT_SECONDS, remaining),
        )
        if deadline - monotonic() <= 0:
            return None
        if candidates is None or len(candidates) > 1:
            return None
        if len(candidates) == 1:
            return candidates[0]
        if attempt + 1 < RUN_LOOKUP_ATTEMPTS:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            sleeper(min(RUN_LOOKUP_DELAY_SECONDS, remaining))
    return None


def start_hosted_proof(
    *,
    acknowledged: bool,
    sync_fork: bool = False,
    runner: Runner = _default_runner,
    sleeper: Sleeper = time.sleep,
    monotonic: Monotonic = time.monotonic,
    utc_now: UtcNow = _utc_now,
    token_factory: TokenFactory = secrets.token_hex,
) -> str:
    """Create or reuse the caller's exact fork and dispatch the reviewed workflow."""

    if not acknowledged:
        raise HostedProofError(
            "Explicit acknowledgement is required because the workflow kills a bounded test tree."
        )

    correlation_id = token_factory(16)
    if not isinstance(correlation_id, str) or not CORRELATION_ID.fullmatch(correlation_id):
        raise HostedProofError("Could not generate a safe hosted-proof correlation identifier.")
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
        for attempt in range(FORK_READY_ATTEMPTS):
            metadata = _fork_metadata(runner, repository)
            if metadata.returncode == 0:
                break
            if attempt + 1 < FORK_READY_ATTEMPTS:
                sleeper(FORK_READY_DELAY_SECONDS)
        if fork.returncode != 0 and metadata.returncode != 0:
            raise HostedProofError("GitHub could not find or create the expected personal fork.")
    if metadata.returncode != 0:
        raise HostedProofError("The new fork was not ready for workflow dispatch.")

    is_fork, parent, branch = _parse_metadata(metadata.stdout)
    if not is_fork or parent.casefold() != UPSTREAM.casefold():
        raise HostedProofError(f"Refusing to use {repository}: it is not a fork of {UPSTREAM}.")

    workflow_identity = _workflow_identity(runner, repository, branch)
    if (
        workflow_identity.returncode != 0
        or workflow_identity.stdout.strip() != REVIEWED_WORKFLOW_BLOB
    ):
        if not sync_fork:
            raise HostedProofError(
                "Refusing to dispatch: the fork workflow does not match the reviewed "
                "workflow. Rerun with `--sync-fork` to permit a fast-forward-only sync "
                "and exact revalidation."
            )
        synchronized = _call(
            runner,
            "repo",
            "sync",
            f"{HOST}/{repository}",
            "--source",
            f"{HOST}/{UPSTREAM}",
            "--branch",
            branch,
        )
        if synchronized.returncode != 0:
            raise HostedProofError(
                "GitHub could not fast-forward the fork; no workflow was dispatched."
            )
        refreshed_metadata = _fork_metadata(runner, repository)
        if refreshed_metadata.returncode != 0:
            raise HostedProofError(
                "GitHub could not revalidate the synchronized fork; no workflow was dispatched."
            )
        is_fork, parent, refreshed_branch = _parse_metadata(refreshed_metadata.stdout)
        if not is_fork or parent.casefold() != UPSTREAM.casefold():
            raise HostedProofError(
                "The synchronized repository no longer matches the expected upstream fork; "
                "no workflow was dispatched."
            )
        if refreshed_branch != branch:
            raise HostedProofError(
                "The synchronized fork changed its default branch; no workflow was dispatched."
            )
        workflow_identity = _workflow_identity(runner, repository, branch)
        if (
            workflow_identity.returncode != 0
            or workflow_identity.stdout.strip() != REVIEWED_WORKFLOW_BLOB
        ):
            raise HostedProofError(
                "The synchronized fork still does not contain the reviewed workflow; "
                "no workflow was dispatched."
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

    try:
        dispatch_started_at = _as_utc(utc_now())
    except (TypeError, ValueError) as error:
        raise HostedProofError("Could not establish a safe UTC dispatch time.") from error

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
        "--raw-field",
        f"run_correlation_id={correlation_id}",
    )
    if dispatched.returncode != 0:
        raise HostedProofError("GitHub rejected the hosted-proof workflow dispatch.")

    expected_run_prefix = f"https://{HOST}/{repository}/actions/runs/"
    for line in dispatched.stdout.splitlines():
        candidate = line.strip()
        if RUN_URL.fullmatch(candidate) and candidate.startswith(expected_run_prefix):
            return candidate
    discovered = _discover_run_url(
        runner,
        repository=repository,
        login=login,
        branch=branch,
        correlation_id=correlation_id,
        dispatch_started_at=dispatch_started_at,
        sleeper=sleeper,
        monotonic=monotonic,
        utc_now=utc_now,
    )
    if discovered is not None:
        return discovered
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
    parser.add_argument(
        "--wait",
        action="store_true",
        help="wait for an exact run and print its terminal PASS or FAIL result",
    )
    parser.add_argument(
        "--sync-fork",
        action="store_true",
        help=(
            "if the personal fork is stale, explicitly allow a fast-forward-only sync "
            "from the reviewed upstream before exact revalidation"
        ),
    )
    parser.add_argument(
        "--show-log",
        action="store_true",
        help="with --wait, also print the bounded public log on a successful run",
    )
    arguments = parser.parse_args(argv)
    if arguments.show_log and not arguments.wait:
        parser.error("--show-log requires --wait")

    if shutil.which("gh") is None:
        parser.error("GitHub CLI (`gh`) is required")
    try:
        url = start_hosted_proof(
            acknowledged=arguments.i_understand_this_kills_a_test_tree,
            sync_fork=arguments.sync_fork,
        )
    except HostedProofError as error:
        parser.error(str(error))
    print(f"Hosted proof dispatched: {url}")
    status = 0
    result_line: str | None = None
    if arguments.wait:
        if _watch_command(url) is None:
            print("Automatic wait unavailable because the exact run URL was not resolved.")
            status = 1
        else:
            try:
                log, passed = follow_hosted_proof(url)
            except HostedProofError as error:
                parser.error(str(error))
            print("Hosted proof finished.")
            if arguments.show_log or not passed:
                print("Bounded public workflow log:")
                print(log)
            result = "PASS" if passed else "FAIL"
            result_line = f"Hosted proof result: {result} ({url})"
            if not passed:
                print(f"Hosted proof did not pass; inspect {url}.")
                status = 1
    else:
        watch_command = _watch_command(url)
        if watch_command is not None:
            print(f"Watch from this terminal: {watch_command}")
        log_command = _log_command(url)
        if log_command is not None:
            print(f"Read the bounded result: {log_command}")
    print(f"After it finishes, share the public run or friction: {RESULT_FORM_URL}")
    if result_line is not None:
        print(result_line)
    return status
