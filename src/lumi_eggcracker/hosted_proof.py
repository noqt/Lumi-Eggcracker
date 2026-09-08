"""Start the reviewed hosted containment proof in a caller-owned GitHub fork."""

from __future__ import annotations

import argparse
import json
import os
import re
import runpy
import secrets
import shutil
import stat
import subprocess
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
QUALIFIED_SOURCE_SHA256 = "78fcc0aeb8c3e5f6713b4db57c70f72a288115cd2d34c38b28f6267a6e12e163"
RESUME_METADATA_MAX_BYTES = 65_536
PROBE_STEP = "Run and validate the bounded synthetic probe"
PREFLIGHT_STEP = "Bind the disposable public host and exact source"
REVIEWED_PROBE_BLOBS = {
    "scripts/containment_probe.py": "e789d9eb218aee3bac0e177624ed691b38be9cdb",
    "src/lumi_eggcracker/__init__.py": "d1cd62d2bce3028bf96ad2f185902dba9b3fddf1",
    "src/lumi_eggcracker/adoption.py": "8fedc96a52c4f677566a5fd27a4681629e1bd73d",
    "src/lumi_eggcracker/containment.py": "3baaea926fa8cc759e2ae056aa1e91a134b34790",
    "src/lumi_eggcracker/containment_probe.py": "4becf27ef07dc3f6fb7e4410921e2c3fc1895c82",
    "src/lumi_eggcracker/discovery.py": "10cec85df3931c2b4d775484da9e97cc555927a9",
    "src/lumi_eggcracker/jsonio.py": "d09c32d35df2c423aa504f6e178c3820dae765cd",
}

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


def _unique_metadata(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Ambiguous metadata")
        value[key] = item
    return value


def _reject_metadata_number(_value: str) -> None:
    raise ValueError("Non-standard metadata number")


def _resume_call(runner: Runner, *arguments: str) -> subprocess.CompletedProcess[str]:
    try:
        return _call(runner, *arguments)
    except HostedProofError as error:
        raise HostedProofError("Read-only GitHub request failed; retry the same resume URL.") from error


def _resume_json(runner: Runner, endpoint: str) -> dict:
    """Read bounded public metadata; never include server responses in errors."""
    response = _resume_call(runner, "api", "--hostname", HOST, "--method", "GET", endpoint)
    try:
        if response.returncode or len(response.stdout.encode("utf-8")) > RESUME_METADATA_MAX_BYTES:
            raise ValueError
        value = json.loads(response.stdout, object_pairs_hook=_unique_metadata,
                           parse_constant=_reject_metadata_number)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise HostedProofError("Could not verify bounded public run metadata; retry resume.") from error


def _public_repository(value: object, repository: str) -> bool:
    return (
        isinstance(value, dict)
        and value.get("full_name") == repository
        and value.get("private") is False
        and type(value.get("id")) is int
        and value["id"] > 0
    )


def _resume_identity(runner: Runner, url: str) -> tuple[str, str, dict]:
    match = RUN_URL.fullmatch(url)
    if match is None:
        raise HostedProofError("Resume requires an exact public hosted-proof run URL.")
    repository = f"{match.group('owner')}/{REPOSITORY_NAME}"
    metadata = _resume_json(runner, f"repos/{repository}")
    if not _public_repository(metadata, repository) or metadata.get("visibility") != "public":
        raise HostedProofError("Resume requires the public canonical repository or its direct fork.")
    if repository == UPSTREAM:
        valid_origin = metadata.get("fork") is False
    else:
        parent = metadata.get("parent")
        valid_origin = metadata.get("fork") is True and _public_repository(parent, UPSTREAM)
    if not valid_origin:
        raise HostedProofError("Resume requires the public canonical repository or its direct fork.")
    endpoint = f"repos/{repository}/actions/runs/{match.group('run_id')}"
    state = _resume_json(runner, endpoint)
    head = state.get("head_sha")
    attempt = state.get("run_attempt")
    if (
        type(state.get("id")) is not int
        or str(state["id"]) != match.group("run_id")
        or state.get("html_url") != url
        or state.get("event") != "workflow_dispatch"
        or state.get("path") != f".github/workflows/{WORKFLOW}"
        or not _public_repository(state.get("repository"), repository)
        or state["repository"]["id"] != metadata["id"]
        or not _public_repository(state.get("head_repository"), repository)
        or state["head_repository"]["id"] != metadata["id"]
        or not isinstance(head, str)
        or not re.fullmatch(r"[0-9a-f]{40}", head)
        or type(attempt) is not int
        or attempt < 1
    ):
        raise HostedProofError("Run identity was not verified; check the exact public run URL.")
    if state.get("status") != "completed":
        raise HostedProofError("Run is not completed; retry the same resume URL after completion.")
    if state.get("conclusion") != "success":
        raise HostedProofError("Run did not succeed; inspect the public run. No success receipt is available.")
    try:
        workflow = _workflow_identity(runner, repository, head)
    except HostedProofError as error:
        raise HostedProofError("Read-only workflow identity request failed; retry resume.") from error
    if workflow.returncode or workflow.stdout.strip() != REVIEWED_WORKFLOW_BLOB:
        raise HostedProofError("Run does not use the exact reviewed workflow at its immutable source.")
    _resume_source(runner, repository, head)
    return repository, endpoint, state


def _resume_source(runner: Runner, repository: str, head: str) -> None:
    """Independently check executable source, including import-shadowing paths."""
    tree = _resume_json(runner, f"repos/{repository}/git/trees/{head}?recursive=1")
    entries = tree.get("tree")
    if tree.get("truncated") is not False or not isinstance(entries, list):
        raise HostedProofError("Complete run-source identity is unavailable.")
    found = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise HostedProofError("Run-source tree metadata is invalid.")
        path = entry["path"]
        if path in found:
            raise HostedProofError("Run-source tree metadata is ambiguous.")
        found[path] = entry
        if path in {"src", "src/lumi_eggcracker", "scripts"}:
            if entry.get("mode") != "040000" or entry.get("type") != "tree":
                raise HostedProofError("Run-source import roots are not regular trees.")
        elif path.startswith("src/"):
            # A flat package containing only ordinary .py/.json files cannot
            # shadow the pinned modules with packages, pyc or native extensions.
            if (
                not re.fullmatch(r"src/lumi_eggcracker/[A-Za-z_][A-Za-z_0-9]*\.(py|json)", path)
                or entry.get("mode") not in {"100644", "100755"}
                or entry.get("type") != "blob"
            ):
                raise HostedProofError("Run-source contains unreviewed import paths.")
    if not {"src", "src/lumi_eggcracker", "scripts"}.issubset(found):
        raise HostedProofError("Run-source import roots are missing.")
    for path, expected in REVIEWED_PROBE_BLOBS.items():
        entry = found.get(path, {})
        if (
            entry.get("sha") != expected or entry.get("type") != "blob"
            or entry.get("mode") not in {"100644", "100755"}
        ):
            raise HostedProofError("Run-source differs from the reviewed probe sources.")


def _receipt_from_log(log: str, head: str) -> dict:
    """Accept only actual output lines from the reviewed job, not echoed shell source."""
    root = Path(__file__).resolve().parents[2]
    try:
        validator = runpy.run_path(str(root / "scripts" / "validate_hosted_proof_receipt.py"))
        schema = validator["_read_json"](
            root / "schemas" / "hosted-proof-receipt-v1.schema.json",
            maximum_bytes=validator["MAX_SCHEMA_BYTES"], label="schema",
        )
        objects = []
        markers = []
        for line in log.splitlines():
            fields = line.split("\t", 2)
            if len(fields) != 3 or fields[0] != "containment-probe":
                continue
            stamped = re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z (.*)", fields[2])
            if stamped is None:
                continue
            payload = stamped.group(1)
            if fields[1] == PREFLIGHT_STEP and payload.startswith("FORK_PROBE_"):
                markers.append(payload)
            if fields[1] != PROBE_STEP:
                continue
            if payload.startswith("FORK_PROBE_"):
                markers.append(payload)
            if payload.startswith("{"):
                if len(payload.encode("utf-8")) > validator["MAX_RECEIPT_BYTES"]:
                    raise ValueError
                objects.append(json.loads(
                    payload, object_pairs_hook=validator["_unique_object"],
                    parse_constant=validator["_reject_nonstandard_number"],
                ))
        if markers != [
            f"FORK_PROBE_WORKFLOW_BLOB={REVIEWED_WORKFLOW_BLOB}",
            "FORK_PROBE_PREFLIGHT=PASS", "FORK_PROBE_RESULT=PASS",
        ] or len(objects) != 1:
            raise ValueError
        receipt = objects[0]
        validator["validate_receipt"](receipt, schema)
        if (
            receipt.get("result") != "TERMINATED"
            or receipt.get("source_commit") != head
            or receipt.get("source_tree_sha256") != QUALIFIED_SOURCE_SHA256
        ):
            raise ValueError
        return receipt
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as error:
        raise HostedProofError(
            "No single reviewed success receipt was verified; inspect the public run. "
            "Use a current source checkout if the validator is unavailable."
        ) from error


def resume_hosted_proof(
    url: str, *, receipt_path: Path | None = None, runner: Runner = _default_runner,
) -> None:
    """Read an already completed run without dispatch, waiting, sync or raw-log output."""
    repository, endpoint, state = _resume_identity(runner, url)
    response = _resume_call(
        runner, "run", "view", str(state["id"]), "--repo", f"{HOST}/{repository}",
        "--attempt", str(state["run_attempt"]), "--log",
    )
    try:
        if response.returncode or len(response.stdout.encode("utf-8")) > FOLLOW_LOG_MAX_BYTES:
            raise ValueError
    except (ValueError, UnicodeError) as error:
        raise HostedProofError("Public log unavailable or oversized; retry resume.") from error
    receipt = _receipt_from_log(response.stdout, state["head_sha"])
    # A rerun or metadata change during retrieval invalidates this snapshot.
    if _resume_json(runner, endpoint) != state:
        raise HostedProofError("Run changed during retrieval; retry resume without exporting.")
    if receipt_path is not None:
        try:
            # Require a trusted existing directory chain; refuse symlink/reparse
            # parents rather than resolving them into a different destination.
            for parent in receipt_path.absolute().parents:
                metadata = parent.lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & 0x400
                ):
                    raise OSError("Unsafe output directory")
            # O_EXCL rejects existing files and dangling symlinks atomically.
            with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
        except (OSError, ValueError) as error:
            raise HostedProofError(
                "Receipt was not saved completely. Choose a new writable file path; "
                "an existing or partial file is never overwritten or removed."
            ) from error


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
    parser.add_argument("--resume", metavar="URL", help="verify the same completed public run")
    parser.add_argument("--receipt", type=Path, metavar="PATH", help="with --resume, save a new receipt")
    arguments = parser.parse_args(argv)
    if arguments.resume is not None:
        if (
            arguments.wait or arguments.sync_fork or arguments.show_log
            or arguments.i_understand_this_kills_a_test_tree
        ):
            parser.error("--resume cannot be combined with starter or log-display options")
        if shutil.which("gh") is None:
            parser.error("GitHub CLI (`gh`) is required")
        try:
            resume_hosted_proof(arguments.resume, receipt_path=arguments.receipt)
        except HostedProofError as error:
            parser.error(
                f"{error} No workflow was dispatched; existing files were not overwritten."
            )
        print(f"Hosted proof result: PASS ({arguments.resume})")
        if arguments.receipt is not None:
            print("Success receipt saved; schema validation is not independent run authentication.")
        return 0
    if arguments.receipt is not None:
        parser.error("--receipt requires --resume")
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
