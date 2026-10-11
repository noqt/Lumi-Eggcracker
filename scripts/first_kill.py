"""Run the public first-kill demonstration from a clean Linux host.

This is deliberately a small campaign wrapper around the qualified release
installer and real-AI smoke scripts. It does not weaken installer checks,
overwrite an existing installation, or send telemetry anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - first-kill is a native Linux command
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


REPOSITORY = "noqt/Lumi-Eggcracker"
DEFAULT_TAG = "v1.0.10"
RELEASE_KEY_FINGERPRINT = "53786DEB001459956A2E1B86A3F29F7A27636DC7"
WORKLOAD_USER = "lumi-eggcracker-workload"
INSTALL_TARGETS = (
    Path("/usr/local/lib/lumi-eggcracker"),
    Path("/usr/local/bin/eggcracker"),
    Path("/etc/lumi-eggcracker"),
    Path("/var/lib/lumi-eggcracker"),
    Path("/run/lumi-eggcracker"),
    Path("/run/lumi-eggcracker-watchdog"),
    Path("/etc/systemd/system/lumi-eggcracker.service"),
    Path("/etc/systemd/system/lumi-eggcracker-watchdog.service"),
    Path("/etc/tmpfiles.d/lumi-eggcracker.conf"),
)
REQUIRED_HOST_COMMANDS = (
    "/bin/sleep",
    "/usr/bin/env",
    "/usr/bin/python3",
    "/usr/bin/systemctl",
    "/usr/bin/systemd-run",
    "/usr/bin/journalctl",
    "/usr/sbin/runuser",
    "/usr/sbin/useradd",
    "/usr/sbin/userdel",
    "/usr/sbin/groupdel",
    "/usr/bin/gpg",
    "/usr/bin/git",
    "/usr/sbin/ip",
    "/usr/sbin/nft",
    "/usr/bin/nsenter",
)
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ZIP_COMMENT_BYTES = 65_535
MIN_TOTAL_MEMORY_BYTES = 7 * 1024 * 1024 * 1024
MIN_FREE_ROOT_BYTES = 8 * 1024 * 1024 * 1024
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
DEFAULT_AI_SMOKE_WORKSPACE = Path("/opt/lumi-eggcracker-ai-smoke")
QUALIFIED_LLAMA_SHA256 = "ef0b86d353638b74519079b5937b9d62b4d4c6c6cdbf68812d7898437ecc4fb5"


class FirstKillError(RuntimeError):
    """A user-actionable campaign failure."""


PREFLIGHT_SCHEMA = "lumi-eggcracker.first-kill-preflight.v1"
THIRD_PARTY_PLAN_SCHEMA = "lumi-eggcracker.third-party-download-plan.v1"
THIRD_PARTY_DOWNLOAD_PLAN_SCHEMA = THIRD_PARTY_PLAN_SCHEMA
PLAN_SCHEMA = THIRD_PARTY_PLAN_SCHEMA
PLAN_VERSION = 1
FULL_RUN_FAILURE_SCHEMA = "lumi-eggcracker.first-kill-failure.v1"
FULL_RUN_FAILURE_VERSION = 1
FULL_RUN_NEXT_ACTION = "STOP_AND_REVIEW_BEFORE_RETRY"

# The result file is deliberately a separate, opt-in projection.  Keep this
# allowlist closed: it must never become a second receipt or a wrapper build
# report.  In particular, release authentication details and all operator,
# host, path, and process identities stay out of this document.
SUCCESS_RESULT_SCHEMA = "lumi-eggcracker.first-kill-success.v1"
SUCCESS_RESULT_VERSION = 1
SUCCESS_RESULT_VALUE = "FIRST_KILL_SUCCEEDED"
SUCCESS_DISPOSITION_REMOVED = "REMOVED_AND_VERIFIED"
SUCCESS_DISPOSITION_RETAINED = "RETAINED_BY_OPERATOR"
SUCCESS_DISPOSITIONS = frozenset({SUCCESS_DISPOSITION_REMOVED, SUCCESS_DISPOSITION_RETAINED})
SUCCESS_RUN_SCOPE = "ONE_SIGNED_RELEASE_FIRST_KILL_RUN"
SUCCESS_SOURCE_COMMIT_ROLE = "VERIFIED_RELEASE_SOURCE"
SUCCESS_AI_ASSETS_NEW_REMOVED = "NEW_ASSETS_REMOVED"
SUCCESS_AI_ASSETS_NEW_RETAINED = "NEW_ASSETS_RETAINED_BY_OPERATOR"
SUCCESS_AI_ASSETS_PREEXISTING_EXCLUDED = "PREEXISTING_ASSETS_EXCLUDED_UNTOUCHED"
SUCCESS_AI_ASSET_DISPOSITIONS = frozenset(
    {
        SUCCESS_AI_ASSETS_NEW_REMOVED,
        SUCCESS_AI_ASSETS_NEW_RETAINED,
        SUCCESS_AI_ASSETS_PREEXISTING_EXCLUDED,
    }
)
SUCCESS_RESULT_FIELDS = frozenset(
    {
        "ai_assets_disposition",
        "authenticated",
        "captured_processes",
        "independent_containment_proof",
        "disposition",
        "primitive",
        "profile",
        "result",
        "root_populated",
        "schema",
        "source_commit",
        "source_commit_role",
        "surviving_pids",
        "tag",
        "trigger",
        "trigger_to_empty_ms",
        "version",
        "run_scope",
    }
)
RESULT_OUTPUT_MAX_BYTES = 8 * 1024
RESULT_OUTPUT_MAX_CAPTURED_PROCESSES = 4096
RESULT_OUTPUT_MAX_TRIGGER_TO_EMPTY_MS = 10 * 60 * 1000.0
RESULT_OUTPUT_FAILURE = "success result could not be published"
RESULT_OUTPUT_INVALID = "result-output destination is unavailable"
RESULT_OUTPUT_REPARSE_POINT = 0x400
RESULT_OUTPUT_TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
RESULT_OUTPUT_COMMIT = re.compile(r"[0-9a-f]{40}\Z")

LLAMA_REPOSITORY = "https://github.com/ggml-org/llama.cpp.git"
LLAMA_TAG = "b10240"
LLAMA_COMMIT = "0b14b87d7c20cb753b94b96854dd7b45306fc696"
MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf"
MODEL_REVISION = "9217f5db79a29953eb74d5343926648285ec7e67"
MODEL_SHA256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
LLAMA_LICENSE = "MIT"
MODEL_LICENSE = "Apache-2.0"
LICENSE_STATUS = "DECLARED_METADATA_NOT_VERIFIED"
MODEL_DOWNLOAD_MAX_BYTES = 600 * 1024 * 1024
PLAN_TRANSFER_UNKNOWN = "UNKNOWN"
PLAN_TRANSFER_UNCAPPED = "UNCAPPED_BY_THIS_TOOL"


class ThirdPartyPlanError(RuntimeError):
    """The fixed source-only projection cannot be emitted safely."""


FULL_RUN_STAGE_PRE_INSTALL = "pre-install"
FULL_RUN_STAGE_INSTALL = "install"
FULL_RUN_STAGE_POST_INSTALL = "post-install"
FULL_RUN_STAGE_REMOVAL = "removal"
FULL_RUN_STAGE_RESULT_PUBLICATION = "result-publication"
FULL_RUN_STAGE_UNKNOWN = "unknown"
FULL_RUN_STAGES = frozenset(
    {
        FULL_RUN_STAGE_PRE_INSTALL,
        FULL_RUN_STAGE_INSTALL,
        FULL_RUN_STAGE_POST_INSTALL,
        FULL_RUN_STAGE_REMOVAL,
        FULL_RUN_STAGE_RESULT_PUBLICATION,
        FULL_RUN_STAGE_UNKNOWN,
    }
)
FULL_RUN_INSTALL_STATE_NOT_INSTALLED = "NOT_INSTALLED"
FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL = "UNKNOWN_OR_PARTIAL"
FULL_RUN_INSTALL_STATE_INSTALLED = "INSTALLED"
FULL_RUN_INSTALL_STATES = frozenset(
    {
        FULL_RUN_INSTALL_STATE_NOT_INSTALLED,
        FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL,
        FULL_RUN_INSTALL_STATE_INSTALLED,
    }
)
FULL_RUN_REMOVAL_NOT_REQUIRED = "NOT_REQUIRED"
FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
FULL_RUN_FAILURE_FIELDS = frozenset(
    {
        "installation_state",
        "next_action",
        "reason_code",
        "removal_guidance",
        "result",
        "schema",
        "stage",
        "version",
    }
)


def _full_run_failure_diagnostic(stage: str, installation_state: str) -> dict[str, str | int]:
    """Return the fixed-shape, redacted report for a full-run failure."""
    if stage not in FULL_RUN_STAGES:
        stage = FULL_RUN_STAGE_UNKNOWN
    if installation_state not in FULL_RUN_INSTALL_STATES:
        installation_state = FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL
    reason_code = {
        FULL_RUN_STAGE_PRE_INSTALL: "PRE_INSTALL_FAILURE",
        FULL_RUN_STAGE_INSTALL: "INSTALL_FAILURE",
        FULL_RUN_STAGE_POST_INSTALL: "POST_INSTALL_FAILURE",
        FULL_RUN_STAGE_REMOVAL: "REMOVAL_FAILURE",
        FULL_RUN_STAGE_RESULT_PUBLICATION: "RESULT_PUBLICATION_FAILURE",
        FULL_RUN_STAGE_UNKNOWN: "UNKNOWN_FAILURE",
    }[stage]
    removal_guidance = {
        FULL_RUN_INSTALL_STATE_NOT_INSTALLED: FULL_RUN_REMOVAL_NOT_REQUIRED,
        FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL: FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED,
        FULL_RUN_INSTALL_STATE_INSTALLED: FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED,
    }[installation_state]
    return {
        "installation_state": installation_state,
        "next_action": FULL_RUN_NEXT_ACTION,
        "reason_code": reason_code,
        "removal_guidance": removal_guidance,
        "result": "FULL_RUN_FAILED",
        "schema": FULL_RUN_FAILURE_SCHEMA,
        "stage": stage,
        "version": FULL_RUN_FAILURE_VERSION,
    }


def _print_full_run_failure(stage: str, installation_state: str) -> None:
    """Print only the bounded full-run failure object; never serialize the exception."""
    print(
        json.dumps(_full_run_failure_diagnostic(stage, installation_state), indent=2, sort_keys=True),
        file=sys.stderr,
    )


class PreflightDiagnostic:
    """Stable, redacted metadata for one preflight refusal."""

    __slots__ = ("failed_check", "next_action", "reason_code")

    def __init__(self, failed_check: str, reason_code: str, next_action: str) -> None:
        self.failed_check = failed_check
        self.reason_code = reason_code
        self.next_action = next_action


PREFLIGHT_DIAGNOSTICS = {
    "operator_database": PreflightDiagnostic(
        "operator", "OPERATOR_DATABASE_UNAVAILABLE", "run on a host with POSIX account databases"
    ),
    "operator_required": PreflightDiagnostic(
        "operator", "OPERATOR_REQUIRED", "provide a non-root operator identity"
    ),
    "operator_missing": PreflightDiagnostic(
        "operator", "OPERATOR_ACCOUNT_MISSING", "provide an existing non-root operator identity"
    ),
    "operator_root": PreflightDiagnostic(
        "operator", "OPERATOR_MUST_NOT_BE_ROOT", "provide a non-root operator identity"
    ),
    "host_root": PreflightDiagnostic(
        "host", "ROOT_REQUIRED", "rerun as root on the supported disposable host"
    ),
    "host_platform": PreflightDiagnostic(
        "host", "NATIVE_LINUX_REQUIRED", "run on a supported native Linux host"
    ),
    "host_wsl": PreflightDiagnostic(
        "host", "WSL_UNSUPPORTED", "run on a supported native Linux host"
    ),
    "host_memory": PreflightDiagnostic(
        "host", "HOST_MEMORY_UNAVAILABLE", "run on a host with verifiable physical memory"
    ),
    "host_memory_limit": PreflightDiagnostic(
        "host", "HOST_MEMORY_INSUFFICIENT", "use a host meeting the minimum memory requirement"
    ),
    "host_disk": PreflightDiagnostic(
        "host", "ROOT_DISK_UNAVAILABLE", "run on a host with verifiable root free space"
    ),
    "host_disk_limit": PreflightDiagnostic(
        "host", "ROOT_DISK_INSUFFICIENT", "use a host meeting the minimum root free-space requirement"
    ),
    "host_cgroup": PreflightDiagnostic(
        "host", "PIDS_CONTROLLER_UNAVAILABLE", "run on a host with cgroup v2 and the pids controller"
    ),
    "host_pidfd": PreflightDiagnostic(
        "host", "PIDFD_UNAVAILABLE", "run with Python/Linux pidfd support enabled"
    ),
    "host_command": PreflightDiagnostic(
        "tool_availability", "REQUIRED_COMMAND_MISSING", "provide all required host commands"
    ),
    "build_tool": PreflightDiagnostic(
        "tool_availability", "BUILD_TOOL_MISSING", "provide the required build tooling"
    ),
    "install_target": PreflightDiagnostic(
        "clean_install_targets", "INSTALL_TARGET_EXISTS", "remove conflicting installation targets before retrying"
    ),
    "workload_database": PreflightDiagnostic(
        "clean_install_targets", "WORKLOAD_IDENTITY_DATABASE_UNAVAILABLE", "run on a host with POSIX account databases"
    ),
    "workload_residue": PreflightDiagnostic(
        "clean_install_targets", "WORKLOAD_IDENTITY_EXISTS", "remove residual workload identity before retrying"
    ),
    "local_git": PreflightDiagnostic(
        "local_annotated_tag_identity", "LOCAL_GIT_UNAVAILABLE", "run from a readable local Git checkout"
    ),
    "tag_unsupported": PreflightDiagnostic(
        "local_annotated_tag_identity", "QUALIFIED_TAG_REQUIRED", "use the qualified local release tag"
    ),
    "tag_not_annotated": PreflightDiagnostic(
        "local_annotated_tag_identity", "ANNOTATED_TAG_REQUIRED", "use the qualified local annotated tag"
    ),
    "tag_commit": PreflightDiagnostic(
        "local_annotated_tag_identity", "TAG_COMMIT_UNAVAILABLE", "use a qualified tag that resolves to a commit"
    ),
    "unexpected": PreflightDiagnostic(
        "preflight", "PREFLIGHT_CHECK_FAILED", "review supported-host and local-release requirements before retrying"
    ),
}


class PreflightFailure(FirstKillError):
    """A FirstKillError carrying only trusted preflight diagnostic metadata."""

    def __init__(self, message: str, diagnostic_key: str) -> None:
        diagnostic = PREFLIGHT_DIAGNOSTICS[diagnostic_key]
        self.failed_check = diagnostic.failed_check
        self.reason_code = diagnostic.reason_code
        self.next_action = diagnostic.next_action
        super().__init__(message)


def preflight_failure(diagnostic_key: str, message: str) -> PreflightFailure:
    """Create a refusal with a trusted diagnostic selected at the check site."""
    return PreflightFailure(message, diagnostic_key)


def say(message: str) -> None:
    print(f"[eggcracker] {message}", flush=True)


def _plan_inputs_are_pinned() -> bool:
    try:
        values = (
            (PLAN_SCHEMA, "lumi-eggcracker.third-party-download-plan.v1", str),
            (PLAN_VERSION, 1, int),
            (LLAMA_REPOSITORY, "https://github.com/ggml-org/llama.cpp.git", str),
            (LLAMA_TAG, "b10240", str),
            (LLAMA_COMMIT, "0b14b87d7c20cb753b94b96854dd7b45306fc696", str),
            (MODEL_URL, "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf", str),
            (MODEL_REVISION, "9217f5db79a29953eb74d5343926648285ec7e67", str),
            (MODEL_SHA256, "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db", str),
            (LLAMA_LICENSE, "MIT", str),
            (MODEL_LICENSE, "Apache-2.0", str),
            (LICENSE_STATUS, "DECLARED_METADATA_NOT_VERIFIED", str),
            (MODEL_DOWNLOAD_MAX_BYTES, 600 * 1024 * 1024, int),
            (MIN_TOTAL_MEMORY_BYTES, 7 * 1024 * 1024 * 1024, int),
            (MIN_FREE_ROOT_BYTES, 8 * 1024 * 1024 * 1024, int),
            (PLAN_TRANSFER_UNKNOWN, "UNKNOWN", str),
            (PLAN_TRANSFER_UNCAPPED, "UNCAPPED_BY_THIS_TOOL", str),
        )
        return all(
            type(actual) is expected_type and actual == expected
            for actual, expected, expected_type in values
        )
    except Exception:  # noqa: BLE001 - fail closed without reflecting malformed input
        return False


def build_third_party_download_plan() -> dict[str, Any]:
    """Return the deterministic, offline source-only third-party projection."""
    if not _plan_inputs_are_pinned():
        raise ThirdPartyPlanError("pinned third-party plan inputs are invalid")
    return {
        "schema_version": PLAN_SCHEMA,
        "plan_version": PLAN_VERSION,
        "result": "THIRD_PARTY_DOWNLOAD_PLAN",
        "mode": "offline-source-only",
        "llama": {
            "repository": LLAMA_REPOSITORY,
            "tag": LLAMA_TAG,
            "commit": LLAMA_COMMIT,
            "license": LLAMA_LICENSE,
            "license_status": LICENSE_STATUS,
            "license_verified": False,
            "legal_clearance": False,
        },
        "model": {
            "url": MODEL_URL,
            "revision": MODEL_REVISION,
            "sha256": MODEL_SHA256,
            "license": MODEL_LICENSE,
            "license_status": LICENSE_STATUS,
            "license_verified": False,
            "legal_clearance": False,
        },
        "model_download_max_bytes": MODEL_DOWNLOAD_MAX_BYTES,
        "minimum_total_memory_bytes": MIN_TOTAL_MEMORY_BYTES,
        "minimum_free_root_bytes": MIN_FREE_ROOT_BYTES,
        "transfer_limits": {
            "llama_cpp_clone": {
                "status": PLAN_TRANSFER_UNKNOWN,
                "bound": PLAN_TRANSFER_UNCAPPED,
                "max_bytes": None,
                "bounded_by_this_tool": False,
            },
            "model_download": {
                "max_bytes": MODEL_DOWNLOAD_MAX_BYTES,
                "bounded_by_this_tool": True,
                "is_total_transfer_bound": False,
            },
            "source_clone_build_package_release": {
                "status": PLAN_TRANSFER_UNCAPPED,
                "max_bytes": None,
                "bounded_by_this_tool": False,
            },
        },
    }


def third_party_download_plan() -> dict[str, Any]:
    """Compatibility name for callers that request the source-only plan."""
    return build_third_party_download_plan()


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float = 120,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FirstKillError(f"could not run {' '.join(argv)}: {error}") from error
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise FirstKillError(detail or f"command failed: {' '.join(argv)}")
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(64 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise FirstKillError(f"cannot read {path}") from error
    return value.hexdigest()


def parse_checksums(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise FirstKillError("release SHA256SUMS is unreadable") from error
    for line in lines:
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or len(fields[0]) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in fields[0]
        ):
            raise FirstKillError("release SHA256SUMS contains an invalid line")
        name = fields[1].removeprefix("*")
        if not name or name in values:
            raise FirstKillError("release SHA256SUMS contains a duplicate or empty name")
        values[name] = fields[0].lower()
    if not values:
        raise FirstKillError("release SHA256SUMS is empty")
    return values


def validated_zip_members(bundle: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = bundle.infolist()
    if not members or len(members) > MAX_ARCHIVE_MEMBERS:
        raise FirstKillError("release bundle has an invalid member count")
    if min(member.header_offset for member in members) != 0:
        raise FirstKillError("release bundle contains prepended or concatenated data")
    seen: set[str] = set()
    total = 0
    for member in members:
        name = member.filename
        raw_name = name.removesuffix("/")
        raw_parts = raw_name.split("/")
        path = PurePosixPath(raw_name)
        parts = path.parts
        normalized = path.as_posix().rstrip("/")
        if (
            not name
            or "\x00" in name
            or "\\" in name
            or any(part in ("", ".", "..") for part in raw_parts)
            or path.is_absolute()
            or not normalized
            or any(part in ("", ".", "..") for part in parts)
            or (len(parts[0]) >= 2 and parts[0][1] == ":")
        ):
            raise FirstKillError("release bundle contains an unsafe path")
        if normalized in seen:
            raise FirstKillError("release bundle contains a duplicate path")
        seen.add(normalized)
        mode = (member.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if member.flag_bits & 0x1 or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise FirstKillError("release bundle contains a link or special member")
        if member.is_dir() != (file_type == stat.S_IFDIR) and file_type != 0:
            raise FirstKillError("release bundle member type is inconsistent")
        if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise FirstKillError("release bundle member exceeds the extraction limit")
        total += member.file_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise FirstKillError("release bundle exceeds the extraction limit")
    return members


def has_exact_zip_end(path: Path) -> bool:
    try:
        size = path.stat().st_size
        window_size = min(size, MAX_ZIP_COMMENT_BYTES + 22)
        with path.open("rb") as handle:
            handle.seek(size - window_size)
            tail = handle.read(window_size)
    except OSError:
        return False
    marker = b"PK\x05\x06"
    position = tail.find(marker)
    while position >= 0:
        if position + 22 <= len(tail):
            comment_size = int.from_bytes(tail[position + 20 : position + 22], "little")
            if position + 22 + comment_size == len(tail):
                return True
        position = tail.find(marker, position + 1)
    return False


def safe_extract(archive: Path, destination: Path) -> None:
    if not has_exact_zip_end(archive):
        raise FirstKillError("release bundle is truncated or has trailing data")
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = validated_zip_members(bundle)
            for member in members:
                candidate = (destination / member.filename).resolve()
                if not candidate.is_relative_to(destination.resolve()):
                    raise FirstKillError("release bundle contains an unsafe path")
            bundle.extractall(destination)
    except (OSError, zipfile.BadZipFile) as error:
        raise FirstKillError("release bundle is not a valid ZIP archive") from error


def download(url: str, destination: Path, *, maximum: int = MAX_DOWNLOAD_BYTES) -> None:
    if not url.startswith("https://"):
        raise FirstKillError("refusing a non-HTTPS release URL")
    request = urllib.request.Request(url, headers={"User-Agent": "Eggcracker-first-kill"})
    temporary = destination.with_name(f".{destination.name}.download")
    temporary.unlink(missing_ok=True)
    total = 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("xb") as handle:
            if not str(response.url).startswith("https://"):
                raise FirstKillError("release download redirected away from HTTPS")
            while block := response.read(64 * 1024):
                total += len(block)
                if total > maximum:
                    raise FirstKillError(f"release asset exceeds {maximum} bytes")
                handle.write(block)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except (OSError, urllib.error.URLError) as error:
        raise FirstKillError(f"could not download {url}: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def require_regular(path: Path, description: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FirstKillError(f"{description} is missing: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise FirstKillError(f"{description} must be a regular file: {path}")


def require_root_directory(path: Path, description: str, *, private: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FirstKillError(f"{description} is missing: {path}") from error
    forbidden_mode = 0o077 if private else 0o022
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & forbidden_mode
    ):
        access = "root-private" if private else "root-owned and not writable by group/other"
        raise FirstKillError(f"{description} must be a {access} directory: {path}")


def operator_name(explicit: str | None) -> str:
    if pwd is None:
        raise preflight_failure(
            "operator_database", "first-kill requires the POSIX passwd database"
        )
    value = explicit or os.environ.get("SUDO_USER")
    if not value or value == "root":
        raise preflight_failure(
            "operator_required", "run through sudo and pass --operator <your-login>"
        )
    try:
        account = pwd.getpwnam(value)
    except KeyError as error:
        raise preflight_failure("operator_missing", "operator account does not exist") from error
    if account.pw_uid == 0:
        raise preflight_failure("operator_root", "the operator must be a non-root login")
    return value


def require_host_commands() -> None:
    """Reject a host missing commands required later by the signed installer."""
    for binary in REQUIRED_HOST_COMMANDS:
        path = Path(binary)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise preflight_failure(
                "host_command",
                f"required host command is missing or not executable: {binary}",
            )


def require_clean_workload_identity() -> None:
    """Reject residue that a clean demonstration cannot safely claim or remove."""
    if pwd is None or grp is None:
        raise preflight_failure(
            "workload_database", "first-kill requires the POSIX account databases"
        )
    for lookup, identity in (
        (pwd.getpwnam, "account"),
        (grp.getgrnam, "group"),
    ):
        try:
            lookup(WORKLOAD_USER)
        except KeyError:
            continue
        raise preflight_failure(
            "workload_residue", f"refusing a pre-existing Eggcracker workload {identity}"
        )


def total_memory_bytes() -> int:
    """Return kernel-reported physical memory, or refuse an unverifiable host."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError) as error:
        raise preflight_failure("host_memory", "first-kill could not verify host memory") from error
    if (
        not isinstance(pages, int)
        or not isinstance(page_size, int)
        or pages < 1
        or page_size < 1
    ):
        raise preflight_failure("host_memory", "first-kill could not verify host memory")
    return pages * page_size


def free_root_bytes() -> int:
    """Return free root-filesystem bytes, or refuse an unverifiable host."""
    try:
        free = shutil.disk_usage("/").free
    except OSError as error:
        raise preflight_failure(
            "host_disk", "first-kill could not verify free root disk space"
        ) from error
    if not isinstance(free, int) or free < 0:
        raise preflight_failure("host_disk", "first-kill could not verify free root disk space")
    return free


def compatibility(operator: str) -> None:
    if os.geteuid() != 0:
        raise preflight_failure(
            "host_root", "run as root, for example: sudo python3 scripts/first_kill.py ..."
        )
    if platform.system() != "Linux":
        raise preflight_failure(
            "host_platform", "first-kill requires native Linux; Windows and macOS are unsupported"
        )
    if "microsoft" in platform.release().lower() or os.environ.get("WSL_DISTRO_NAME"):
        raise preflight_failure("host_wsl", "first-kill requires native Linux; WSL2 is unsupported")
    if total_memory_bytes() < MIN_TOTAL_MEMORY_BYTES:
        raise preflight_failure(
            "host_memory_limit",
            "first-kill requires at least 7 GiB of kernel-reported memory "
            "(normally an 8 GiB provisioned VM)",
        )
    if free_root_bytes() < MIN_FREE_ROOT_BYTES:
        raise preflight_failure(
            "host_disk_limit",
            "first-kill requires at least 8 GiB free on the root filesystem",
        )
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if not controllers.is_file() or "pids" not in controllers.read_text(encoding="ascii").split():
        raise preflight_failure(
            "host_cgroup", "unified cgroup v2 with the pids controller is required"
        )
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise preflight_failure("host_pidfd", "this Python/Linux host lacks the required pidfd primitives")
    require_host_commands()
    required_tool_groups = (
        (("cmake",), "CMake"),
        (("c++", "g++", "clang++"), "a C++ compiler (c++, g++ or clang++)"),
        (("make", "ninja"), "a CMake build backend (Make or Ninja)"),
    )
    for commands, description in required_tool_groups:
        if not any(shutil.which(command) for command in commands):
            raise preflight_failure("build_tool", f"required build tooling is missing: {description}")
    for target in INSTALL_TARGETS:
        if target.exists() or target.is_symlink():
            raise preflight_failure(
                "install_target", f"refusing to overwrite an existing installation target: {target}"
            )
    require_clean_workload_identity()
    try:
        if pwd is None:
            raise preflight_failure(
                "operator_database", "first-kill requires the POSIX passwd database"
            )
        pwd.getpwnam(operator)
    except KeyError as error:
        raise preflight_failure("operator_missing", "operator account does not exist") from error


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    try:
        probe = run(
            ["/usr/bin/git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            check=False,
        )
    except FirstKillError as error:
        raise preflight_failure("local_git", "could not inspect the local Git checkout") from error
    if probe.returncode or probe.stdout.strip() != "true":
        raise preflight_failure(
            "local_git", "first-kill must be run from a Git checkout containing the signed tag"
        )
    return root


def local_release_identity(root: Path, tag: str) -> str:
    """Verify the qualified local annotated tag without network or GPG state."""
    if tag != DEFAULT_TAG:
        raise preflight_failure(
            "tag_unsupported", f"preflight supports only the qualified local tag {DEFAULT_TAG}"
        )
    reference = f"refs/tags/{tag}"
    try:
        kind = run(["/usr/bin/git", "-C", str(root), "cat-file", "-t", reference], check=False)
        resolved = run(
            ["/usr/bin/git", "-C", str(root), "rev-parse", f"{reference}^{{}}"],
            check=False,
        )
    except FirstKillError as error:
        raise preflight_failure(
            "local_git", "could not inspect the qualified local release tag"
        ) from error
    if kind.returncode or kind.stdout.strip() != "tag":
        raise preflight_failure(
            "tag_not_annotated", f"the local {tag} reference is missing or is not an annotated tag"
        )
    commit = resolved.stdout.strip()
    if resolved.returncode or len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit.lower()
    ):
        raise preflight_failure("tag_commit", f"the local {tag} tag does not resolve to a commit")
    return commit


def _safe_preflight_tag(tag: str) -> str:
    """Expose only the fixed qualified tag; every other argument is untrusted."""
    return DEFAULT_TAG if tag == DEFAULT_TAG else "<redacted>"


def _preflight_diagnostic(error: BaseException) -> PreflightDiagnostic:
    if isinstance(error, PreflightFailure):
        return PreflightDiagnostic(error.failed_check, error.reason_code, error.next_action)
    return PREFLIGHT_DIAGNOSTICS["unexpected"]


def _print_preflight_blocked(tag: str, error: BaseException) -> None:
    diagnostic = _preflight_diagnostic(error)
    print(
        json.dumps(
            {
                "changes_made": False,
                "failed_check": diagnostic.failed_check,
                "mode": "preflight-only",
                "next_action": diagnostic.next_action,
                "reason_code": diagnostic.reason_code,
                "result": "PREFLIGHT_BLOCKED",
                "schema": PREFLIGHT_SCHEMA,
                "supported": False,
                "tag": _safe_preflight_tag(tag),
            },
            indent=2,
            sort_keys=True,
        )
    )


def run_preflight(operator_value: str | None, tag: str) -> int:
    """Run read-only host and local-release availability checks."""
    try:
        operator = operator_name(operator_value)
        compatibility(operator)
        commit = local_release_identity(repository_root(), tag)
    except Exception as error:  # noqa: BLE001 - bounded preflight output must not leak failures
        _print_preflight_blocked(tag, error)
        return 2
    print(
        json.dumps(
            {
                "changes_made": False,
                "checks": [
                    "host",
                    "operator",
                    "tool_availability",
                    "clean_install_targets",
                    "local_annotated_tag_identity",
                ],
                "mode": "preflight-only",
                "result": "PREFLIGHT_PASSED",
                "schema": PREFLIGHT_SCHEMA,
                "supported": True,
                "tag": tag,
                "tag_commit": commit,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def import_release_key(gpg_home: Path, key: Path) -> None:
    imported = run(
        ["/usr/bin/gpg", "--homedir", str(gpg_home), "--batch", "--import", str(key)],
        check=False,
    )
    if imported.returncode:
        raise FirstKillError(imported.stderr.strip() or "release public key import failed")
    shown = run(
        [
            "/usr/bin/gpg",
            "--homedir",
            str(gpg_home),
            "--batch",
            "--with-colons",
            "--show-keys",
            str(key),
        ]
    )
    primary_fingerprints: list[str] = []
    expect_primary_fingerprint = False
    for line in shown.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            expect_primary_fingerprint = True
        elif fields[0] == "fpr" and expect_primary_fingerprint:
            primary_fingerprints.append(fields[9].upper())
            expect_primary_fingerprint = False
    if primary_fingerprints != [RELEASE_KEY_FINGERPRINT]:
        raise FirstKillError(
            "downloaded release key does not contain exactly the published primary key"
        )


def require_pinned_valid_signature(
    result: subprocess.CompletedProcess[str], description: str
) -> None:
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise FirstKillError(f"{description} verification failed: {detail}")
    fingerprints: set[str] = set()
    marker = "[GNUPG:] VALIDSIG "
    for line in (result.stdout + "\n" + result.stderr).splitlines():
        position = line.find(marker)
        if position < 0:
            continue
        for value in line[position + len(marker) :].split():
            if re.fullmatch(r"[0-9A-Fa-f]{40}", value):
                fingerprints.add(value.upper())
    if RELEASE_KEY_FINGERPRINT not in fingerprints:
        raise FirstKillError(f"{description} was not signed by the pinned release key")


def verify_tag(root: Path, tag: str, key: Path) -> str:
    gpg_home = Path(tempfile.mkdtemp(prefix="eggcracker-gpg-"))
    os.chmod(gpg_home, 0o700)
    try:
        import_release_key(gpg_home, key)
        env = os.environ.copy()
        env["GNUPGHOME"] = str(gpg_home)
        verified = run(
            ["/usr/bin/git", "-C", str(root), "verify-tag", "--raw", tag],
            env=env,
            check=False,
        )
        require_pinned_valid_signature(verified, "signed tag")
        commit = run(["/usr/bin/git", "-C", str(root), "rev-parse", f"{tag}^{{}}"])
        return commit.stdout.strip()
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def verify_checksum_signature(key: Path, sums: Path, signature: Path) -> None:
    gpg_home = Path(tempfile.mkdtemp(prefix="eggcracker-gpg-"))
    os.chmod(gpg_home, 0o700)
    try:
        import_release_key(gpg_home, key)
        verified = run(
            [
                "/usr/bin/gpg",
                "--homedir",
                str(gpg_home),
                "--batch",
                "--status-fd",
                "1",
                "--verify",
                str(signature),
                str(sums),
            ],
            check=False,
        )
        require_pinned_valid_signature(verified, "release checksum signature")
    finally:
        shutil.rmtree(gpg_home, ignore_errors=True)


def verify_bundle_checksum(bundle: Path, sums: Path) -> None:
    expected = parse_checksums(sums)
    if expected.get(bundle.name) != digest(bundle):
        raise FirstKillError("downloaded Linux bundle does not match signed SHA256SUMS")


def release_files(tag: str, workspace: Path) -> tuple[Path, Path, Path, Path]:
    version = tag.removeprefix("v")
    if not version.replace(".", "").isdigit() or version.count(".") != 2:
        raise FirstKillError("tag must look like v1.0.10")
    base = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
    sums = workspace / "SHA256SUMS"
    signature = workspace / "SHA256SUMS.asc"
    bundle = workspace / f"lumi-eggcracker-{version}-linux.zip"
    key = workspace / "eggcracker-release-key.asc"
    download(f"{base}/SHA256SUMS", sums, maximum=64 * 1024)
    download(f"{base}/SHA256SUMS.asc", signature, maximum=64 * 1024)
    download(f"{base}/{bundle.name}", bundle, maximum=8 * 1024 * 1024)
    download(f"{base}/{key.name}", key, maximum=64 * 1024)
    for path, description in (
        (sums, "release SHA256SUMS"),
        (signature, "release checksum signature"),
        (key, "release public key"),
    ):
        require_regular(path, description)
    if b"BEGIN PGP PRIVATE KEY BLOCK" in key.read_bytes():
        raise FirstKillError("release key asset unexpectedly contains private key material")
    return bundle, key, sums, signature


def extracted_release(bundle: Path, workspace: Path) -> Path:
    extraction = workspace / "release"
    extraction.mkdir(mode=0o700)
    safe_extract(bundle, extraction)
    roots = [item for item in extraction.iterdir() if item.is_dir()]
    if len(roots) != 1:
        raise FirstKillError("release bundle has an unexpected top-level layout")
    root = roots[0]
    require_regular(root / "release-manifest.json", "release manifest")
    require_regular(root / "SHA256SUMS", "embedded SHA256SUMS")
    require_regular(root / f"{root.name}.pyz", "release artifact")
    return root


def manifest(release_root: Path) -> dict[str, Any]:
    try:
        value = json.loads((release_root / "release-manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FirstKillError("release manifest is invalid") from error
    if not isinstance(value, dict) or value.get("version") != release_root.name.removeprefix("lumi-eggcracker-"):
        raise FirstKillError("release manifest version does not match the bundle")
    return value


def install_release(release_root: Path, operator: str, release: dict[str, Any]) -> None:
    artifact = release_root / str(release["artifact"])
    installer = release_root / "scripts" / "install.py"
    require_regular(artifact, "release artifact")
    require_regular(installer, "release installer")
    run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(installer),
            "--operator",
            operator,
            "--artifact",
            str(artifact),
            "--expected-sha256",
            str(release["sha256"]),
        ],
        timeout=180,
    )


def installed_workload_user() -> str:
    if pwd is None:
        raise FirstKillError("first-kill requires the POSIX passwd database")
    path = Path("/var/lib/lumi-eggcracker/install-manifest.json")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        result = value["workload_user"]
        pwd.getpwnam(result)
    except (OSError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FirstKillError("installed workload identity cannot be verified") from error
    if result != WORKLOAD_USER:
        raise FirstKillError("installed workload identity is not the dedicated Eggcracker account")
    return result


def wait_for_receipt(before: set[Path], *, timeout: float = 240) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for path in sorted(DETECTIONS.glob("*.json"), key=lambda item: item.stat().st_mtime_ns):
            if path in before:
                continue
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and value.get("result") == "TERMINATED":
                return value
        time.sleep(0.02)
    raise FirstKillError("the real AI workload produced no TERMINATED receipt within 240 seconds")


def run_real_smoke(
    campaign_root: Path,
    workspace: Path,
    workload_user: str,
    assets_workspace: Path,
    demo_delay_seconds: float = 0,
) -> dict[str, Any]:
    # Run the campaign checkout's preparer so its current resource safeguards
    # govern the build. The qualified runner digest below still binds output.
    assets_script = campaign_root / "scripts" / "prepare_ai_smoke.py"
    require_regular(assets_script, "AI smoke preparer")
    run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(assets_script),
            "--workspace",
            str(assets_workspace),
            "--accept-third-party-downloads",
        ],
        timeout=1800,
    )
    manifest_path = assets_workspace / "ai-smoke-assets.json"
    require_regular(manifest_path, "AI smoke asset manifest")
    try:
        asset_value = json.loads(manifest_path.read_text(encoding="utf-8"))
        runner = Path(asset_value["llama"]["path"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise FirstKillError("AI smoke asset manifest has no usable runner path") from error
    if runner.is_symlink() or not runner.is_file():
        raise FirstKillError("pinned AI smoke runner is not a regular file")
    if digest(runner) != QUALIFIED_LLAMA_SHA256:
        raise FirstKillError(
            "the prepared llama.cpp runner is not the qualified release build; "
            "use the default /opt/lumi-eggcracker-ai-smoke workspace"
        )
    fixture = Path(tempfile.mkdtemp(prefix="eggcracker-first-kill-fixture-", dir="/tmp"))
    os.chmod(fixture, 0o711)
    runner_copy = fixture / secrets.token_hex(12)
    model_copy = fixture / secrets.token_hex(12)
    wrapper = fixture / f"{secrets.token_hex(8)}.py"
    output = fixture / "model-output"
    shutil.copyfile(runner, runner_copy)
    os.chmod(runner_copy, 0o755)
    # The asset workspace is root-private by design. Copy the runner's shared
    # libraries into the public fixture so the dedicated workload identity can
    # execute the real binary without granting it access to the asset cache.
    for library in runner.parent.glob("lib*.so*"):
        if library.is_symlink() or library.is_file():
            shutil.copyfile(library, fixture / library.name)
    try:
        os.link(Path(asset_value["model"]["path"]), model_copy)
    except OSError:
        shutil.copyfile(Path(asset_value["model"]["path"]), model_copy)
    os.chmod(model_copy, 0o644)
    wrapper.write_text(
        "import os,sys,time\n"
        "delay=float(os.environ.get('EGGCRACKER_FIRST_KILL_DELAY','0'))\n"
        "if delay: time.sleep(delay)\n"
        "os.execv(sys.argv[1], sys.argv[1:])\n",
        encoding="utf-8",
    )
    command = [
        str(runner_copy),
        "-m",
        str(model_copy),
        "-p",
        "Name one Linux cgroup property.",
        "-n",
        "4096",
        "-t",
        "12",
        "-tb",
        "12",
        "-c",
        "512",
        "--simple-io",
        "--single-turn",
        "--no-warmup",
        "--no-display-prompt",
        "--ignore-eos",
        "--seed",
        "1234",
    ]
    before = set(DETECTIONS.glob("*.json"))
    canary = subprocess.Popen(["/bin/sleep", "180"], start_new_session=True)
    workload: subprocess.Popen[bytes] | None = None
    handle = output.open("wb")
    try:
        workload = subprocess.Popen(
            [
                "/usr/sbin/runuser",
                "-u",
                workload_user,
                "--",
                "/usr/bin/env",
                f"LD_LIBRARY_PATH={fixture}",
                f"EGGCRACKER_FIRST_KILL_DELAY={demo_delay_seconds:.3f}",
                "/usr/bin/python3",
                str(wrapper),
                *command,
            ],
            stdout=handle,
            stderr=handle,
            start_new_session=True,
        )
        say(f"real unapproved AI workload started (pid {workload.pid})")
        time.sleep(0.5)
        if workload.poll() is not None:
            raise FirstKillError("the real AI workload exited before it could be observed")
        say("workload state: RUNNING; waiting for Eggcracker detection")
        receipt = wait_for_receipt(before)
        detector = receipt.get("detector") if isinstance(receipt.get("detector"), dict) else {}
        if detector.get("profile") != "content.gguf-llama":
            raise FirstKillError("the real workload was not classified by the expected GGUF/llama profile")
        if canary.poll() is not None:
            raise FirstKillError("the unrelated canary did not survive the first-kill")
        return receipt
    finally:
        handle.close()
        if workload is not None and workload.poll() is None:
            try:
                os.killpg(workload.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            workload.wait(timeout=5)
        if canary.poll() is None:
            try:
                os.killpg(canary.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            canary.wait(timeout=5)
        shutil.rmtree(fixture, ignore_errors=True)


def receipt_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    detector = receipt.get("detector") if isinstance(receipt.get("detector"), dict) else {}
    containment = receipt.get("containment") if isinstance(receipt.get("containment"), dict) else {}
    capture = receipt.get("capture") if isinstance(receipt.get("capture"), dict) else {}
    trigger_value = receipt.get("trigger")
    trigger = trigger_value.get("kind") if isinstance(trigger_value, dict) else trigger_value
    captured = capture.get("captured_processes")
    if isinstance(captured, list):
        captured = len(captured)
    elif not isinstance(captured, int):
        captured = None
    survivors = containment.get("surviving_pids")
    if isinstance(survivors, list):
        survivors = [] if not survivors else len(survivors)
    elif not isinstance(survivors, (int, type(None))):
        survivors = None
    return {
        "result": receipt.get("result"),
        "profile": detector.get("profile"),
        "trigger": trigger,
        "primitive": containment.get("primitive"),
        "captured_processes": captured,
        "root_populated": containment.get("root_populated"),
        "surviving_pids": survivors,
        "trigger_to_empty_ms": containment.get("trigger_to_empty_ms"),
    }


def _result_output_link_like(info: os.stat_result) -> bool:
    """Return whether an lstat/fstat result is a link or reparse point."""
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & RESULT_OUTPUT_REPARSE_POINT)


def _result_output_identity(info: os.stat_result) -> tuple[int, int]:
    device = getattr(info, "st_dev", None)
    inode = getattr(info, "st_ino", None)
    if type(device) is not int or type(inode) is not int:
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    return device, inode


def _result_output_effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    value = getter()
    if type(value) is not int or value < 0:
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    return value


def _result_output_check_owner_mode(info: os.stat_result, *, directory: bool, mode: int | None = None) -> None:
    """Check ownership and private mode without following a path component."""
    if _result_output_link_like(info):
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise FirstKillError(RESULT_OUTPUT_INVALID)
    elif not stat.S_ISREG(info.st_mode):
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    owner = getattr(info, "st_uid", None)
    if type(owner) is not int or owner != _result_output_effective_uid():
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    actual_mode = stat.S_IMODE(info.st_mode)
    if mode is not None:
        if actual_mode != mode:
            raise FirstKillError(RESULT_OUTPUT_INVALID)
    elif actual_mode & 0o022:
        raise FirstKillError(RESULT_OUTPUT_INVALID)


def _result_output_path(value: Path | str | os.PathLike[str]) -> Path:
    """Return a safe absolute lexical path; never resolve through links."""
    try:
        path = Path(value)
        if (
            not path.is_absolute()
            or not path.anchor
            or not path.name
            or any(part == ".." for part in path.parts)
            or "\x00" in os.fspath(path)
            or path.drive.startswith(("\\\\", "//"))
        ):
            raise FirstKillError(RESULT_OUTPUT_INVALID)
        return Path(os.path.abspath(os.fspath(path)))
    except (FirstKillError, OSError, TypeError, ValueError):
        raise FirstKillError(RESULT_OUTPUT_INVALID) from None


def _result_output_directory_chain(path: Path) -> tuple[int, int]:
    """Inspect every parent component and return the final directory identity."""
    try:
        anchor = Path(path.anchor)
        if not anchor.anchor:
            raise FirstKillError(RESULT_OUTPUT_INVALID)
        parts = path.parts[len(anchor.parts) :]
        current = anchor
        anchor_info = os.lstat(current)
        _result_output_check_owner_mode(anchor_info, directory=True)
        for part in parts:
            current = current / part
            info = os.lstat(current)
            _result_output_check_owner_mode(info, directory=True)
        return _result_output_identity(os.lstat(path))
    except FirstKillError:
        raise
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        raise FirstKillError(RESULT_OUTPUT_INVALID) from None


def _result_output_readonly_directory_chain(path: Path) -> None:
    """Check an absence path's parents without imposing output ownership rules."""
    try:
        anchor = Path(path.anchor)
        if not anchor.anchor:
            raise FirstKillError("installation removal could not be verified")
        current = anchor
        info = os.lstat(current)
        if _result_output_link_like(info) or not stat.S_ISDIR(info.st_mode):
            raise FirstKillError("installation removal could not be verified")
        for part in path.parts[len(anchor.parts) :]:
            current = current / part
            info = os.lstat(current)
            if _result_output_link_like(info) or not stat.S_ISDIR(info.st_mode):
                raise FirstKillError("installation removal could not be verified")
    except FirstKillError:
        raise
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        raise FirstKillError("installation removal could not be verified") from None


def _result_output_is_within(path: Path, target: Path) -> bool:
    try:
        return os.path.commonpath((os.fspath(path), os.fspath(target))) == os.fspath(target)
    except (OSError, ValueError):
        return False


def validate_result_output(
    value: Path | str | os.PathLike[str],
    *,
    forbidden_targets: tuple[Path, ...] = (),
) -> Path:
    """Validate a new result destination before any campaign effects."""
    path = _result_output_path(value)
    for target_value in (*INSTALL_TARGETS, *forbidden_targets):
        try:
            target = _result_output_path(target_value)
        except FirstKillError:
            # A fixed managed target is always absolute.  A malformed optional
            # target is a fail-closed destination refusal, never an exemption.
            raise FirstKillError(RESULT_OUTPUT_INVALID) from None
        if _result_output_is_within(path, target):
            raise FirstKillError(RESULT_OUTPUT_INVALID)
    _result_output_directory_chain(path.parent)
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        return path
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        raise FirstKillError(RESULT_OUTPUT_INVALID) from None
    if _result_output_link_like(existing) or stat.S_ISREG(existing.st_mode):
        raise FirstKillError(RESULT_OUTPUT_INVALID)
    raise FirstKillError(RESULT_OUTPUT_INVALID)


def _result_output_parent_matches(fd: int, identity: tuple[int, int]) -> bool:
    try:
        info = os.fstat(fd)
        _result_output_check_owner_mode(info, directory=True)
        return _result_output_identity(info) == identity
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        return False


def _result_output_parent_path_matches(path: Path, identity: tuple[int, int]) -> bool:
    try:
        return _result_output_directory_chain(path) == identity
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        return False


def _result_output_verify_file(info: os.stat_result, identity: tuple[int, int]) -> None:
    _result_output_check_owner_mode(info, directory=False, mode=0o600)
    if _result_output_identity(info) != identity:
        raise FirstKillError(RESULT_OUTPUT_FAILURE)


def _result_output_unlink_owned(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    parent_identity: tuple[int, int],
    parent_path: Path,
) -> None:
    """Remove only our exact temporary inode after revalidating its parent."""
    if not _result_output_parent_matches(parent_fd, parent_identity) or not _result_output_parent_path_matches(
        parent_path, parent_identity
    ):
        return
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _result_output_verify_file(current, identity)
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        return


def _result_output_unlink_published_owned(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    parent_identity: tuple[int, int],
    parent_path: Path,
) -> None:
    """Remove only our published inode after a later publication failure."""
    if not _result_output_parent_matches(parent_fd, parent_identity) or not _result_output_parent_path_matches(
        parent_path, parent_identity
    ):
        return
    try:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(parent_fd)
            return
        _result_output_verify_file(current, identity)
        os.unlink(name, dir_fd=parent_fd)
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(parent_fd)
        else:
            return
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        return


def publish_success_result(
    destination: Path,
    document: dict[str, Any],
    *,
    forbidden_targets: tuple[Path, ...] = (),
) -> None:
    """Publish one result atomically, without replacing any existing file."""
    try:
        destination = validate_result_output(destination, forbidden_targets=forbidden_targets)
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode("utf-8")
        if len(encoded) > RESULT_OUTPUT_MAX_BYTES:
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        directory = destination.parent
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        supported_dir_fd = getattr(os, "supports_dir_fd", set())
        if not all(callable(item) and item in supported_dir_fd for item in (os.stat, os.link, os.unlink)):
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        parent_info = os.lstat(directory)
        _result_output_check_owner_mode(parent_info, directory=True)
        parent_identity = _result_output_identity(parent_info)
        parent_fd = os.open(
            os.fspath(directory),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except FirstKillError:
        raise FirstKillError(RESULT_OUTPUT_FAILURE) from None
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        raise FirstKillError(RESULT_OUTPUT_FAILURE) from None

    descriptor: int | None = None
    temporary_name: str | None = None
    temporary_identity: tuple[int, int] | None = None
    destination_published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        for _ in range(8):
            candidate = f".{destination.name}.lumi-first-kill-{secrets.token_hex(12)}.tmp"
            try:
                descriptor = os.open(candidate, flags, 0o600, dir_fd=parent_fd)
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or temporary_name is None:
            raise FirstKillError(RESULT_OUTPUT_FAILURE)

        if not hasattr(os, "fchmod"):
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        _result_output_check_owner_mode(created, directory=False, mode=0o600)
        temporary_identity = _result_output_identity(created)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FirstKillError(RESULT_OUTPUT_FAILURE)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        if not _result_output_parent_matches(parent_fd, parent_identity):
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        if not _result_output_parent_path_matches(directory, parent_identity):
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        current_temporary = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        _result_output_verify_file(current_temporary, temporary_identity)
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FirstKillError(RESULT_OUTPUT_FAILURE)

        os.link(
            temporary_name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        destination_published = True
        published = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        _result_output_verify_file(published, temporary_identity)
        _result_output_unlink_owned(
            parent_fd,
            temporary_name,
            temporary_identity,
            parent_identity,
            directory,
        )
        try:
            os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FirstKillError(RESULT_OUTPUT_FAILURE)
        os.fsync(parent_fd)
    except FirstKillError:
        if destination_published and temporary_identity is not None:
            _result_output_unlink_published_owned(
                parent_fd,
                destination.name,
                temporary_identity,
                parent_identity,
                directory,
            )
        raise FirstKillError(RESULT_OUTPUT_FAILURE) from None
    except Exception:  # noqa: BLE001 - fail closed without reflecting platform details
        if destination_published and temporary_identity is not None:
            _result_output_unlink_published_owned(
                parent_fd,
                destination.name,
                temporary_identity,
                parent_identity,
                directory,
            )
        raise FirstKillError(RESULT_OUTPUT_FAILURE) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_name is not None and temporary_identity is not None:
            _result_output_unlink_owned(
                parent_fd,
                temporary_name,
                temporary_identity,
                parent_identity,
                directory,
            )
        try:
            os.close(parent_fd)
        except OSError:
            pass


def _success_receipt_projection(receipt: object) -> dict[str, Any]:
    """Validate kill/canary evidence and return only bounded safe metrics."""
    if type(receipt) is not dict or receipt.get("result") != "TERMINATED":
        raise FirstKillError("the first-kill receipt is malformed")
    for canary_field in ("canary_survived", "canary_alive"):
        if canary_field in receipt and receipt[canary_field] is not True:
            raise FirstKillError("the first-kill receipt is malformed")
    detector = receipt.get("detector")
    trigger = receipt.get("trigger")
    capture = receipt.get("capture")
    containment = receipt.get("containment")
    if not all(type(item) is dict for item in (detector, trigger, capture, containment)):
        raise FirstKillError("the first-kill receipt is malformed")
    if detector.get("profile") != "content.gguf-llama":
        raise FirstKillError("the first-kill receipt is malformed")
    if trigger.get("kind") != "UNAPPROVED_AI_MATCH":
        raise FirstKillError("the first-kill receipt is malformed")
    if containment.get("primitive") != "pidfd-stop+cgroup.kill":
        raise FirstKillError("the first-kill receipt is malformed")
    root_populated = containment.get("root_populated")
    surviving_pids = containment.get("surviving_pids")
    captured = capture.get("captured_processes")
    elapsed = containment.get("trigger_to_empty_ms")
    if type(root_populated) is not int or root_populated != 0:
        raise FirstKillError("the first-kill receipt is malformed")
    if type(surviving_pids) is not list or surviving_pids:
        raise FirstKillError("the first-kill receipt is malformed")
    if type(captured) is not int or not 1 <= captured <= RESULT_OUTPUT_MAX_CAPTURED_PROCESSES:
        raise FirstKillError("the first-kill receipt is malformed")
    if type(elapsed) not in (int, float) or isinstance(elapsed, bool):
        raise FirstKillError("the first-kill receipt is malformed")
    if not math.isfinite(float(elapsed)) or not 0 <= float(elapsed) <= RESULT_OUTPUT_MAX_TRIGGER_TO_EMPTY_MS:
        raise FirstKillError("the first-kill receipt is malformed")
    if "error" in receipt:
        raise FirstKillError("the first-kill receipt is malformed")
    return {
        "captured_processes": captured,
        "primitive": "pidfd-stop+cgroup.kill",
        "profile": "content.gguf-llama",
        "root_populated": 0,
        "surviving_pids": 0,
        "trigger": "UNAPPROVED_AI_MATCH",
        "trigger_to_empty_ms": float(elapsed),
    }


def build_success_result(
    receipt: object,
    tag: str,
    source_commit: str,
    disposition: str,
    *,
    ai_workspace_preexisting: bool = False,
) -> dict[str, Any]:
    """Build the fixed, nonidentifying success document."""
    if (
        type(tag) is not str
        or len(tag) > 32
        or not RESULT_OUTPUT_TAG.fullmatch(tag)
        or type(source_commit) is not str
        or not RESULT_OUTPUT_COMMIT.fullmatch(source_commit)
        or type(disposition) is not str
        or disposition not in SUCCESS_DISPOSITIONS
        or type(ai_workspace_preexisting) is not bool
    ):
        raise FirstKillError("the first-kill success result is malformed")
    if ai_workspace_preexisting:
        ai_assets_disposition = SUCCESS_AI_ASSETS_PREEXISTING_EXCLUDED
    elif disposition == SUCCESS_DISPOSITION_REMOVED:
        ai_assets_disposition = SUCCESS_AI_ASSETS_NEW_REMOVED
    else:
        ai_assets_disposition = SUCCESS_AI_ASSETS_NEW_RETAINED
    document: dict[str, Any] = {
        "ai_assets_disposition": ai_assets_disposition,
        "authenticated": False,
        "disposition": disposition,
        "independent_containment_proof": False,
        "result": SUCCESS_RESULT_VALUE,
        "run_scope": SUCCESS_RUN_SCOPE,
        "schema": SUCCESS_RESULT_SCHEMA,
        "source_commit": source_commit,
        "source_commit_role": SUCCESS_SOURCE_COMMIT_ROLE,
        "tag": tag,
        "version": SUCCESS_RESULT_VERSION,
    }
    document.update(_success_receipt_projection(receipt))
    if set(document) != SUCCESS_RESULT_FIELDS:
        raise FirstKillError("the first-kill success result is malformed")
    try:
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError) as error:
        raise FirstKillError("the first-kill success result is malformed") from error
    if len(encoded) > RESULT_OUTPUT_MAX_BYTES:
        raise FirstKillError("the first-kill success result is malformed")
    return document


def verify_removed_targets(
    workspace: Path,
    assets_workspace: Path | None,
    *,
    assets_preexisting: bool,
) -> None:
    """Verify every exact managed target is absent without following links."""
    targets: list[Path] = list(INSTALL_TARGETS) + [workspace]
    if assets_workspace is not None and not assets_preexisting:
        targets.append(assets_workspace)
    seen: set[str] = set()
    for target in targets:
        try:
            path = _result_output_path(target)
            key = os.path.normcase(os.fspath(path))
            if key in seen:
                continue
            seen.add(key)
            try:
                os.lstat(path)
            except FileNotFoundError:
                # A missing leaf is trustworthy only when its entire parent
                # chain is still made of real directories; a dangling parent
                # link is an error, not proof of absence.
                _result_output_readonly_directory_chain(path.parent)
            else:
                raise FirstKillError("installation removal could not be verified")
        except FirstKillError:
            raise
        except (OSError, TypeError, ValueError):
            raise FirstKillError("installation removal could not be verified") from None


def remove_installation(release_root: Path, workspace: Path, assets_workspace: Path | None = None) -> None:
    uninstaller = release_root / "scripts" / "uninstall.py"
    verify = release_root / "scripts" / "verify_uninstalled.py"
    if not uninstaller.is_file():
        raise FirstKillError("release uninstaller is missing")
    run(["/usr/bin/python3", "-I", "-S", str(uninstaller)], timeout=180)
    if verify.is_file():
        run(["/usr/bin/python3", "-I", "-S", str(verify)], timeout=60)
    shutil.rmtree(workspace, ignore_errors=True)
    if assets_workspace is not None and assets_workspace.exists() and not assets_workspace.is_symlink():
        shutil.rmtree(assets_workspace, ignore_errors=True)


def cleanup_choice() -> bool:
    if not sys.stdin.isatty():
        return False
    answer = input("Remove Eggcracker and temporary smoke assets now? [Y/n] ").strip().lower()
    return answer in {"", "y", "yes"}


def prepare_workspace(path: Path) -> Path:
    """Create or safely reuse a first-kill workspace for repeat demonstrations."""
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise FirstKillError("--workspace must be a non-symlink directory")
        require_root_directory(path, "--workspace", private=True)
        allowed = {
            "ai-smoke",
            "release",
            "SHA256SUMS",
            "SHA256SUMS.asc",
            "eggcracker-release-key.asc",
        }
        unexpected = [
            item.name
            for item in path.iterdir()
            if item.name not in allowed
            and not (
                item.name.startswith("lumi-eggcracker-")
                and item.name.endswith("-linux.zip")
            )
        ]
        if unexpected:
            raise FirstKillError("--workspace contains unexpected files: " + ", ".join(sorted(unexpected)))
        old_release = path / "release"
        if old_release.is_symlink():
            raise FirstKillError("--workspace release directory must not be a symlink")
        if old_release.exists():
            shutil.rmtree(old_release)
    else:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    require_root_directory(path, "--workspace", private=True)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify, install and demonstrate the signed Eggcracker release on Linux."
    )
    parser.add_argument("--operator", help="non-root login that will operate Eggcracker")
    parser.add_argument("--tag", help=f"signed release tag (default: {DEFAULT_TAG})")
    parser.add_argument("--workspace", type=Path, help="temporary workspace; default is a new /tmp directory")
    parser.add_argument(
        "--ai-workspace",
        type=Path,
        help="root-owned workspace for the pinned real-AI demo (default: /opt/lumi-eggcracker-ai-smoke)",
    )
    parser.add_argument(
        "--demo-delay-seconds",
        type=float,
        default=None,
        help="keep the real workload visibly running before model execution (recording aid; max 60s)",
    )
    parser.add_argument(
        "--accept-third-party-downloads",
        action="store_true",
        help="accept downloading the pinned llama.cpp source and Qwen model for the demonstration",
    )
    parser.add_argument(
        "--third-party-download-plan",
        action="store_true",
        help="print the deterministic offline source-only third-party download plan",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="check host, tools and local release identity without downloads or system changes",
    )
    parser.add_argument("--keep", action="store_true", help="leave the installation and smoke assets in place")
    parser.add_argument("--remove", action="store_true", help="remove the installation without prompting")
    parser.add_argument(
        "--result-output",
        type=Path,
        help="write the opt-in fixed success result to a new absolute file",
    )
    args = parser.parse_args(argv)

    # Keep this branch immediately after parsing: a plan is an informational
    # projection and must not inspect the operator, host, checkout or paths,
    # and must not perform any workspace, network, subprocess, install or
    # other effect.
    if args.third_party_download_plan:
        incompatible = []
        if args.operator is not None:
            incompatible.append("--operator")
        if args.tag is not None:
            incompatible.append("--tag")
        if args.workspace is not None:
            incompatible.append("--workspace")
        if args.ai_workspace is not None:
            incompatible.append("--ai-workspace")
        if args.demo_delay_seconds is not None:
            incompatible.append("--demo-delay-seconds")
        if args.accept_third_party_downloads:
            incompatible.append("--accept-third-party-downloads")
        if args.preflight_only:
            incompatible.append("--preflight-only")
        if args.keep:
            incompatible.append("--keep")
        if args.remove:
            incompatible.append("--remove")
        if args.result_output is not None:
            incompatible.append("--result-output")
        if incompatible:
            parser.error(
                "--third-party-download-plan cannot be combined with " + ", ".join(incompatible)
            )
        try:
            value = build_third_party_download_plan()
        except ThirdPartyPlanError as error:
            raise SystemExit("third-party download plan unavailable: pinned inputs are invalid") from error
        print(json.dumps(value, sort_keys=True))
        return 0

    tag = DEFAULT_TAG if args.tag is None else args.tag
    demo_delay_seconds = 0 if args.demo_delay_seconds is None else args.demo_delay_seconds
    if args.keep and args.remove:
        parser.error("--keep and --remove are mutually exclusive")
    if not 0 <= demo_delay_seconds <= 60:
        parser.error("--demo-delay-seconds must be between 0 and 60")
    if args.preflight_only:
        incompatible = []
        if args.workspace is not None:
            incompatible.append("--workspace")
        if args.ai_workspace is not None:
            incompatible.append("--ai-workspace")
        if args.keep:
            incompatible.append("--keep")
        if args.remove:
            incompatible.append("--remove")
        if args.result_output is not None:
            incompatible.append("--result-output")
        if args.demo_delay_seconds:
            incompatible.append("--demo-delay-seconds")
        if args.accept_third_party_downloads:
            incompatible.append("--accept-third-party-downloads")
        if incompatible:
            parser.error("--preflight-only cannot be combined with " + ", ".join(incompatible))
        return run_preflight(args.operator, tag)
    if not args.accept_third_party_downloads:
        parser.error("--accept-third-party-downloads is required because the demo downloads a real model")

    if args.result_output is not None:
        if args.keep == args.remove:
            parser.error("--result-output requires exactly one explicit --keep or --remove")
        preliminary_forbidden: list[Path] = []
        if args.workspace is not None:
            preliminary_forbidden.append(Path(os.path.abspath(os.fspath(args.workspace))))
        preliminary_forbidden.append(
            Path(os.path.abspath(os.fspath(args.ai_workspace or DEFAULT_AI_SMOKE_WORKSPACE)))
        )
        try:
            args.result_output = validate_result_output(
                args.result_output,
                forbidden_targets=tuple(preliminary_forbidden),
            )
        except FirstKillError:
            parser.error(RESULT_OUTPUT_INVALID)

    workspace: Path | None = None
    ai_workspace: Path | None = None
    ai_workspace_preexisting = False
    release_root: Path | None = None
    stage = FULL_RUN_STAGE_PRE_INSTALL
    installation_state = FULL_RUN_INSTALL_STATE_NOT_INSTALLED
    try:
        stage = FULL_RUN_STAGE_PRE_INSTALL
        operator = operator_name(args.operator)
        say("checking Linux, cgroup-v2, pidfd and clean-install compatibility")
        compatibility(operator)
        root = repository_root()
        if args.workspace:
            workspace = prepare_workspace(args.workspace.absolute())
        else:
            workspace = Path(tempfile.mkdtemp(prefix="eggcracker-first-kill-"))
            os.chmod(workspace, 0o700)
        ai_workspace = (args.ai_workspace or DEFAULT_AI_SMOKE_WORKSPACE).absolute()
        ai_workspace_preexisting = ai_workspace.exists()
        if ai_workspace.is_symlink() or (ai_workspace.exists() and not ai_workspace.is_dir()):
            raise FirstKillError("--ai-workspace must be a non-symlink directory")
        if ai_workspace_preexisting:
            require_root_directory(ai_workspace, "--ai-workspace", private=False)
        if args.result_output is not None:
            args.result_output = validate_result_output(
                args.result_output,
                forbidden_targets=(workspace, ai_workspace),
            )
        say(f"downloading and checking signed {tag} release assets")
        bundle, key, sums, signature = release_files(tag, workspace)
        commit = verify_tag(root, tag, key)
        verify_checksum_signature(key, sums, signature)
        verify_bundle_checksum(bundle, sums)
        release_root = extracted_release(bundle, workspace)
        release = manifest(release_root)
        if release.get("source_commit") != commit:
            raise FirstKillError("signed tag commit and release source commit do not match")
        verifier = release_root / "scripts" / "verify_release.py"
        source_archive = release_root / str(release["source_archive"])
        artifact = release_root / str(release["artifact"])
        run(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                str(verifier),
                "--artifact",
                str(artifact),
                "--source-archive",
                str(source_archive),
                "--release-bundle",
                str(bundle),
            ],
            timeout=180,
        )
        say(f"signature and release identity verified: {tag} -> {commit}")
        say("installing the root-controlled supervisor")
        stage = FULL_RUN_STAGE_INSTALL
        installation_state = FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL
        install_release(release_root, operator, release)
        installation_state = FULL_RUN_INSTALL_STATE_INSTALLED
        stage = FULL_RUN_STAGE_POST_INSTALL
        workload_user = installed_workload_user()
        say("preparing the pinned real local-AI smoke assets (explicit third-party download)")
        say("launching an unapproved model and waiting for the complete-tree kill")
        receipt = run_real_smoke(
            root,
            workspace,
            workload_user,
            ai_workspace,
            demo_delay_seconds,
        )
        safe_receipt_projection: dict[str, Any] | None = None
        if args.result_output is not None:
            safe_receipt_projection = _success_receipt_projection(receipt)
            print(
                json.dumps(
                    {"result": "TERMINATED", **safe_receipt_projection},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(json.dumps(receipt_summary(receipt), indent=2, sort_keys=True))
        say("first-kill demonstration passed: the real workload was terminated and its canary survived")
        should_remove = args.remove or (not args.keep and cleanup_choice())
        if should_remove:
            say("removing Eggcracker and temporary smoke assets")
            stage = FULL_RUN_STAGE_REMOVAL
            installation_state = FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL
            remove_installation(
                release_root,
                workspace,
                None if ai_workspace_preexisting else ai_workspace,
            )
            if args.result_output is not None:
                verify_removed_targets(
                    workspace,
                    None if ai_workspace_preexisting else ai_workspace,
                    assets_preexisting=ai_workspace_preexisting,
                )
                installation_state = FULL_RUN_INSTALL_STATE_NOT_INSTALLED
            workspace = None
            ai_workspace = None
            say("clean removal passed")
        else:
            if args.result_output is not None:
                installation_state = FULL_RUN_INSTALL_STATE_INSTALLED
                say("left installed by request")
            else:
                say(f"left installed by request; release workspace: {workspace}; AI assets: {ai_workspace}")
        if args.result_output is not None:
            disposition = (
                SUCCESS_DISPOSITION_REMOVED if should_remove else SUCCESS_DISPOSITION_RETAINED
            )
            stage = FULL_RUN_STAGE_RESULT_PUBLICATION
            document = build_success_result(
                receipt,
                tag,
                commit,
                disposition,
                ai_workspace_preexisting=ai_workspace_preexisting,
            )
            publish_success_result(args.result_output, document)
        return 0
    except (FirstKillError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            say("cancelled")
        else:
            _print_full_run_failure(stage, installation_state)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
