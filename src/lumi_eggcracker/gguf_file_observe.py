"""Private, read-only GGUF file-evidence prototype.

This module deliberately observes one explicitly selected file only.  It does
not identify a workload, inspect a runtime, or request an action.  The GGUF
header and prefix digest come from :func:`lumi_eggcracker.artifacts.validate_gguf_fd`;
this module adds the stricter single-path boundary and a small public report.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass

from .artifacts import MAX_ARTIFACT_BYTES, ArtifactEvidence, validate_gguf_fd
from .detectors import Catalogue, load_bundled
from .jsonio import JsonInputError, canonical_bytes

SCHEMA = "lumi-eggcracker.gguf-file-evidence.v1"

# These are deliberately fixed, local bounds.  They are part of this private
# prototype's boundary rather than values supplied by the selected pathname or
# by a catalogue file.
MIN_FILE_BYTES = 25
MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_STRING_BYTES = 256
MAX_OUTPUT_BYTES = 16 * 1024
MAX_ERROR_BYTES = 128
MAX_CONTENT_PROFILES = 16
MAX_PROFILE_GROUPS = 8
MAX_GROUP_VALUES = 16
MAX_LIST_ITEMS = 32

ERROR_TEXT = "file evidence observation refused\n"
CONTENT_GROUPS = ("MODEL_CONTENT", "MODEL_RUNTIME", "MODEL_TOPOLOGY")
LIMITATIONS = (
    "file evidence does not establish runtime or topology",
    "file evidence does not establish workload identity or provenance",
    "file evidence does not establish approval",
    "file evidence does not establish safety",
    "file evidence does not establish containment",
    "file evidence does not establish actuation",
    "file evidence does not establish native qualification",
)


@dataclass(frozen=True)
class _StableIdentity:
    """Path/fd identity fields safe for a same-object comparison.

    ``st_ctime_ns`` is intentionally absent.  On Windows it is not a stable
    identity field, and comparing it between a pathname stat and descriptor
    stat would reject or accept files for platform-specific reasons.
    """

    device: int
    inode: int
    size: int
    mode: int


@dataclass(frozen=True)
class _ChangeMarker:
    identity: _StableIdentity
    mtime_ns: int


def _bounded_text(value: object, *, limit: int = MAX_STRING_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise JsonInputError("bounded text is invalid")
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as error:
        raise JsonInputError("bounded text is invalid") from error
    if size > limit:
        raise JsonInputError("bounded text exceeds the fixed limit")
    return value


def _path_argument(path: str | os.PathLike[str]) -> str | bytes:
    try:
        value = os.fspath(path)
    except (TypeError, ValueError) as error:
        raise JsonInputError("selected path is invalid") from error
    if not isinstance(value, (str, bytes)) or not value:
        raise JsonInputError("selected path is invalid")
    try:
        encoded = os.fsencode(value)
    except (TypeError, UnicodeError) as error:
        raise JsonInputError("selected path is invalid") from error
    if not encoded or len(encoded) > MAX_PATH_BYTES or b"\0" in encoded:
        raise JsonInputError("selected path exceeds the fixed limit")
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return isinstance(attributes, int) and bool(attributes & reparse)


def _stable_identity(metadata: os.stat_result) -> _StableIdentity:
    try:
        return _StableIdentity(
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_size),
            int(metadata.st_mode),
        )
    except (AttributeError, TypeError, ValueError, OverflowError) as error:
        raise JsonInputError("file identity is unavailable") from error


def _change_marker(metadata: os.stat_result) -> _ChangeMarker:
    identity = _stable_identity(metadata)
    try:
        mtime_ns = int(metadata.st_mtime_ns)
    except (AttributeError, TypeError, ValueError, OverflowError) as error:
        raise JsonInputError("file change marker is unavailable") from error
    return _ChangeMarker(identity, mtime_ns)


def _check_regular(metadata: os.stat_result) -> _StableIdentity:
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise JsonInputError("selected path must not be a link or reparse point")
    if not stat.S_ISREG(metadata.st_mode):
        raise JsonInputError("selected path must be a regular file")
    identity = _stable_identity(metadata)
    if not MIN_FILE_BYTES <= identity.size <= MAX_FILE_BYTES:
        raise JsonInputError("selected file size is outside the fixed limit")
    return identity


def _lstat(path: str | bytes) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except (OSError, ValueError) as error:
        raise JsonInputError("selected file cannot be inspected") from error
    _check_regular(metadata)
    return metadata


def _fstat(descriptor: int) -> os.stat_result:
    try:
        metadata = os.fstat(descriptor)
    except (OSError, ValueError) as error:
        raise JsonInputError("opened file identity is unavailable") from error
    _check_regular(metadata)
    return metadata


def _open_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    return flags


def _open_selected(path: str | bytes) -> int:
    try:
        return os.open(path, _open_flags())
    except (OSError, ValueError) as error:
        raise JsonInputError("selected file cannot be opened") from error


def _version(evidence: ArtifactEvidence) -> int:
    prefix = "gguf-v"
    if not isinstance(evidence.evidence_id, str) or not evidence.evidence_id.startswith(prefix):
        raise JsonInputError("parser returned unsupported evidence")
    try:
        version = int(evidence.evidence_id[len(prefix) :])
    except (TypeError, ValueError) as error:
        raise JsonInputError("parser returned unsupported evidence") from error
    if version not in {2, 3}:
        raise JsonInputError("parser returned unsupported evidence")
    return version


def _catalogue_profiles(
    catalogue: Catalogue, *, evidence_id: str
) -> tuple[list[dict[str, object]], list[str]]:
    if len(catalogue.profiles) > MAX_CONTENT_PROFILES:
        raise JsonInputError("catalogue profile count exceeds the fixed limit")
    supplied: dict[str, set[str]] = {
        "MODEL_CONTENT": {evidence_id},
        "MODEL_RUNTIME": set(),
        "MODEL_TOPOLOGY": set(),
    }
    reports: list[dict[str, object]] = []
    complete: list[str] = []
    for profile in catalogue.profiles:
        if profile.path != "CONTENT":
            continue
        identifier = _bounded_text(profile.identifier)
        if len(profile.groups) > MAX_PROFILE_GROUPS:
            raise JsonInputError("catalogue group count exceeds the fixed limit")
        groups: list[dict[str, object]] = []
        profile_complete = True
        for requirement in profile.groups:
            group = requirement.get("group")
            values = requirement.get("any")
            if group not in CONTENT_GROUPS or not isinstance(values, tuple):
                raise JsonInputError("catalogue group is invalid")
            if len(values) > MAX_GROUP_VALUES:
                raise JsonInputError("catalogue value count exceeds the fixed limit")
            required: list[str] = []
            for value in values:
                required.append(_bounded_text(value, limit=MAX_STRING_BYTES))
            if len(required) > MAX_LIST_ITEMS:
                raise JsonInputError("catalogue list exceeds the fixed limit")
            available = supplied[group]
            matched = [value for value in required if value in available]
            satisfied = bool(matched)
            missing = [] if satisfied else required
            if not satisfied:
                profile_complete = False
            groups.append(
                {
                    "group": group,
                    "required_any": required,
                    "supplied": matched,
                    "missing": missing,
                    "satisfied": satisfied,
                }
            )
        if profile_complete:
            complete.append(identifier)
        reports.append({"id": identifier, "groups": groups, "complete": profile_complete})
    return reports, complete


def _report(evidence: ArtifactEvidence, catalogue: Catalogue) -> dict[str, object]:
    evidence_id = _bounded_text(evidence.evidence_id)
    version = _version(evidence)
    if evidence.format != "GGUF":
        raise JsonInputError("parser returned unsupported format")
    try:
        size = int(evidence.size)
    except (TypeError, ValueError, OverflowError) as error:
        raise JsonInputError("parser returned invalid size") from error
    if not MIN_FILE_BYTES <= size <= MAX_FILE_BYTES:
        raise JsonInputError("parser returned invalid size")
    public = evidence.public()
    size_bucket = public.get("size_bucket")
    if not isinstance(size_bucket, str):
        raise JsonInputError("parser returned invalid size bucket")
    size_bucket = _bounded_text(size_bucket)
    prefix_sha256 = evidence.header_sha256
    if (
        not isinstance(prefix_sha256, str)
        or len(prefix_sha256) != 64
        or any(character not in "0123456789abcdef" for character in prefix_sha256)
    ):
        raise JsonInputError("parser returned invalid prefix hash")
    profiles, complete = _catalogue_profiles(catalogue, evidence_id=evidence_id)
    if len(profiles) > MAX_CONTENT_PROFILES or len(complete) > MAX_CONTENT_PROFILES:
        raise JsonInputError("catalogue output count exceeds the fixed limit")
    inspected = min(size, MAX_ARTIFACT_BYTES)
    report: dict[str, object] = {
        "schema_version": SCHEMA,
        "result": "FILE_EVIDENCE_ONLY",
        "evidence": {
            "format": "GGUF",
            "evidence_id": evidence_id,
            "gguf_version": version,
            "size_bucket": size_bucket,
            "hash_scope": "first_prefix_only",
            "prefix_sha256": prefix_sha256,
            "inspected_prefix_bytes": inspected,
        },
        "content_evidence": {
            "MODEL_CONTENT": [evidence_id],
            "MODEL_RUNTIME": [],
            "MODEL_TOPOLOGY": [],
        },
        "catalogue": {
            "schema_version": "lumi-eggcracker.detectors.v3",
            "content_profiles": profiles,
            "complete_profiles": complete,
        },
        "limitations": list(LIMITATIONS),
    }
    return report


def observe_file(path: str | os.PathLike[str]) -> dict[str, object]:
    """Observe exactly one path and return a redacted file-evidence report.

    The caller owns presentation.  The function never writes to the selected
    file or to a report file; the command-line wrapper emits the report on
    stdout only after all checks have completed.
    """

    selected = _path_argument(path)
    path_before = _lstat(selected)
    path_identity = _stable_identity(path_before)
    path_marker = _change_marker(path_before)
    descriptor = _open_selected(selected)
    try:
        fd_before = _fstat(descriptor)
        if _stable_identity(fd_before) != path_identity:
            raise JsonInputError("selected path changed while opening")
        fd_marker = _change_marker(fd_before)
        evidence = validate_gguf_fd(descriptor)
        fd_after = _fstat(descriptor)
        if _change_marker(fd_after) != fd_marker:
            raise JsonInputError("selected file changed during observation")
        path_after = _lstat(selected)
        if _stable_identity(path_after) != path_identity:
            raise JsonInputError("selected path changed during observation")
        if _change_marker(path_after) != path_marker:
            raise JsonInputError("selected file changed during observation")
        if _stable_identity(fd_after) != _stable_identity(path_after):
            raise JsonInputError("selected path changed during observation")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return _report(evidence, load_bundled())


def observe(path: str | os.PathLike[str]) -> dict[str, object]:
    """Short alias for callers of the private prototype."""

    return observe_file(path)


def _emit_report(report: dict[str, object]) -> None:
    try:
        raw = canonical_bytes(report)
    except (TypeError, ValueError, JsonInputError) as error:
        raise JsonInputError("report encoding failed") from error
    if len(raw) > MAX_OUTPUT_BYTES:
        raise JsonInputError("report exceeds the fixed output limit")
    try:
        sys.stdout.write(raw.decode("ascii"))
    except (UnicodeError, OSError) as error:
        raise JsonInputError("report output failed") from error


def _emit_error() -> None:
    message = ERROR_TEXT
    if len(message.encode("ascii")) > MAX_ERROR_BYTES:
        message = "file evidence error\n"
    try:
        sys.stderr.write(message)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    """Run the one-file observer; all failures are generic ``rc=2`` errors."""

    arguments = sys.argv[1:] if argv is None else argv
    if not isinstance(arguments, list) or len(arguments) != 1:
        _emit_error()
        return 2
    try:
        report = observe_file(arguments[0])
        _emit_report(report)
    except (OSError, TypeError, ValueError, OverflowError):
        # The command boundary intentionally reveals neither parser details nor
        # selected-path data.  KeyboardInterrupt/SystemExit remain outside this
        # ordinary failure path.
        _emit_error()
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by the module entry point
    raise SystemExit(main())
