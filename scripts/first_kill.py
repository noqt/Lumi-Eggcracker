"""Run the public first-kill demonstration from a clean Linux host.

This is deliberately a small campaign wrapper around the qualified release
installer and real-AI smoke scripts. It does not weaken installer checks,
overwrite an existing installation, or send telemetry anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
    import pwd
except ImportError:  # pragma: no cover - first-kill is a native Linux command
    pwd = None  # type: ignore[assignment]


REPOSITORY = "noqt/Lumi-Eggcracker"
DEFAULT_TAG = "v1.0.0"
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
MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ZIP_COMMENT_BYTES = 65_535
DETECTIONS = Path("/var/lib/lumi-eggcracker/detections")
DEFAULT_AI_SMOKE_WORKSPACE = Path("/opt/lumi-eggcracker-ai-smoke")
QUALIFIED_LLAMA_SHA256 = "ef0b86d353638b74519079b5937b9d62b4d4c6c6cdbf68812d7898437ecc4fb5"


class FirstKillError(RuntimeError):
    """A user-actionable campaign failure."""


def say(message: str) -> None:
    print(f"[eggcracker] {message}", flush=True)


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
        path = PurePosixPath(name)
        parts = path.parts
        normalized = path.as_posix().rstrip("/")
        if (
            not name
            or "\x00" in name
            or "\\" in name
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
        raise FirstKillError("first-kill requires the POSIX passwd database")
    value = explicit or os.environ.get("SUDO_USER")
    if not value or value == "root":
        raise FirstKillError("run through sudo and pass --operator <your-login>")
    try:
        account = pwd.getpwnam(value)
    except KeyError as error:
        raise FirstKillError("operator account does not exist") from error
    if account.pw_uid == 0:
        raise FirstKillError("the operator must be a non-root login")
    return value


def compatibility(operator: str) -> None:
    if os.geteuid() != 0:
        raise FirstKillError("run as root, for example: sudo python3 scripts/first_kill.py ...")
    if platform.system() != "Linux":
        raise FirstKillError("first-kill requires native Linux; Windows and macOS are unsupported")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if not controllers.is_file() or "pids" not in controllers.read_text(encoding="ascii").split():
        raise FirstKillError("unified cgroup v2 with the pids controller is required")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise FirstKillError("this Python/Linux host lacks the required pidfd primitives")
    for binary in ("/usr/bin/python3", "/usr/bin/systemctl", "/usr/bin/systemd-run", "/usr/sbin/runuser", "/usr/bin/gpg", "/usr/bin/git"):
        if not Path(binary).is_file():
            raise FirstKillError(f"required host command is missing: {binary}")
    required_tool_groups = (
        (("cmake",), "CMake"),
        (("c++", "g++", "clang++"), "a C++ compiler (c++, g++ or clang++)"),
        (("make", "ninja"), "a CMake build backend (Make or Ninja)"),
    )
    for commands, description in required_tool_groups:
        if not any(shutil.which(command) for command in commands):
            raise FirstKillError(f"required build tooling is missing: {description}")
    for target in INSTALL_TARGETS:
        if target.exists() or target.is_symlink():
            raise FirstKillError(f"refusing to overwrite an existing installation target: {target}")
    try:
        if pwd is None:
            raise FirstKillError("first-kill requires the POSIX passwd database")
        pwd.getpwnam(operator)
    except KeyError as error:
        raise FirstKillError("operator account does not exist") from error


def repository_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    try:
        probe = run(
            ["/usr/bin/git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            check=False,
        )
    except FirstKillError as error:
        raise FirstKillError("could not inspect the local Git checkout") from error
    if probe.returncode or probe.stdout.strip() != "true":
        raise FirstKillError("first-kill must be run from a Git checkout containing the signed tag")
    return root


def local_release_identity(root: Path, tag: str) -> str:
    """Verify the qualified local annotated tag without network or GPG state."""
    if tag != DEFAULT_TAG:
        raise FirstKillError(f"preflight supports only the qualified local tag {DEFAULT_TAG}")
    reference = f"refs/tags/{tag}"
    try:
        kind = run(["/usr/bin/git", "-C", str(root), "cat-file", "-t", reference], check=False)
        resolved = run(
            ["/usr/bin/git", "-C", str(root), "rev-parse", f"{reference}^{{}}"],
            check=False,
        )
    except FirstKillError as error:
        raise FirstKillError("could not inspect the qualified local release tag") from error
    if kind.returncode or kind.stdout.strip() != "tag":
        raise FirstKillError(f"the local {tag} reference is missing or is not an annotated tag")
    commit = resolved.stdout.strip()
    if resolved.returncode or len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit.lower()
    ):
        raise FirstKillError(f"the local {tag} tag does not resolve to a commit")
    return commit


def run_preflight(operator_value: str | None, tag: str) -> int:
    """Run read-only host and local-release availability checks."""
    operator = operator_name(operator_value)
    compatibility(operator)
    commit = local_release_identity(repository_root(), tag)
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
        raise FirstKillError("tag must look like v1.0.0")
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
    release_root: Path,
    workspace: Path,
    workload_user: str,
    assets_workspace: Path,
    demo_delay_seconds: float = 0,
) -> dict[str, Any]:
    assets_script = release_root / "scripts" / "prepare_ai_smoke.py"
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
    parser.add_argument("--tag", default=DEFAULT_TAG, help=f"signed release tag (default: {DEFAULT_TAG})")
    parser.add_argument("--workspace", type=Path, help="temporary workspace; default is a new /tmp directory")
    parser.add_argument(
        "--ai-workspace",
        type=Path,
        help="root-owned workspace for the pinned real-AI demo (default: /opt/lumi-eggcracker-ai-smoke)",
    )
    parser.add_argument(
        "--demo-delay-seconds",
        type=float,
        default=0,
        help="keep the real workload visibly running before model execution (recording aid; max 60s)",
    )
    parser.add_argument(
        "--accept-third-party-downloads",
        action="store_true",
        help="accept downloading the pinned llama.cpp source and Qwen model for the demonstration",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="check host, tools and local release identity without downloads or system changes",
    )
    parser.add_argument("--keep", action="store_true", help="leave the installation and smoke assets in place")
    parser.add_argument("--remove", action="store_true", help="remove the installation without prompting")
    args = parser.parse_args(argv)
    if args.keep and args.remove:
        parser.error("--keep and --remove are mutually exclusive")
    if not 0 <= args.demo_delay_seconds <= 60:
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
        if args.demo_delay_seconds:
            incompatible.append("--demo-delay-seconds")
        if args.accept_third_party_downloads:
            incompatible.append("--accept-third-party-downloads")
        if incompatible:
            parser.error("--preflight-only cannot be combined with " + ", ".join(incompatible))
        try:
            return run_preflight(args.operator, args.tag)
        except FirstKillError as error:
            print(f"eggcracker preflight: {error}", file=sys.stderr)
            return 2
    if not args.accept_third_party_downloads:
        parser.error("--accept-third-party-downloads is required because the demo downloads a real model")

    workspace: Path | None = None
    ai_workspace: Path | None = None
    ai_workspace_preexisting = False
    installed = False
    release_root: Path | None = None
    try:
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
        say(f"downloading and checking signed {args.tag} release assets")
        bundle, key, sums, signature = release_files(args.tag, workspace)
        commit = verify_tag(root, args.tag, key)
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
        say(f"signature and release identity verified: {args.tag} -> {commit}")
        say("installing the root-controlled supervisor")
        install_release(release_root, operator, release)
        installed = True
        workload_user = installed_workload_user()
        say("preparing the pinned real local-AI smoke assets (explicit third-party download)")
        say("launching an unapproved model and waiting for the complete-tree kill")
        receipt = run_real_smoke(
            release_root,
            workspace,
            workload_user,
            ai_workspace,
            args.demo_delay_seconds,
        )
        print(json.dumps(receipt_summary(receipt), indent=2, sort_keys=True))
        say("first-kill demonstration passed: the real workload was terminated and its canary survived")
        should_remove = args.remove or (not args.keep and cleanup_choice())
        if should_remove:
            say("removing Eggcracker and temporary smoke assets")
            remove_installation(
                release_root,
                workspace,
                None if ai_workspace_preexisting else ai_workspace,
            )
            installed = False
            workspace = None
            ai_workspace = None
            say("clean removal passed")
        else:
            say(f"left installed by request; release workspace: {workspace}; AI assets: {ai_workspace}")
        return 0
    except (FirstKillError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            say("cancelled")
        else:
            print(f"eggcracker first-kill: {error}", file=sys.stderr)
        if installed and release_root is not None and workspace is not None and not args.keep:
            say("installation remains in place; rerun with --remove after reviewing the failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
