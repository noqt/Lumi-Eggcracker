"""Exercise the privileged installer boundary on a disposable Ubuntu host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

INSTALLED = Path("/usr/local/lib/lumi-eggcracker/lumi-eggcracker.pyz")
POLICY = Path("/etc/lumi-eggcracker/policy.json")
TARGETS = (
    Path("/usr/local/lib/lumi-eggcracker"),
    Path("/usr/local/bin/eggcracker"),
    Path("/etc/lumi-eggcracker"),
    Path("/etc/systemd/system/lumi-eggcracker.service"),
    Path("/etc/systemd/system/lumi-eggcracker-watchdog.service"),
    Path("/var/lib/lumi-eggcracker"),
    Path("/run/lumi-eggcracker"),
    Path("/run/lumi-eggcracker-watchdog"),
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def invoke(
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
    timeout: float = 180,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=timeout,
    )


def require_success(command: list[str], *, timeout: float = 180) -> str:
    result = invoke(command, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "command failed")
    return result.stdout.strip()


def rejected(
    case: str,
    command: list[str],
    *,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = invoke(command, environment=environment)
    if result.returncode == 0:
        raise RuntimeError(f"{case} was accepted")
    return {
        "case": case,
        "exit_code": result.returncode,
        "result": "PASS",
        "stderr": result.stderr.strip()[-500:],
    }


class InstallerCampaign:
    def __init__(self, release: Path, operator: str, output: Path) -> None:
        self.release = release.resolve()
        self.operator = operator
        self.output = output
        self.manifest = json.loads(
            (self.release / "release-manifest.json").read_text(encoding="utf-8")
        )
        version = self.manifest.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise RuntimeError("release fixture version is invalid")
        self.artifact = self.release / f"lumi-eggcracker-{version}.pyz"
        self.installer = self.release / "scripts" / "install.py"
        self.uninstaller = self.release / "scripts" / "uninstall.py"
        self.verify_uninstalled = self.release / "scripts" / "verify_uninstalled.py"
        self.verifier = self.release / "scripts" / "verify_release.py"
        self.source = self.release / f"lumi-eggcracker-{version}-source.zip"
        self.bundle = self.release.parent / f"lumi-eggcracker-{version}-linux.zip"
        self.expected = digest(self.artifact)
        if (
            self.expected != self.manifest.get("sha256")
            or self.manifest.get("source_commit") is None
            or any(path.is_symlink() or not path.is_file() for path in (
                self.artifact,
                self.installer,
                self.uninstaller,
                self.verify_uninstalled,
                self.verifier,
                self.source,
                self.bundle,
            ))
        ):
            raise RuntimeError("release fixture identity is invalid")
        token = secrets.token_hex(8)
        self.root = Path(f"/opt/lumi-installer-p0-{token}")
        self.root.mkdir(mode=0o700)
        self.results: list[dict[str, Any]] = []
        self.canary = subprocess.Popen(
            ["/usr/sbin/runuser", "-u", operator, "--", "/bin/sleep", "900"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    @property
    def install_command(self) -> list[str]:
        return [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(self.installer),
            "--artifact",
            str(self.artifact),
            "--expected-sha256",
            self.expected,
            "--operator",
            self.operator,
        ]

    def assert_canary(self) -> None:
        if self.canary.poll() is not None:
            raise RuntimeError("installer campaign killed its unrelated canary")

    def assert_exact_install(self, expected: str | None = None) -> None:
        wanted = expected or self.expected
        if digest(INSTALLED) != wanted:
            raise RuntimeError("installed artifact identity is incorrect")
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        if policy.get("source_commit") != self.manifest["source_commit"]:
            raise RuntimeError("installed source identity is incorrect")
        value = json.loads(require_success(["/usr/local/bin/eggcracker", "doctor"]))
        if value.get("result") != "PASS":
            raise RuntimeError("installed product health is not PASS")

    def exact_install(self) -> None:
        require_success(self.install_command)
        self.assert_exact_install()

    def clean_uninstall(self) -> None:
        require_success(["/usr/bin/python3", "-I", "-S", str(self.uninstaller)])
        require_success(
            ["/usr/bin/python3", "-I", "-S", str(self.verify_uninstalled)]
        )

    def copy_release_pair(self, name: str) -> tuple[Path, Path]:
        root = self.root / name
        root.mkdir(mode=0o700)
        artifact = root / self.artifact.name
        manifest = root / "release-manifest.json"
        shutil.copyfile(self.artifact, artifact)
        shutil.copyfile(self.release / "release-manifest.json", manifest)
        return artifact, manifest

    def command_for(self, artifact: Path, expected: str) -> list[str]:
        return [
            "/usr/bin/python3",
            "-I",
            "-S",
            str(self.installer),
            "--artifact",
            str(artifact),
            "--expected-sha256",
            expected,
            "--operator",
            self.operator,
        ]

    def installed_input_attacks(self) -> None:
        baseline = digest(INSTALLED)
        self.results.append(rejected("pre-existing-install", self.install_command))
        self.results.append(
            rejected(
                "wrong-expected-digest",
                self.command_for(self.artifact, "0" * 64),
            )
        )

        hooks = self.root / "python-hooks"
        hooks.mkdir(mode=0o700)
        marker = hooks / "IMPORTED"
        for name in ("argparse.py", "sitecustomize.py"):
            (hooks / name).write_text(
                f"open({str(marker)!r},'w').write({name!r})\n"
                "raise RuntimeError('hostile import hook')\n",
                encoding="utf-8",
            )
        environment = dict(os.environ)
        environment.update(
            {
                "PYTHONPATH": str(hooks),
                "PYTHONSTARTUP": str(hooks / "sitecustomize.py"),
                "PYTHONUSERBASE": str(hooks),
            }
        )
        self.results.append(
            rejected(
                "isolated-python-import-hooks",
                self.install_command,
                environment=environment,
            )
        )
        if marker.exists():
            raise RuntimeError("privileged installer imported hostile Python code")

        link = self.root / "install-link.py"
        link.symlink_to(self.installer)
        linked_command = list(self.install_command)
        linked_command[3] = str(link)
        self.results.append(rejected("symlinked-installer", linked_command))

        symlink_root = self.root / "artifact-symlink"
        symlink_root.mkdir(mode=0o700)
        linked_artifact = symlink_root / self.artifact.name
        linked_artifact.symlink_to(self.artifact)
        shutil.copyfile(
            self.release / "release-manifest.json",
            symlink_root / "release-manifest.json",
        )
        self.results.append(
            rejected(
                "symlinked-artifact",
                self.command_for(linked_artifact, self.expected),
            )
        )

        for case, key, value in (
            ("manifest-source-drift", "source_commit", "0" * 40),
            ("manifest-version-downgrade", "version", "0.4.0"),
            ("manifest-artifact-digest-drift", "sha256", "f" * 64),
        ):
            artifact, manifest = self.copy_release_pair(case)
            changed = dict(self.manifest)
            changed[key] = value
            manifest.write_text(
                json.dumps(changed, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.results.append(
                rejected(case, self.command_for(artifact, self.expected))
            )

        artifact, manifest = self.copy_release_pair("manifest-symlink")
        manifest.unlink()
        manifest.symlink_to(self.release / "release-manifest.json")
        self.results.append(
            rejected(
                "symlinked-release-manifest",
                self.command_for(artifact, self.expected),
            )
        )

        malicious_bundle = self.root / "traversal-linux.zip"
        shutil.copyfile(self.bundle, malicious_bundle)
        with zipfile.ZipFile(malicious_bundle, "a") as archive:
            archive.writestr("../P0-ESCAPE", b"blocked")
        self.results.append(
            rejected(
                "release-bundle-traversal-entry",
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    str(self.verifier),
                    "--artifact",
                    str(self.artifact),
                    "--source-archive",
                    str(self.source),
                    "--release-bundle",
                    str(malicious_bundle),
                ],
            )
        )
        if digest(INSTALLED) != baseline:
            raise RuntimeError("rejected installer input changed the active artifact")
        self.assert_exact_install()

    def partial_state_rejection(self) -> None:
        partial = Path("/etc/lumi-eggcracker")
        partial.mkdir(mode=0o700)
        try:
            self.results.append(
                rejected("partial-prior-installation", self.install_command)
            )
        finally:
            partial.rmdir()
        if any(path.exists() or path.is_symlink() for path in TARGETS):
            raise RuntimeError("partial-state rejection left installation residue")

    def descriptor_swap(self) -> None:
        root = self.root / "descriptor-swap"
        root.mkdir(mode=0o700)
        artifact = root / self.artifact.name
        hostile = root / "hostile.pyz"
        padding = root / "padding.bin"
        shutil.copyfile(self.artifact, artifact)
        with padding.open("wb") as handle:
            for _ in range(96):
                handle.write(os.urandom(1024 * 1024))
        with zipfile.ZipFile(artifact, "a", compression=zipfile.ZIP_STORED) as archive:
            archive.write(padding, "p0/descriptor-window.bin")
        padding.unlink()
        shutil.copyfile(artifact, hostile)
        with zipfile.ZipFile(hostile, "a") as archive:
            archive.writestr("p0/hostile-pathname", b"must-not-install")
        expected = digest(artifact)
        hostile_digest = digest(hostile)
        if expected == hostile_digest:
            raise RuntimeError("descriptor-swap fixtures are not distinct")
        manifest = dict(self.manifest)
        manifest["artifact"] = artifact.name
        manifest["sha256"] = expected
        (root / "release-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        command = self.command_for(artifact, expected)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stopped = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline and process.poll() is None:
                for descriptor in Path(f"/proc/{process.pid}/fd").glob("*"):
                    try:
                        target = os.readlink(descriptor)
                    except OSError:
                        continue
                    if target == str(artifact):
                        os.kill(process.pid, signal.SIGSTOP)
                        stopped = True
                        break
                if stopped:
                    break
                time.sleep(0.001)
            if not stopped or any(path.exists() or path.is_symlink() for path in TARGETS):
                raise RuntimeError("installer descriptor race window was not captured")
            os.replace(hostile, artifact)
            os.kill(process.pid, signal.SIGCONT)
            stdout, stderr = process.communicate(timeout=240)
        finally:
            if process.poll() is None:
                if stopped:
                    os.kill(process.pid, signal.SIGCONT)
                process.kill()
                process.wait(timeout=10)
        if process.returncode:
            raise RuntimeError(stderr.strip() or stdout.strip() or "descriptor install failed")
        if digest(artifact) != hostile_digest or digest(INSTALLED) != expected:
            raise RuntimeError("installer reopened the swapped artifact pathname")
        self.assert_exact_install(expected)
        self.results.append(
            {
                "case": "held-descriptor-pathname-swap",
                "installed_sha256": expected,
                "pathname_sha256": hostile_digest,
                "result": "PASS",
            }
        )

    def run(self) -> dict[str, Any]:
        self.assert_exact_install()
        self.installed_input_attacks()
        self.clean_uninstall()
        self.partial_state_rejection()
        self.descriptor_swap()
        self.clean_uninstall()
        self.exact_install()
        self.assert_canary()
        return {
            "cases": self.results,
            "exact_artifact_sha256": self.expected,
            "result": "PASS",
            "schema_version": "lumi-eggcracker.installer-p0.v1",
            "source_commit": self.manifest["source_commit"],
            "version": self.manifest["version"],
        }

    def close(self) -> None:
        if self.canary.poll() is None:
            try:
                os.killpg(self.canary.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            self.canary.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.canary.kill()
        if self.root.exists() and not self.root.is_symlink():
            shutil.rmtree(self.root)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("installer P0 campaign must run as root")
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if (
        args.output.exists()
        or args.output.is_symlink()
        or not args.output.parent.is_dir()
        or pwd.getpwnam(args.operator).pw_uid == 0
    ):
        raise SystemExit("installer campaign arguments are invalid")
    campaign = InstallerCampaign(args.release_root, args.operator, args.output)
    try:
        value = campaign.run()
        args.output.write_text(
            json.dumps(value, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"output": str(args.output), "result": "PASS"}, sort_keys=True))
        return 0
    except BaseException as error:
        if not args.output.exists():
            args.output.write_text(
                json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "result": "FAIL",
                        "schema_version": "lumi-eggcracker.installer-p0.v1",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        raise
    finally:
        campaign.close()


if __name__ == "__main__":
    raise SystemExit(main())
