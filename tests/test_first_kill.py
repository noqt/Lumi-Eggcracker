from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
TAG_COMMIT = "a" * 40
EXPECTED_FIRST_KILL_COMMANDS = frozenset(
    {
        "/bin/sleep",
        "/usr/bin/env",
        "/usr/bin/git",
        "/usr/bin/gpg",
        "/usr/bin/journalctl",
        "/usr/bin/nsenter",
        "/usr/bin/python3",
        "/usr/bin/systemctl",
        "/usr/bin/systemd-run",
        "/usr/sbin/groupdel",
        "/usr/sbin/ip",
        "/usr/sbin/nft",
        "/usr/sbin/runuser",
        "/usr/sbin/useradd",
        "/usr/sbin/userdel",
    }
)
SPEC = importlib.util.spec_from_file_location("first_kill", ROOT / "scripts" / "first_kill.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load first-kill script")
first_kill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_kill)


def success_receipt(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "result": "TERMINATED",
        "detector": {"profile": "content.gguf-llama", "path": "PRIVATE"},
        "trigger": {"kind": "UNAPPROVED_AI_MATCH", "pid": 424242},
        "capture": {"captured_processes": 1, "path": "PRIVATE"},
        "containment": {
            "primitive": "pidfd-stop+cgroup.kill",
            "root_populated": 0,
            "surviving_pids": [],
            "trigger_to_empty_ms": 42.5,
        },
    }
    value.update(overrides)
    return value


@contextlib.contextmanager
def publication_mocks(
    *,
    destination_exists: bool = False,
    link_race: bool = False,
    parent_race: bool = False,
    write_side_effect=None,
    fsync_side_effect=None,
):
    """Exercise publish_success_result through mocked POSIX descriptor calls."""
    destination = Path(os.path.abspath(os.path.join(os.sep, "synthetic-result", "result.json")))
    parent_fd = 101
    temporary_fd = 102
    parent_info = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o700,
        st_uid=0,
        st_dev=11,
        st_ino=22,
        st_file_attributes=0,
    )
    temporary_info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=0,
        st_dev=11,
        st_ino=33,
        st_file_attributes=0,
    )
    existing_info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_uid=0,
        st_dev=11,
        st_ino=44,
        st_file_attributes=0,
    )
    temporary_name: list[str | None] = [None]
    temporary_stats = 0
    destination_checked = False
    destination_unlinked = False
    stat_calls: list[tuple[object, object]] = []

    def fake_open(name, _flags, _mode=0o777, **kwargs):
        if kwargs.get("dir_fd") == parent_fd:
            temporary_name[0] = name
            return temporary_fd
        return parent_fd

    def fake_stat(name, **kwargs):
        nonlocal destination_checked, temporary_stats
        stat_calls.append((name, kwargs.get("dir_fd")))
        if name == destination.name:
            if destination_unlinked:
                raise FileNotFoundError(name)
            if destination_exists:
                return existing_info
            if not destination_checked:
                destination_checked = True
                raise FileNotFoundError(name)
            return temporary_info
        temporary_stats += 1
        if temporary_stats <= 2:
            return temporary_info
        raise FileNotFoundError(name)

    def fake_link(*_args, **_kwargs):
        if link_race:
            raise FileExistsError(destination.name)

    def fake_unlink(name, **_kwargs):
        nonlocal destination_unlinked
        if name == destination.name:
            destination_unlinked = True

    if write_side_effect is None:
        write_side_effect = lambda _fd, view: len(view)
    write = mock.Mock(side_effect=write_side_effect)
    open_call = mock.Mock(side_effect=fake_open)
    stat_call = mock.Mock(side_effect=fake_stat)
    link = mock.Mock(side_effect=fake_link)
    unlink = mock.Mock(side_effect=fake_unlink)
    close = mock.Mock()
    fsync = mock.Mock(side_effect=fsync_side_effect)

    class SupportsAll:
        def __contains__(self, _value):
            return True

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(first_kill, "validate_result_output", return_value=destination))
        stack.enter_context(mock.patch.object(first_kill, "_result_output_effective_uid", return_value=0))
        stack.enter_context(mock.patch.object(first_kill, "_result_output_parent_matches", return_value=not parent_race))
        stack.enter_context(mock.patch.object(first_kill, "_result_output_parent_path_matches", return_value=True))
        stack.enter_context(mock.patch.object(first_kill.os, "O_DIRECTORY", 0x10000, create=True))
        stack.enter_context(mock.patch.object(first_kill.os, "O_NOFOLLOW", 0x20000, create=True))
        stack.enter_context(mock.patch.object(first_kill.os, "supports_dir_fd", SupportsAll(), create=True))
        stack.enter_context(mock.patch.object(first_kill.os, "lstat", return_value=parent_info))
        stack.enter_context(mock.patch.object(first_kill.os, "open", open_call))
        stack.enter_context(mock.patch.object(first_kill.os, "fchmod", mock.Mock(), create=True))
        stack.enter_context(mock.patch.object(first_kill.os, "fstat", return_value=temporary_info))
        stack.enter_context(mock.patch.object(first_kill.os, "write", write))
        stack.enter_context(mock.patch.object(first_kill.os, "fsync", fsync))
        stack.enter_context(mock.patch.object(first_kill.os, "close", close))
        stack.enter_context(mock.patch.object(first_kill.os, "stat", stat_call))
        stack.enter_context(mock.patch.object(first_kill.os, "link", link))
        stack.enter_context(mock.patch.object(first_kill.os, "unlink", unlink))
        stack.enter_context(mock.patch.object(first_kill.secrets, "token_hex", return_value="fixed"))
        yield {
            "destination": destination,
            "fsync": fsync,
            "link": link,
            "open": open_call,
            "stat": stat_call,
            "stat_calls": stat_calls,
            "temporary_name": temporary_name,
            "unlink": unlink,
            "write": write,
        }


class FirstKillTests(unittest.TestCase):
    def assert_entrypoint_refuses_before_side_effects(
        self,
        expected_reason_code: str,
        passwd=None,
        group=None,
        platform_release: str = "6.8.0-generic",
        wsl_distro_name: str | None = None,
        total_memory_bytes: int | None = None,
        free_root_bytes: int | None = None,
    ) -> None:
        if passwd is None:
            passwd = mock.Mock()

            def clean_passwd_lookup(name: str):
                if name == first_kill.WORKLOAD_USER:
                    raise KeyError(name)
                return object()

            passwd.getpwnam.side_effect = clean_passwd_lookup
        if group is None:
            group = mock.Mock()
            group.getgrnam.side_effect = KeyError(first_kill.WORKLOAD_USER)
        operator_name = mock.Mock(return_value="tester")
        repository_root = mock.Mock()
        prepare_workspace = mock.Mock()
        release_files = mock.Mock()
        install_release = mock.Mock()
        run_real_smoke = mock.Mock()
        remove_installation = mock.Mock()
        make_temporary = mock.Mock()
        environment = {}
        if wsl_distro_name is not None:
            environment["WSL_DISTRO_NAME"] = wsl_distro_name
        errors = io.StringIO()
        memory = mock.Mock(
            return_value=(
                first_kill.MIN_TOTAL_MEMORY_BYTES
                if total_memory_bytes is None
                else total_memory_bytes
            )
        )
        disk = mock.Mock(
            return_value=(
                first_kill.MIN_FREE_ROOT_BYTES
                if free_root_bytes is None
                else free_root_bytes
            )
        )
        with (
            mock.patch.multiple(
                first_kill,
                operator_name=operator_name,
                pwd=passwd,
                grp=group,
                repository_root=repository_root,
                prepare_workspace=prepare_workspace,
                release_files=release_files,
                install_release=install_release,
                run_real_smoke=run_real_smoke,
                remove_installation=remove_installation,
                total_memory_bytes=memory,
                free_root_bytes=disk,
            ),
            mock.patch.multiple(
                first_kill.os,
                geteuid=mock.Mock(return_value=0),
                pidfd_open=mock.Mock(),
                access=mock.Mock(return_value=True),
                environ=environment,
                create=True,
            ),
            mock.patch.object(first_kill.signal, "pidfd_send_signal", create=True),
            mock.patch.multiple(
                first_kill.platform,
                system=mock.Mock(return_value="Linux"),
                release=mock.Mock(return_value=platform_release),
            ),
            mock.patch.multiple(
                first_kill.Path,
                read_text=mock.Mock(return_value="pids"),
                exists=mock.Mock(return_value=False),
                is_symlink=mock.Mock(return_value=False),
            ),
            mock.patch.object(first_kill.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(first_kill.tempfile, "mkdtemp", make_temporary),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(
                ["--operator", "tester", "--accept-third-party-downloads"]
            )

        self.assertEqual(2, result)
        summary = json.loads(errors.getvalue())
        self.assertEqual(first_kill.FULL_RUN_FAILURE_FIELDS, set(summary))
        self.assertEqual(first_kill.FULL_RUN_FAILURE_SCHEMA, summary["schema"])
        self.assertEqual(first_kill.FULL_RUN_FAILURE_VERSION, summary["version"])
        self.assertEqual("FULL_RUN_FAILED", summary["result"])
        self.assertEqual(first_kill.FULL_RUN_STAGE_PRE_INSTALL, summary["stage"])
        self.assertEqual(expected_reason_code, summary["reason_code"])
        self.assertEqual(
            first_kill.FULL_RUN_INSTALL_STATE_NOT_INSTALLED,
            summary["installation_state"],
        )
        self.assertEqual(first_kill.FULL_RUN_REMOVAL_NOT_REQUIRED, summary["removal_guidance"])
        self.assertEqual(first_kill.FULL_RUN_NEXT_ACTION, summary["next_action"])
        for forbidden in (
            repository_root,
            prepare_workspace,
            release_files,
            install_release,
            run_real_smoke,
            remove_installation,
            make_temporary,
        ):
            forbidden.assert_not_called()

    def test_minimum_memory_is_seven_gibibytes(self) -> None:
        self.assertEqual(7 * 1024 * 1024 * 1024, first_kill.MIN_TOTAL_MEMORY_BYTES)

    def test_minimum_free_root_disk_is_eight_gibibytes(self) -> None:
        self.assertEqual(8 * 1024 * 1024 * 1024, first_kill.MIN_FREE_ROOT_BYTES)

    def test_low_memory_refusal_precedes_entrypoint_side_effects(self) -> None:
        with mock.patch.object(
            first_kill.Path, "is_file", autospec=True, return_value=True
        ):
            self.assert_entrypoint_refuses_before_side_effects(
                "PRE_INSTALL_FAILURE",
                total_memory_bytes=first_kill.MIN_TOTAL_MEMORY_BYTES - 1,
            )

    def test_low_disk_refusal_precedes_entrypoint_side_effects(self) -> None:
        with mock.patch.object(
            first_kill.Path, "is_file", autospec=True, return_value=True
        ):
            self.assert_entrypoint_refuses_before_side_effects(
                "PRE_INSTALL_FAILURE",
                free_root_bytes=first_kill.MIN_FREE_ROOT_BYTES - 1,
            )

    def test_wsl_refusal_precedes_entrypoint_side_effects(self) -> None:
        with mock.patch.object(
            first_kill.Path, "is_file", autospec=True, return_value=True
        ):
            self.assert_entrypoint_refuses_before_side_effects(
                "PRE_INSTALL_FAILURE",
                platform_release="6.18.33.1-microsoft-standard-WSL2",
            )

    def test_wsl_environment_refusal_precedes_entrypoint_side_effects(self) -> None:
        with mock.patch.object(
            first_kill.Path, "is_file", autospec=True, return_value=True
        ):
            self.assert_entrypoint_refuses_before_side_effects(
                "PRE_INSTALL_FAILURE",
                platform_release="6.8.0-custom",
                wsl_distro_name="test-wsl",
            )

    def test_default_release_identity_is_the_1_0_candidate(self) -> None:
        self.assertEqual("v1.0.10", first_kill.DEFAULT_TAG)

    def test_third_party_plan_is_exact_and_deterministic(self) -> None:
        expected = {
            "schema_version": "lumi-eggcracker.third-party-download-plan.v1",
            "plan_version": 1,
            "result": "THIRD_PARTY_DOWNLOAD_PLAN",
            "mode": "offline-source-only",
            "llama": {
                "repository": "https://github.com/ggml-org/llama.cpp.git",
                "tag": "b10240",
                "commit": "0b14b87d7c20cb753b94b96854dd7b45306fc696",
                "license": "MIT",
                "license_status": "DECLARED_METADATA_NOT_VERIFIED",
                "license_verified": False,
                "legal_clearance": False,
            },
            "model": {
                "url": "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/9217f5db79a29953eb74d5343926648285ec7e67/qwen2.5-0.5b-instruct-q4_k_m.gguf",
                "revision": "9217f5db79a29953eb74d5343926648285ec7e67",
                "sha256": "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
                "license": "Apache-2.0",
                "license_status": "DECLARED_METADATA_NOT_VERIFIED",
                "license_verified": False,
                "legal_clearance": False,
            },
            "model_download_max_bytes": 600 * 1024 * 1024,
            "minimum_total_memory_bytes": 7 * 1024 * 1024 * 1024,
            "minimum_free_root_bytes": 8 * 1024 * 1024 * 1024,
            "transfer_limits": {
                "llama_cpp_clone": {
                    "status": "UNKNOWN",
                    "bound": "UNCAPPED_BY_THIS_TOOL",
                    "max_bytes": None,
                    "bounded_by_this_tool": False,
                },
                "model_download": {
                    "max_bytes": 600 * 1024 * 1024,
                    "bounded_by_this_tool": True,
                    "is_total_transfer_bound": False,
                },
                "source_clone_build_package_release": {
                    "status": "UNCAPPED_BY_THIS_TOOL",
                    "max_bytes": None,
                    "bounded_by_this_tool": False,
                },
            },
        }
        first = first_kill.build_third_party_download_plan()
        second = first_kill.build_third_party_download_plan()
        self.assertEqual(expected, first)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_third_party_plan_rejects_malformed_pinned_projection_without_reflection(self) -> None:
        canary = "https://unsafe.example/private-path?argv=secret"
        output = io.StringIO()
        errors = io.StringIO()
        with (
            mock.patch.object(first_kill, "MODEL_URL", canary),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--third-party-download-plan"])
        self.assertEqual("third-party download plan unavailable: pinned inputs are invalid", str(raised.exception))
        self.assertEqual("", output.getvalue())
        self.assertNotIn(canary, errors.getvalue())

    def test_third_party_plan_is_zero_effect_before_host_or_install_steps(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(first_kill, "operator_name") as operator,
            mock.patch.object(first_kill, "compatibility") as compatibility,
            mock.patch.object(first_kill, "repository_root") as repository_root,
            mock.patch.object(first_kill, "local_release_identity") as identity,
            mock.patch.object(first_kill, "prepare_workspace") as prepare_workspace,
            mock.patch.object(first_kill, "release_files") as release_files,
            mock.patch.object(first_kill, "download") as download,
            mock.patch.object(first_kill, "run") as run,
            mock.patch.object(first_kill, "install_release") as install_release,
            mock.patch.object(first_kill, "run_real_smoke") as run_real_smoke,
            mock.patch.object(first_kill, "remove_installation") as remove_installation,
            mock.patch.object(first_kill.tempfile, "mkdtemp") as make_temporary,
            mock.patch.object(first_kill.urllib.request, "urlopen") as urlopen,
            mock.patch.object(first_kill, "total_memory_bytes") as memory,
            mock.patch.object(first_kill, "free_root_bytes") as disk,
            contextlib.redirect_stdout(output),
        ):
            result = first_kill.main(["--third-party-download-plan"])
        self.assertEqual(0, result)
        payload = output.getvalue()
        self.assertEqual(first_kill.build_third_party_download_plan(), json.loads(payload))
        for forbidden_field in ('"path"', '"argv"', '"env"', '"platform"', '"host"'):
            self.assertNotIn(forbidden_field, payload)
        for forbidden in (
            operator,
            compatibility,
            repository_root,
            identity,
            prepare_workspace,
            release_files,
            download,
            run,
            install_release,
            run_real_smoke,
            remove_installation,
            make_temporary,
            urlopen,
            memory,
            disk,
        ):
            forbidden.assert_not_called()

    def test_third_party_plan_rejects_preflight_flag_before_effects(self) -> None:
        errors = io.StringIO()
        with (
            mock.patch.object(first_kill, "operator_name") as operator,
            contextlib.redirect_stderr(errors),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--third-party-download-plan", "--preflight-only"])
        self.assertEqual(2, raised.exception.code)
        self.assertIn("--third-party-download-plan cannot be combined", errors.getvalue())
        operator.assert_not_called()

    def test_preflight_requires_every_fixed_installer_command(self) -> None:
        self.assertEqual(
            EXPECTED_FIRST_KILL_COMMANDS,
            frozenset(first_kill.REQUIRED_HOST_COMMANDS),
        )
        for missing in EXPECTED_FIRST_KILL_COMMANDS:
            with self.subTest(missing=missing):

                def present(path: Path, expected: str = missing) -> bool:
                    return path.as_posix() != expected

                with (
                    mock.patch.object(
                        first_kill.Path, "is_file", autospec=True, side_effect=present
                    ),
                    mock.patch.object(first_kill.os, "access", return_value=True),
                    self.assertRaisesRegex(
                        first_kill.FirstKillError, missing.replace("/", r"\/")
                    ),
                ):
                    first_kill.require_host_commands()

    def test_each_missing_command_refusal_precedes_entrypoint_side_effects(self) -> None:
        for missing in EXPECTED_FIRST_KILL_COMMANDS:
            with self.subTest(missing=missing):

                def present(path: Path, expected: str = missing) -> bool:
                    return path.as_posix() != expected

                with mock.patch.object(
                    first_kill.Path, "is_file", autospec=True, side_effect=present
                ):
                    self.assert_entrypoint_refuses_before_side_effects(
                        "PRE_INSTALL_FAILURE"
                    )

    def test_preflight_rejects_residual_workload_identity(self) -> None:
        passwd = mock.Mock()
        group = mock.Mock()
        passwd.getpwnam.return_value = object()

        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.object(first_kill, "grp", group),
            self.assertRaisesRegex(first_kill.FirstKillError, "workload account"),
        ):
            first_kill.require_clean_workload_identity()

        passwd.getpwnam.side_effect = KeyError(first_kill.WORKLOAD_USER)
        group.getgrnam.return_value = object()
        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.object(first_kill, "grp", group),
            self.assertRaisesRegex(first_kill.FirstKillError, "workload group"),
        ):
            first_kill.require_clean_workload_identity()

    def test_each_residual_identity_refusal_precedes_entrypoint_side_effects(self) -> None:
        for residual in ("account", "group"):
            with self.subTest(residual=residual):
                passwd = mock.Mock()
                group = mock.Mock()
                if residual == "account":
                    passwd.getpwnam.return_value = object()
                else:
                    def passwd_lookup(name: str):
                        if name == first_kill.WORKLOAD_USER:
                            raise KeyError(name)
                        return object()

                    passwd.getpwnam.side_effect = passwd_lookup
                    group.getgrnam.return_value = object()

                with (
                    mock.patch.object(
                        first_kill.Path, "is_file", autospec=True, return_value=True
                    ),
                ):
                    self.assert_entrypoint_refuses_before_side_effects(
                        "PRE_INSTALL_FAILURE",
                        passwd,
                        group,
                    )

    def test_preflight_exits_before_every_mutating_or_network_step(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester") as operator,
            mock.patch.object(first_kill, "compatibility") as compatibility,
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill,
                "local_release_identity",
                return_value=TAG_COMMIT,
            ),
            mock.patch.object(first_kill, "prepare_workspace") as prepare_workspace,
            mock.patch.object(first_kill, "release_files") as release_files,
            mock.patch.object(first_kill, "verify_tag") as verify_tag,
            mock.patch.object(
                first_kill, "verify_checksum_signature"
            ) as verify_checksum_signature,
            mock.patch.object(first_kill, "verify_bundle_checksum") as verify_bundle_checksum,
            mock.patch.object(first_kill, "install_release") as install_release,
            mock.patch.object(first_kill, "run_real_smoke") as run_real_smoke,
            mock.patch.object(first_kill.tempfile, "mkdtemp") as make_temporary,
            contextlib.redirect_stdout(output),
        ):
            result = first_kill.main(["--operator", "tester", "--preflight-only"])

        self.assertEqual(0, result)
        operator.assert_called_once_with("tester")
        compatibility.assert_called_once_with("tester")
        for forbidden in (
            prepare_workspace,
            release_files,
            verify_tag,
            verify_checksum_signature,
            verify_bundle_checksum,
            install_release,
            run_real_smoke,
            make_temporary,
        ):
            forbidden.assert_not_called()
        summary = json.loads(output.getvalue())
        self.assertEqual("PREFLIGHT_PASSED", summary["result"])
        self.assertEqual(first_kill.PREFLIGHT_SCHEMA, summary["schema"])
        self.assertTrue(summary["supported"])
        self.assertEqual(TAG_COMMIT, summary["tag_commit"])
        self.assertNotIn("qualified_commit", summary)
        self.assertFalse(summary["changes_made"])
        self.assertNotIn("/checkout", output.getvalue())

    def test_preflight_incompatibilities_emit_trusted_bounded_diagnostics(self) -> None:
        canary = "SECRET_PATH=/private/operator-name pid=424242 --danger"
        non_default_tag = "v9.9.9"
        blocked_fields = {
            "changes_made",
            "failed_check",
            "mode",
            "next_action",
            "reason_code",
            "result",
            "schema",
            "supported",
            "tag",
        }
        cases = (
            ("operator_database", "operator"),
            ("operator_required", "operator"),
            ("operator_missing", "operator"),
            ("operator_root", "operator"),
            ("host_root", "compatibility"),
            ("host_platform", "compatibility"),
            ("host_wsl", "compatibility"),
            ("host_memory", "compatibility"),
            ("host_memory_limit", "compatibility"),
            ("host_disk", "compatibility"),
            ("host_disk_limit", "compatibility"),
            ("host_cgroup", "compatibility"),
            ("host_pidfd", "compatibility"),
            ("host_command", "compatibility"),
            ("build_tool", "compatibility"),
            ("install_target", "compatibility"),
            ("workload_database", "compatibility"),
            ("workload_residue", "compatibility"),
            ("local_git", "repository"),
            ("tag_unsupported", "identity"),
            ("tag_not_annotated", "identity"),
            ("tag_commit", "identity"),
        )
        self.assertEqual(first_kill.DEFAULT_TAG, first_kill._safe_preflight_tag(first_kill.DEFAULT_TAG))
        self.assertEqual("<redacted>", first_kill._safe_preflight_tag(non_default_tag))
        for diagnostic_key, stage in cases:
            with self.subTest(diagnostic_key=diagnostic_key):
                output = io.StringIO()
                errors = io.StringIO()
                with (
                    mock.patch.object(first_kill, "operator_name", return_value="tester") as operator,
                    mock.patch.object(first_kill, "compatibility") as compatibility,
                    mock.patch.object(
                        first_kill, "repository_root", return_value=Path("/private/repo")
                    ) as root,
                    mock.patch.object(
                        first_kill, "local_release_identity", return_value=TAG_COMMIT
                    ) as identity,
                    mock.patch.object(first_kill, "prepare_workspace") as prepare_workspace,
                    mock.patch.object(first_kill, "release_files") as release_files,
                    mock.patch.object(first_kill, "verify_tag") as verify_tag,
                    mock.patch.object(first_kill, "verify_checksum_signature") as signature,
                    mock.patch.object(first_kill, "verify_bundle_checksum") as checksum,
                    mock.patch.object(first_kill, "install_release") as install,
                    mock.patch.object(first_kill, "run_real_smoke") as smoke,
                    mock.patch.object(first_kill.tempfile, "mkdtemp") as make_temporary,
                    mock.patch.object(first_kill, "download") as download,
                    mock.patch.object(first_kill.urllib.request, "urlopen") as urlopen,
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                ):
                    failure = first_kill.preflight_failure(
                        diagnostic_key, f"refusal {diagnostic_key}: {canary}"
                    )
                    if stage == "operator":
                        operator.side_effect = failure
                    elif stage == "compatibility":
                        compatibility.side_effect = failure
                    elif stage == "repository":
                        root.side_effect = failure
                    else:
                        identity.side_effect = failure
                    result = first_kill.main(
                        [
                            "--operator",
                            "tester",
                            "--tag",
                            non_default_tag,
                            "--preflight-only",
                        ]
                    )

                self.assertEqual(2, result)
                summary = json.loads(output.getvalue())
                self.assertEqual(blocked_fields, set(summary))
                self.assertEqual(first_kill.PREFLIGHT_SCHEMA, summary["schema"])
                self.assertEqual("preflight-only", summary["mode"])
                self.assertEqual("PREFLIGHT_BLOCKED", summary["result"])
                self.assertFalse(summary["changes_made"])
                self.assertFalse(summary["supported"])
                self.assertEqual("<redacted>", summary["tag"])
                diagnostic = first_kill.PREFLIGHT_DIAGNOSTICS[diagnostic_key]
                self.assertEqual(diagnostic.failed_check, summary["failed_check"])
                self.assertEqual(diagnostic.reason_code, summary["reason_code"])
                self.assertEqual(diagnostic.next_action, summary["next_action"])
                self.assertNotIn(canary, output.getvalue())
                self.assertNotIn("private", output.getvalue().lower())
                self.assertEqual("", errors.getvalue())
                for forbidden in (
                    prepare_workspace,
                    release_files,
                    verify_tag,
                    signature,
                    checksum,
                    install,
                    smoke,
                    make_temporary,
                    download,
                    urlopen,
                ):
                    forbidden.assert_not_called()
                if stage == "operator":
                    operator.assert_called_once_with("tester")
                    compatibility.assert_not_called()
                    root.assert_not_called()
                    identity.assert_not_called()
                elif stage == "compatibility":
                    operator.assert_called_once_with("tester")
                    compatibility.assert_called_once_with("tester")
                    root.assert_not_called()
                    identity.assert_not_called()
                elif stage == "repository":
                    operator.assert_called_once_with("tester")
                    compatibility.assert_called_once_with("tester")
                    root.assert_called_once_with()
                    identity.assert_not_called()
                else:
                    operator.assert_called_once_with("tester")
                    compatibility.assert_called_once_with("tester")
                    root.assert_called_once_with()
                    identity.assert_called_once_with(Path("/private/repo"), non_default_tag)

    def test_normal_run_still_requires_download_acceptance(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--operator", "tester"])
        self.assertEqual(2, raised.exception.code)

    def _run_result_mode(
        self,
        choice: str,
        *,
        receipt: dict[str, object] | None = None,
        remove_failure: BaseException | None = None,
        publish_failure: BaseException | None = None,
        ai_preexisting: bool = False,
    ) -> tuple[int, mock.Mock, mock.Mock, mock.Mock, str, str]:
        release = {
            "artifact": "lumi-eggcracker-1.0.0.pyz",
            "sha256": "a" * 64,
            "source_archive": "lumi-eggcracker-1.0.0-source.zip",
            "source_commit": TAG_COMMIT,
            "version": "1.0.0",
        }
        workspace = Path("/private-workspace")
        output_path = Path("/private-result.json")
        published = mock.Mock(side_effect=publish_failure)
        removed = mock.Mock(side_effect=remove_failure)
        verified = mock.Mock()
        output = io.StringIO()
        errors = io.StringIO()
        root_directory_patcher = mock.patch.object(first_kill, "require_root_directory")
        root_directory_patcher.start()
        self.addCleanup(root_directory_patcher.stop)
        with tempfile.TemporaryDirectory() if ai_preexisting else contextlib.nullcontext() as ai_workspace_raw:
            ai_workspace_arg = Path(ai_workspace_raw) if ai_workspace_raw is not None else None
            argv = [
                "--operator",
                "tester",
                "--workspace",
                str(workspace),
                "--accept-third-party-downloads",
                "--result-output",
                str(output_path),
                choice,
            ]
            if ai_workspace_arg is not None:
                argv.extend(["--ai-workspace", str(ai_workspace_arg)])
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(first_kill, "operator_name", return_value="tester"))
                stack.enter_context(mock.patch.object(first_kill, "compatibility"))
                stack.enter_context(
                    mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout"))
                )
                stack.enter_context(mock.patch.object(first_kill, "prepare_workspace", return_value=workspace))
                stack.enter_context(
                    mock.patch.object(
                        first_kill,
                        "release_files",
                        return_value=(Path("/bundle.zip"), Path("/key.asc"), Path("/SHA256SUMS"), Path("/SHA256SUMS.asc")),
                    )
                )
                stack.enter_context(mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT))
                stack.enter_context(mock.patch.object(first_kill, "verify_checksum_signature"))
                stack.enter_context(mock.patch.object(first_kill, "verify_bundle_checksum"))
                stack.enter_context(
                    mock.patch.object(first_kill, "extracted_release", return_value=Path("/release"))
                )
                stack.enter_context(mock.patch.object(first_kill, "manifest", return_value=release))
                stack.enter_context(mock.patch.object(first_kill, "run"))
                stack.enter_context(mock.patch.object(first_kill, "install_release"))
                stack.enter_context(
                    mock.patch.object(first_kill, "installed_workload_user", return_value="workload")
                )
                stack.enter_context(
                    mock.patch.object(first_kill, "run_real_smoke", return_value=receipt or success_receipt())
                )
                stack.enter_context(mock.patch.object(first_kill, "remove_installation", removed))
                stack.enter_context(mock.patch.object(first_kill, "verify_removed_targets", verified))
                stack.enter_context(
                    mock.patch.object(first_kill, "validate_result_output", return_value=output_path)
                )
                stack.enter_context(mock.patch.object(first_kill, "publish_success_result", published))
                stack.enter_context(contextlib.redirect_stdout(output))
                stack.enter_context(contextlib.redirect_stderr(errors))
                result = first_kill.main(argv)
        return result, published, verified, removed, output.getvalue(), errors.getvalue()

    def test_result_output_requires_one_explicit_cleanup_choice(self) -> None:
        output = Path("/private-result.json")
        with (
            mock.patch.object(first_kill, "validate_result_output") as validate,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(
                ["--accept-third-party-downloads", "--result-output", str(output)]
            )
        self.assertEqual(2, raised.exception.code)
        validate.assert_not_called()

    def test_result_destination_is_validated_before_download_or_install(self) -> None:
        release_files = mock.Mock()
        with (
            mock.patch.object(
                first_kill,
                "validate_result_output",
                side_effect=first_kill.FirstKillError("PRIVATE destination"),
            ),
            mock.patch.object(first_kill, "release_files", release_files),
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(
                [
                    "--accept-third-party-downloads",
                    "--keep",
                    "--result-output",
                    "/private-result.json",
                ]
            )
        self.assertEqual(2, raised.exception.code)
        release_files.assert_not_called()

    def test_result_output_rejects_plan_and_preflight_before_effects(self) -> None:
        for flags in (
            ["--third-party-download-plan", "--result-output", "/private-result.json", "--keep"],
            ["--preflight-only", "--result-output", "/private-result.json", "--keep"],
        ):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                first_kill.main(flags)

    def test_result_output_keep_publishes_fixed_projection_without_sensitive_fields(self) -> None:
        result, published, verified, removed, output, errors = self._run_result_mode("--keep")
        self.assertEqual(0, result)
        document = published.call_args.args[1]
        self.assertEqual(first_kill.SUCCESS_RESULT_FIELDS, set(document))
        self.assertEqual(first_kill.SUCCESS_DISPOSITION_RETAINED, document["disposition"])
        self.assertEqual(first_kill.SUCCESS_AI_ASSETS_NEW_RETAINED, document["ai_assets_disposition"])
        self.assertEqual(first_kill.SUCCESS_RUN_SCOPE, document["run_scope"])
        self.assertFalse(document["authenticated"])
        self.assertFalse(document["independent_containment_proof"])
        self.assertEqual(first_kill.SUCCESS_SOURCE_COMMIT_ROLE, document["source_commit_role"])
        self.assertEqual(TAG_COMMIT, document["source_commit"])
        self.assertNotIn("PRIVATE", json.dumps(document))
        self.assertNotIn("424242", output + errors)
        removed.assert_not_called()
        verified.assert_not_called()

    def test_result_output_remove_requires_read_only_absence_verification(self) -> None:
        result, published, verified, removed, _output, errors = self._run_result_mode("--remove")
        self.assertEqual(0, result)
        self.assertEqual(first_kill.SUCCESS_DISPOSITION_REMOVED, published.call_args.args[1]["disposition"])
        self.assertEqual(first_kill.SUCCESS_AI_ASSETS_NEW_REMOVED, published.call_args.args[1]["ai_assets_disposition"])
        removed.assert_called_once()
        verified.assert_called_once_with(
            Path("/private-workspace"),
            first_kill.DEFAULT_AI_SMOKE_WORKSPACE.absolute(),
            assets_preexisting=False,
        )
        self.assertEqual("", errors)

    def test_result_output_remove_excludes_preexisting_ai_assets_from_claim(self) -> None:
        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--remove", ai_preexisting=True
        )
        self.assertEqual(0, result)
        document = published.call_args.args[1]
        self.assertEqual(first_kill.SUCCESS_DISPOSITION_REMOVED, document["disposition"])
        self.assertEqual(
            first_kill.SUCCESS_AI_ASSETS_PREEXISTING_EXCLUDED,
            document["ai_assets_disposition"],
        )
        removed.assert_called_once_with(Path("/release"), Path("/private-workspace"), None)
        verified.assert_called_once_with(
            Path("/private-workspace"), None, assets_preexisting=True
        )
        self.assertEqual("", errors)

    def test_result_output_malformed_receipt_and_removal_failure_publish_nothing(self) -> None:
        malformed = success_receipt()
        malformed["containment"] = {"root_populated": 0, "surviving_pids": []}
        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--remove", receipt=malformed
        )
        self.assertEqual(2, result)
        published.assert_not_called()
        removed.assert_not_called()
        verified.assert_not_called()
        self.assertNotIn("PRIVATE", errors)

        failed_canary = success_receipt(canary_survived=False)
        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--keep", receipt=failed_canary
        )
        self.assertEqual(2, result)
        published.assert_not_called()
        removed.assert_not_called()
        verified.assert_not_called()
        self.assertNotIn("PRIVATE", errors)

        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--remove", remove_failure=first_kill.FirstKillError("PRIVATE removal failure")
        )
        self.assertEqual(2, result)
        published.assert_not_called()
        verified.assert_not_called()
        self.assertNotIn("PRIVATE", errors)

    def test_result_publication_parent_identity_race_fails_closed(self) -> None:
        info = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_dev=1,
            st_ino=2,
            st_file_attributes=0,
        )
        replacement = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700,
            st_uid=0,
            st_dev=1,
            st_ino=3,
            st_file_attributes=0,
        )
        with mock.patch.object(first_kill, "_result_output_effective_uid", return_value=0):
            with mock.patch.object(first_kill.os, "lstat", return_value=info):
                self.assertTrue(first_kill._result_output_parent_path_matches(Path("/safe"), (1, 2)))
            with mock.patch.object(first_kill.os, "lstat", return_value=replacement):
                self.assertFalse(first_kill._result_output_parent_path_matches(Path("/safe"), (1, 2)))

    def test_result_publication_posix_calls_complete_and_cleans_exact_temp(self) -> None:
        with publication_mocks() as calls:
            first_kill.publish_success_result(calls["destination"], {"result": "ok"})
        self.assertEqual(1, calls["write"].call_count)
        calls["link"].assert_called_once_with(
            calls["temporary_name"][0],
            calls["destination"].name,
            src_dir_fd=101,
            dst_dir_fd=101,
            follow_symlinks=False,
        )
        calls["unlink"].assert_called_once_with(calls["temporary_name"][0], dir_fd=101)
        self.assertEqual(2, calls["open"].call_count)

    def test_result_publication_posix_calls_partial_write_loop(self) -> None:
        first_write = True

        def partial_write(_fd, view):
            nonlocal first_write
            if first_write:
                first_write = False
                return 1
            return len(view)

        with publication_mocks(write_side_effect=partial_write) as calls:
            first_kill.publish_success_result(calls["destination"], {"result": "partial"})
        self.assertEqual(2, calls["write"].call_count)
        calls["unlink"].assert_called_once_with(calls["temporary_name"][0], dir_fd=101)

    def test_result_publication_posix_calls_write_failure_is_safe(self) -> None:
        with (
            publication_mocks(write_side_effect=OSError("private write failure")) as calls,
            self.assertRaisesRegex(first_kill.FirstKillError, first_kill.RESULT_OUTPUT_FAILURE),
        ):
            first_kill.publish_success_result(calls["destination"], {"result": "write-failure"})
        calls["link"].assert_not_called()
        calls["unlink"].assert_called_once_with(calls["temporary_name"][0], dir_fd=101)

    def test_result_publication_posix_calls_existing_or_raced_destination_never_overwrites(self) -> None:
        with (
            publication_mocks(destination_exists=True) as existing,
            self.assertRaisesRegex(first_kill.FirstKillError, first_kill.RESULT_OUTPUT_FAILURE),
        ):
            first_kill.publish_success_result(existing["destination"], {"result": "existing"})
        existing["link"].assert_not_called()
        existing["unlink"].assert_called_once_with(existing["temporary_name"][0], dir_fd=101)

        with (
            publication_mocks(link_race=True) as raced,
            self.assertRaisesRegex(first_kill.FirstKillError, first_kill.RESULT_OUTPUT_FAILURE),
        ):
            first_kill.publish_success_result(raced["destination"], {"result": "raced"})
        raced["link"].assert_called_once()
        raced["unlink"].assert_called_once_with(raced["temporary_name"][0], dir_fd=101)

    def test_result_publication_posix_calls_parent_identity_race_before_link(self) -> None:
        with (
            publication_mocks(parent_race=True) as calls,
            self.assertRaisesRegex(first_kill.FirstKillError, first_kill.RESULT_OUTPUT_FAILURE),
        ):
            first_kill.publish_success_result(calls["destination"], {"result": "parent-race"})
        calls["link"].assert_not_called()
        calls["unlink"].assert_not_called()

    def test_result_publication_post_link_failure_removes_only_our_destination(self) -> None:
        with (
            publication_mocks(
                fsync_side_effect=[None, OSError("private parent fsync"), None]
            ) as calls,
            self.assertRaisesRegex(first_kill.FirstKillError, first_kill.RESULT_OUTPUT_FAILURE),
        ):
            first_kill.publish_success_result(calls["destination"], {"result": "post-link"})
        self.assertEqual(
            [
                mock.call(calls["temporary_name"][0], dir_fd=101),
                mock.call(calls["destination"].name, dir_fd=101),
            ],
            calls["unlink"].call_args_list,
        )
        self.assertTrue(any(name == calls["destination"].name for name, _fd in calls["stat_calls"]))

    def test_result_publication_cleanup_never_unlinks_foreign_temp(self) -> None:
        foreign = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
            st_dev=11,
            st_ino=99,
            st_file_attributes=0,
        )
        with (
            mock.patch.object(first_kill, "_result_output_effective_uid", return_value=0),
            mock.patch.object(first_kill, "_result_output_parent_matches", return_value=True),
            mock.patch.object(first_kill, "_result_output_parent_path_matches", return_value=True),
            mock.patch.object(first_kill.os, "stat", return_value=foreign),
            mock.patch.object(first_kill.os, "unlink") as unlink,
        ):
            first_kill._result_output_unlink_owned(
                101,
                ".result.tmp",
                (11, 33),
                (11, 22),
                Path("/synthetic-result"),
            )
        unlink.assert_not_called()

    def test_result_output_publication_failure_reports_known_kept_state(self) -> None:
        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--keep", publish_failure=first_kill.FirstKillError("PRIVATE write failure")
        )
        self.assertEqual(2, result)
        published.assert_called_once()
        removed.assert_not_called()
        verified.assert_not_called()
        summary = json.loads(errors)
        self.assertEqual(first_kill.FULL_RUN_INSTALL_STATE_INSTALLED, summary["installation_state"])
        self.assertEqual(first_kill.FULL_RUN_STAGE_RESULT_PUBLICATION, summary["stage"])
        self.assertEqual("RESULT_PUBLICATION_FAILURE", summary["reason_code"])
        self.assertEqual(first_kill.FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED, summary["removal_guidance"])
        self.assertNotIn("PRIVATE", errors)

    def test_result_output_publication_failure_reports_verified_removed_state(self) -> None:
        result, published, verified, removed, _output, errors = self._run_result_mode(
            "--remove", publish_failure=first_kill.FirstKillError("PRIVATE write failure")
        )
        self.assertEqual(2, result)
        published.assert_called_once()
        removed.assert_called_once()
        verified.assert_called_once()
        summary = json.loads(errors)
        self.assertEqual(first_kill.FULL_RUN_INSTALL_STATE_NOT_INSTALLED, summary["installation_state"])
        self.assertEqual(first_kill.FULL_RUN_STAGE_RESULT_PUBLICATION, summary["stage"])
        self.assertEqual("RESULT_PUBLICATION_FAILURE", summary["reason_code"])
        self.assertEqual(first_kill.FULL_RUN_REMOVAL_NOT_REQUIRED, summary["removal_guidance"])
        self.assertNotIn("PRIVATE", errors)

    def test_result_destination_rejects_relative_existing_nonregular_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            existing = root / "existing.json"
            existing.write_text("preserve", encoding="utf-8")
            directory = root / "directory.json"
            directory.mkdir()
            with mock.patch.object(first_kill, "_result_output_effective_uid", return_value=0):
                with self.assertRaises(first_kill.FirstKillError):
                    first_kill.validate_result_output(Path("relative-result.json"))
                with self.assertRaises(first_kill.FirstKillError):
                    first_kill.validate_result_output(existing)
                with self.assertRaises(first_kill.FirstKillError):
                    first_kill.validate_result_output(directory)
                try:
                    link = root / "link.json"
                    os.symlink(existing, link)
                except (NotImplementedError, OSError):
                    link = None
                if link is not None:
                    with self.assertRaises(first_kill.FirstKillError):
                        first_kill.validate_result_output(link)
            self.assertEqual("preserve", existing.read_text(encoding="utf-8"))

    def test_result_removal_verification_rejects_residue_dangling_link_and_keeps_unrelated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = root / "workspace"
            assets = root / "assets"
            workspace.mkdir()
            assets.mkdir()
            unrelated = root / "unrelated.txt"
            unrelated.write_text("preserve", encoding="utf-8")
            original_targets = first_kill.INSTALL_TARGETS
            first_kill.INSTALL_TARGETS = (root / "managed",)
            try:
                with self.assertRaises(first_kill.FirstKillError):
                    first_kill.verify_removed_targets(workspace, assets, assets_preexisting=False)
                workspace.rmdir()
                assets.rmdir()
                first_kill.verify_removed_targets(workspace, assets, assets_preexisting=False)
                self.assertEqual("preserve", unrelated.read_text(encoding="utf-8"))
                dangling = root / "managed"
                try:
                    os.symlink(root / "gone", dangling, target_is_directory=True)
                except (NotImplementedError, OSError):
                    pass
                else:
                    with self.assertRaises(first_kill.FirstKillError):
                        first_kill.verify_removed_targets(workspace, assets, assets_preexisting=False)
            finally:
                first_kill.INSTALL_TARGETS = original_targets

    def test_normal_run_authenticates_checksums_before_extraction_or_install(self) -> None:
        events: list[str] = []
        release = {
            "artifact": "lumi-eggcracker-1.0.0.pyz",
            "sha256": "a" * 64,
            "source_archive": "lumi-eggcracker-1.0.0-source.zip",
            "source_commit": TAG_COMMIT,
            "version": "1.0.0",
        }
        receipt = {
            "result": "TERMINATED",
            "containment": {"surviving_pids": [], "root_populated": 0},
        }
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester"),
            mock.patch.object(first_kill, "compatibility"),
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill, "prepare_workspace", return_value=Path("/private-workspace")
            ),
            mock.patch.object(
                first_kill,
                "release_files",
                return_value=(
                    Path("/bundle.zip"),
                    Path("/key.asc"),
                    Path("/SHA256SUMS"),
                    Path("/SHA256SUMS.asc"),
                ),
            ),
            mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT),
            mock.patch.object(
                first_kill,
                "verify_checksum_signature",
                side_effect=lambda *_: events.append("signature"),
            ),
            mock.patch.object(
                first_kill,
                "verify_bundle_checksum",
                side_effect=lambda *_: events.append("checksum"),
            ),
            mock.patch.object(
                first_kill,
                "extracted_release",
                side_effect=lambda *_: events.append("extract") or Path("/release"),
            ),
            mock.patch.object(first_kill, "manifest", return_value=release),
            mock.patch.object(first_kill, "run"),
            mock.patch.object(
                first_kill,
                "install_release",
                side_effect=lambda *_: events.append("install"),
            ),
            mock.patch.object(
                first_kill, "installed_workload_user", return_value="workload"
            ),
            mock.patch.object(
                first_kill, "run_real_smoke", return_value=receipt
            ) as run_real_smoke,
            mock.patch.object(first_kill, "remove_installation"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = first_kill.main(
                [
                    "--operator",
                    "tester",
                    "--workspace",
                    "/private-workspace",
                    "--accept-third-party-downloads",
                    "--remove",
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(["signature", "checksum", "extract", "install"], events)
        smoke_args = run_real_smoke.call_args.args
        self.assertEqual(Path("/checkout"), smoke_args[0])
        self.assertNotEqual(Path("/release"), smoke_args[0])
        self.assertEqual(
            (
                Path("/private-workspace"),
                "workload",
                first_kill.DEFAULT_AI_SMOKE_WORKSPACE.absolute(),
                0,
            ),
            smoke_args[1:],
        )

    def test_full_run_pre_install_failure_is_bounded_and_redacted(self) -> None:
        canary = "SECRET_PATH=/private/pre-install --argv=hidden ENV_SECRET=hidden"
        output = io.StringIO()
        errors = io.StringIO()
        with (
            mock.patch.object(
                first_kill,
                "operator_name",
                side_effect=first_kill.FirstKillError(canary),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(
                ["--operator", "tester", "--accept-third-party-downloads"]
            )

        self.assertEqual(2, result)
        summary = json.loads(errors.getvalue())
        self.assertEqual(first_kill.FULL_RUN_FAILURE_FIELDS, set(summary))
        self.assertEqual(first_kill.FULL_RUN_FAILURE_SCHEMA, summary["schema"])
        self.assertEqual(first_kill.FULL_RUN_FAILURE_VERSION, summary["version"])
        self.assertEqual("FULL_RUN_FAILED", summary["result"])
        self.assertEqual(first_kill.FULL_RUN_STAGE_PRE_INSTALL, summary["stage"])
        self.assertEqual("PRE_INSTALL_FAILURE", summary["reason_code"])
        self.assertEqual(
            first_kill.FULL_RUN_INSTALL_STATE_NOT_INSTALLED,
            summary["installation_state"],
        )
        self.assertEqual(first_kill.FULL_RUN_REMOVAL_NOT_REQUIRED, summary["removal_guidance"])
        self.assertEqual(first_kill.FULL_RUN_NEXT_ACTION, summary["next_action"])
        self.assertNotIn(canary, output.getvalue() + errors.getvalue())

    def test_full_run_install_failure_reports_partial_install_without_leaks(self) -> None:
        canary = "SECRET_PATH=/private/install --argv=hidden ENV_SECRET=hidden"
        output = io.StringIO()
        errors = io.StringIO()
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester"),
            mock.patch.object(first_kill, "compatibility"),
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill, "prepare_workspace", return_value=Path("/private-workspace")
            ),
            mock.patch.object(
                first_kill,
                "release_files",
                return_value=(
                    Path("/bundle.zip"),
                    Path("/key.asc"),
                    Path("/SHA256SUMS"),
                    Path("/SHA256SUMS.asc"),
                ),
            ),
            mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT),
            mock.patch.object(first_kill, "verify_checksum_signature"),
            mock.patch.object(first_kill, "verify_bundle_checksum"),
            mock.patch.object(first_kill, "extracted_release", return_value=Path("/release")),
            mock.patch.object(
                first_kill,
                "manifest",
                return_value={
                    "artifact": "lumi-eggcracker-1.0.0.pyz",
                    "sha256": "a" * 64,
                    "source_archive": "lumi-eggcracker-1.0.0-source.zip",
                    "source_commit": TAG_COMMIT,
                    "version": "1.0.0",
                },
            ),
            mock.patch.object(first_kill, "run"),
            mock.patch.object(
                first_kill,
                "install_release",
                side_effect=first_kill.FirstKillError(canary),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(
                ["--operator", "tester", "--accept-third-party-downloads"]
            )

        self.assertEqual(2, result)
        summary = json.loads(errors.getvalue())
        self.assertEqual(first_kill.FULL_RUN_FAILURE_FIELDS, set(summary))
        self.assertEqual(first_kill.FULL_RUN_STAGE_INSTALL, summary["stage"])
        self.assertEqual("INSTALL_FAILURE", summary["reason_code"])
        self.assertEqual(
            first_kill.FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL,
            summary["installation_state"],
        )
        self.assertEqual(
            first_kill.FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED,
            summary["removal_guidance"],
        )
        self.assertEqual(first_kill.FULL_RUN_NEXT_ACTION, summary["next_action"])
        self.assertNotIn(canary, output.getvalue() + errors.getvalue())

    def test_full_run_post_install_failure_reports_installed_and_redacts(self) -> None:
        canary = "SECRET_PATH=/private/post-install --argv=hidden ENV_SECRET=hidden"
        output = io.StringIO()
        errors = io.StringIO()
        release = {
            "artifact": "lumi-eggcracker-1.0.0.pyz",
            "sha256": "a" * 64,
            "source_archive": "lumi-eggcracker-1.0.0-source.zip",
            "source_commit": TAG_COMMIT,
            "version": "1.0.0",
        }
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester"),
            mock.patch.object(first_kill, "compatibility"),
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill, "prepare_workspace", return_value=Path("/private-workspace")
            ),
            mock.patch.object(
                first_kill,
                "release_files",
                return_value=(
                    Path("/bundle.zip"),
                    Path("/key.asc"),
                    Path("/SHA256SUMS"),
                    Path("/SHA256SUMS.asc"),
                ),
            ),
            mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT),
            mock.patch.object(first_kill, "verify_checksum_signature"),
            mock.patch.object(first_kill, "verify_bundle_checksum"),
            mock.patch.object(first_kill, "extracted_release", return_value=Path("/release")),
            mock.patch.object(first_kill, "manifest", return_value=release),
            mock.patch.object(first_kill, "run"),
            mock.patch.object(first_kill, "install_release"),
            mock.patch.object(first_kill, "installed_workload_user", return_value="workload"),
            mock.patch.object(
                first_kill,
                "run_real_smoke",
                side_effect=first_kill.FirstKillError(canary),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(
                ["--operator", "tester", "--accept-third-party-downloads"]
            )

        self.assertEqual(2, result)
        summary = json.loads(errors.getvalue())
        self.assertEqual(first_kill.FULL_RUN_FAILURE_FIELDS, set(summary))
        self.assertEqual(first_kill.FULL_RUN_STAGE_POST_INSTALL, summary["stage"])
        self.assertEqual("POST_INSTALL_FAILURE", summary["reason_code"])
        self.assertEqual(first_kill.FULL_RUN_INSTALL_STATE_INSTALLED, summary["installation_state"])
        self.assertEqual(
            first_kill.FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED,
            summary["removal_guidance"],
        )
        self.assertEqual(first_kill.FULL_RUN_NEXT_ACTION, summary["next_action"])
        self.assertNotIn(canary, output.getvalue() + errors.getvalue())
        self.assertNotIn("--remove", output.getvalue() + errors.getvalue())

    def test_full_run_removal_failure_reports_unknown_state_and_redacts(self) -> None:
        canary = "SECRET_PATH=/private/removal --argv=hidden ENV_SECRET=hidden"
        output = io.StringIO()
        errors = io.StringIO()
        release = {
            "artifact": "lumi-eggcracker-1.0.0.pyz",
            "sha256": "a" * 64,
            "source_archive": "lumi-eggcracker-1.0.0-source.zip",
            "source_commit": TAG_COMMIT,
            "version": "1.0.0",
        }
        receipt = {
            "result": "TERMINATED",
            "containment": {"surviving_pids": [], "root_populated": 0},
        }
        with (
            mock.patch.object(first_kill, "operator_name", return_value="tester"),
            mock.patch.object(first_kill, "compatibility"),
            mock.patch.object(first_kill, "repository_root", return_value=Path("/checkout")),
            mock.patch.object(
                first_kill, "prepare_workspace", return_value=Path("/private-workspace")
            ),
            mock.patch.object(
                first_kill,
                "release_files",
                return_value=(
                    Path("/bundle.zip"),
                    Path("/key.asc"),
                    Path("/SHA256SUMS"),
                    Path("/SHA256SUMS.asc"),
                ),
            ),
            mock.patch.object(first_kill, "verify_tag", return_value=TAG_COMMIT),
            mock.patch.object(first_kill, "verify_checksum_signature"),
            mock.patch.object(first_kill, "verify_bundle_checksum"),
            mock.patch.object(first_kill, "extracted_release", return_value=Path("/release")),
            mock.patch.object(first_kill, "manifest", return_value=release),
            mock.patch.object(first_kill, "run"),
            mock.patch.object(first_kill, "install_release"),
            mock.patch.object(first_kill, "installed_workload_user", return_value="workload"),
            mock.patch.object(first_kill, "run_real_smoke", return_value=receipt),
            mock.patch.object(
                first_kill,
                "remove_installation",
                side_effect=first_kill.FirstKillError(canary),
            ),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(
                [
                    "--operator",
                    "tester",
                    "--accept-third-party-downloads",
                    "--remove",
                ]
            )

        self.assertEqual(2, result)
        summary = json.loads(errors.getvalue())
        self.assertEqual(first_kill.FULL_RUN_FAILURE_FIELDS, set(summary))
        self.assertEqual(first_kill.FULL_RUN_STAGE_REMOVAL, summary["stage"])
        self.assertEqual("REMOVAL_FAILURE", summary["reason_code"])
        self.assertEqual(
            first_kill.FULL_RUN_INSTALL_STATE_UNKNOWN_OR_PARTIAL,
            summary["installation_state"],
        )
        self.assertEqual(
            first_kill.FULL_RUN_REMOVAL_MANUAL_REVIEW_REQUIRED,
            summary["removal_guidance"],
        )
        self.assertEqual(first_kill.FULL_RUN_NEXT_ACTION, summary["next_action"])
        self.assertNotIn(canary, output.getvalue() + errors.getvalue())
        self.assertNotIn("--remove", output.getvalue() + errors.getvalue())

    def test_real_smoke_uses_current_campaign_preparer(self) -> None:
        campaign_root = Path("/campaign-checkout")
        expected = campaign_root / "scripts" / "prepare_ai_smoke.py"
        stop = first_kill.FirstKillError("stop after selecting preparer")
        with (
            mock.patch.object(first_kill, "require_regular") as require_regular,
            mock.patch.object(first_kill, "run", side_effect=stop) as run,
            self.assertRaisesRegex(first_kill.FirstKillError, "stop after selecting preparer"),
        ):
            first_kill.run_real_smoke(
                campaign_root,
                Path("/workspace"),
                "workload",
                Path("/assets"),
            )

        require_regular.assert_called_once_with(expected, "AI smoke preparer")
        self.assertEqual(str(expected), run.call_args.args[0][3])
        self.assertNotIn("release", str(run.call_args.args[0][3]))

    def test_preflight_rejects_mutation_only_flags(self) -> None:
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            first_kill.main(["--preflight-only", "--keep"])
        self.assertEqual(2, raised.exception.code)

    def test_preflight_error_redacts_sudo_user_identity(self) -> None:
        canary = "operator-identity-must-not-appear"
        output = io.StringIO()
        errors = io.StringIO()
        passwd = mock.Mock()
        passwd.getpwnam.side_effect = KeyError(canary)
        with (
            mock.patch.object(first_kill, "pwd", passwd),
            mock.patch.dict(os.environ, {"SUDO_USER": canary}),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            result = first_kill.main(["--preflight-only"])
        self.assertEqual(2, result)
        summary = json.loads(output.getvalue())
        self.assertEqual("PREFLIGHT_BLOCKED", summary["result"])
        self.assertEqual("OPERATOR_ACCOUNT_MISSING", summary["reason_code"])
        self.assertNotIn(canary, errors.getvalue())
        self.assertNotIn(canary, output.getvalue())
        self.assertNotIn("operator account does not exist", output.getvalue())

    def test_local_release_identity_requires_annotated_tag(self) -> None:
        annotated = mock.Mock(returncode=0, stdout="tag\n")
        resolved = mock.Mock(returncode=0, stdout=f"{TAG_COMMIT}\n")
        with mock.patch.object(first_kill, "run", side_effect=[annotated, resolved]):
            result = first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)
        self.assertEqual(TAG_COMMIT, result)

    def test_local_release_identity_rejects_non_commit_output(self) -> None:
        annotated = mock.Mock(returncode=0, stdout="tag\n")
        malformed = mock.Mock(returncode=0, stdout="not-a-commit\n")
        with (
            mock.patch.object(first_kill, "run", side_effect=[annotated, malformed]),
            self.assertRaisesRegex(first_kill.FirstKillError, "does not resolve"),
        ):
            first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)

    def test_local_release_identity_rejects_lightweight_tag(self) -> None:
        lightweight = mock.Mock(returncode=0, stdout="commit\n")
        resolved = mock.Mock(returncode=0, stdout=f"{TAG_COMMIT}\n")
        with (
            mock.patch.object(first_kill, "run", side_effect=[lightweight, resolved]),
            self.assertRaisesRegex(first_kill.FirstKillError, "not an annotated tag"),
        ):
            first_kill.local_release_identity(Path("/checkout"), first_kill.DEFAULT_TAG)

    def test_receipt_summary_is_bounded_and_redacts_paths(self) -> None:
        value = first_kill.receipt_summary(
            {
                "result": "TERMINATED",
                "detector": {"profile": "content.gguf-llama", "trigger": "UNAPPROVED"},
                "trigger": {"kind": "UNAPPROVED_AI_MATCH"},
                "capture": {"captured_processes": 2},
                "containment": {
                    "primitive": "pidfd-stop+cgroup.kill",
                    "root_populated": 0,
                    "surviving_pids": [],
                    "trigger_to_empty_ms": 42.5,
                    "local_path": "/tmp/private-model.gguf",
                },
            }
        )
        self.assertEqual("TERMINATED", value["result"])
        self.assertEqual("content.gguf-llama", value["profile"])
        self.assertEqual("UNAPPROVED_AI_MATCH", value["trigger"])
        self.assertEqual(2, value["captured_processes"])
        self.assertEqual(0, value["root_populated"])
        self.assertEqual(42.5, value["trigger_to_empty_ms"])
        self.assertNotIn("local_path", value)
        self.assertNotIn("private-model", str(value))

    def test_checksums_parse_only_sha256_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "SHA256SUMS"
            path.write_text("a" * 64 + "  payload.zip\n", encoding="ascii")
            self.assertEqual({"payload.zip": "a" * 64}, first_kill.parse_checksums(path))

    def test_checksums_reject_non_hex_and_duplicate_names(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "SHA256SUMS"
            path.write_text("z" * 64 + "  payload.zip\n", encoding="ascii")
            with self.assertRaisesRegex(first_kill.FirstKillError, "invalid line"):
                first_kill.parse_checksums(path)
            path.write_text(
                "a" * 64 + "  payload.zip\n" + "b" * 64 + "  payload.zip\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(first_kill.FirstKillError, "duplicate"):
                first_kill.parse_checksums(path)

    def test_safe_extract_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../outside.txt", "no")
            with self.assertRaisesRegex(first_kill.FirstKillError, "unsafe path"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_noncanonical_components(self) -> None:
        for member_name in ("release/./install.py", "release//install.py"):
            with self.subTest(member_name=member_name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                archive = root / "noncanonical.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr(member_name, "untrusted")
                with self.assertRaisesRegex(first_kill.FirstKillError, "unsafe path"):
                    first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_duplicate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr("release/install.py", "trusted")
                    bundle.writestr("release/install.py", "hostile")
            with self.assertRaisesRegex(first_kill.FirstKillError, "duplicate path"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_symlink_members(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "link.zip"
            member = zipfile.ZipInfo("release/install.py")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(member, "../../outside")
            with self.assertRaisesRegex(first_kill.FirstKillError, "link or special"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_trailing_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "appended.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("release/install.py", "trusted")
            with archive.open("ab") as handle:
                handle.write(b"DAYBREAK-TRAILING-DATA")
            with self.assertRaisesRegex(first_kill.FirstKillError, "trailing data"):
                first_kill.safe_extract(archive, root / "out")

    def test_safe_extract_rejects_prepended_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            original = root / "original.zip"
            archive = root / "prepended.zip"
            with zipfile.ZipFile(original, "w") as bundle:
                bundle.writestr("release/install.py", "trusted")
            archive.write_bytes(b"DAYBREAK-PREFIX" + original.read_bytes())
            with self.assertRaisesRegex(first_kill.FirstKillError, "prepended"):
                first_kill.safe_extract(archive, root / "out")

    def test_checksum_signature_requires_valid_pinned_key_signature(self) -> None:
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
            ),
            stderr="",
        )
        verified = mock.Mock(
            returncode=0,
            stdout=(
                "[GNUPG:] VALIDSIG "
                f"{first_kill.RELEASE_KEY_FINGERPRINT} 2026 0 0 4 0 1 10 00 "
                f"{first_kill.RELEASE_KEY_FINGERPRINT}\n"
            ),
            stderr="",
        )
        with mock.patch.object(first_kill, "run", side_effect=[imported, shown, verified]) as run:
            first_kill.verify_checksum_signature(
                Path("/release-key.asc"),
                Path("/SHA256SUMS"),
                Path("/SHA256SUMS.asc"),
            )
        self.assertIn("--verify", run.call_args_list[-1].args[0])

    def test_checksum_signature_failure_is_fatal(self) -> None:
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
            ),
            stderr="",
        )
        rejected = mock.Mock(returncode=1, stdout="", stderr="BAD signature")
        with (
            mock.patch.object(first_kill, "run", side_effect=[imported, shown, rejected]),
            self.assertRaisesRegex(first_kill.FirstKillError, "signature verification failed"),
        ):
            first_kill.verify_checksum_signature(
                Path("/release-key.asc"),
                Path("/SHA256SUMS"),
                Path("/SHA256SUMS.asc"),
            )

    def test_release_key_bundle_cannot_add_an_attacker_primary_key(self) -> None:
        attacker = "B" * 40
        imported = mock.Mock(returncode=0, stdout="", stderr="")
        shown = mock.Mock(
            returncode=0,
            stdout=(
                "pub:::::::::\n"
                f"fpr:::::::::{first_kill.RELEASE_KEY_FINGERPRINT}:\n"
                "pub:::::::::\n"
                f"fpr:::::::::{attacker}:\n"
            ),
            stderr="",
        )
        with (
            mock.patch.object(first_kill, "run", side_effect=[imported, shown]),
            self.assertRaisesRegex(first_kill.FirstKillError, "exactly the published"),
        ):
            first_kill.import_release_key(Path("/gpg-home"), Path("/release-key.asc"))

    def test_public_key_fingerprint_is_pinned(self) -> None:
        self.assertEqual(40, len(first_kill.RELEASE_KEY_FINGERPRINT))
        self.assertEqual(first_kill.RELEASE_KEY_FINGERPRINT.upper(), first_kill.RELEASE_KEY_FINGERPRINT)


if __name__ == "__main__":
    unittest.main()
