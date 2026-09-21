from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from lumi_eggcracker import containment_probe as probe
from lumi_eggcracker.discovery import ProcessIdentity


def probe_identity() -> probe.ProbeCgroupIdentity:
    unit = f"lumi-eggcracker-probe-{'a' * 32}.service"
    return probe.ProbeCgroupIdentity(
        unit=unit,
        invocation_id="b" * 32,
        control_group=f"/system.slice/{unit}",
        parent_device=1,
        parent_inode=2,
        target_device=1,
        target_inode=3,
        boot="c" * 36,
    )


class ContainmentProbeTests(unittest.TestCase):
    def test_failure_receipt_is_small_and_redacted(self) -> None:
        self.assertEqual(
            {
                "mode": "containment-primitive-probe",
                "reason_code": "ROOT_REQUIRED",
                "result": "FAILED",
            },
            probe.failure_receipt("ROOT_REQUIRED"),
        )
        with self.assertRaises(ValueError):
            probe.ProbeError("private path: /tmp/value")

    def test_control_write_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            control = Path(raw) / "pids.max"
            control.touch()
            probe._write_control(control, b"2\n")
            self.assertEqual("2\n", control.read_text(encoding="ascii"))

    def test_source_identity_binds_head_and_executed_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            git = root / ".git"
            reference = git / "refs" / "heads" / "main"
            reference.parent.mkdir(parents=True)
            (git / "HEAD").write_bytes(b"ref: refs/heads/main\n")
            reference.write_bytes(b"a" * 40 + b"\n")
            for relative in (
                Path("scripts/containment_probe.py"),
                Path("src/lumi_eggcracker/__init__.py"),
                Path("src/lumi_eggcracker/adoption.py"),
                Path("src/lumi_eggcracker/containment.py"),
                Path("src/lumi_eggcracker/containment_probe.py"),
                Path("src/lumi_eggcracker/discovery.py"),
                Path("src/lumi_eggcracker/jsonio.py"),
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.as_posix().encode("ascii"))
            commit, tree = probe._source_identity(root=root)
        self.assertEqual("a" * 40, commit)
        self.assertRegex(tree, r"^[0-9a-f]{64}$")

    def test_load_state_requires_explicit_not_found(self) -> None:
        failed = MagicMock(returncode=1, stdout="")
        absent = MagicMock(returncode=1, stdout="not-found\n")
        with patch.object(probe, "_safe_run", return_value=failed), self.assertRaisesRegex(
            probe.ProbeError, "UNIT_STATE_UNAVAILABLE"
        ):
            probe._load_state("unit.service")
        with patch.object(probe, "_safe_run", return_value=absent):
            self.assertEqual("not-found", probe._load_state("unit.service"))

    def test_owner_uses_an_exact_three_task_ceiling(self) -> None:
        result = MagicMock(returncode=0)
        with patch.object(probe, "_safe_run", return_value=result) as run:
            probe._start_owner("lumi-eggcracker-probe-" + "a" * 32 + ".service")
        argv = run.call_args.args[0]
        self.assertIn("--property=Delegate=pids", argv)
        self.assertIn("--property=TasksMax=3", argv)

    def test_owner_capture_rejects_a_drifted_task_ceiling(self) -> None:
        cgroup = probe_identity()
        parent = cgroup.parent_path
        with (
            patch.object(probe, "_property", side_effect=[cgroup.invocation_id, cgroup.control_group]),
            patch.object(probe, "_exact_directory", return_value=MagicMock(st_dev=1, st_ino=2)),
            patch.object(probe.Path, "is_file", autospec=True, return_value=True),
            patch.object(probe.Path, "read_text", autospec=True, return_value="4\n"),
            patch.object(probe, "_read_events", return_value={"max": 0}),
            self.assertRaisesRegex(probe.ProbeError, "OWNER_TASK_LIMIT_INVALID"),
        ):
            probe._capture_owner(cgroup.unit)
        self.assertEqual("/system.slice/" + cgroup.unit, cgroup.control_group)
        self.assertEqual(probe.CGROUP_ROOT / "system.slice" / cgroup.unit, parent)

    def test_preflight_requires_explicit_ack_before_any_host_check(self) -> None:
        with (
            patch.object(probe.os, "geteuid", side_effect=AssertionError("must not run"), create=True),
            self.assertRaisesRegex(probe.ProbeError, "DISPOSABLE_HOST_ACK_REQUIRED"),
        ):
            probe._host_preflight(False)

    def test_preflight_refuses_non_linux_without_platform_traceback(self) -> None:
        with (
            patch.object(probe.platform, "system", return_value="Windows"),
            self.assertRaisesRegex(probe.ProbeError, "NATIVE_LINUX_REQUIRED"),
        ):
            probe._host_preflight(True)

    def test_preflight_refuses_an_existing_installation_target(self) -> None:
        active = Path("/run/lumi-eggcracker")

        def exists(path: Path) -> bool:
            return path == active

        def read_text(path: Path, **_kwargs: object) -> str:
            values = {
                Path("/proc/sys/kernel/osrelease"): "6.8.0-generic",
                Path("/proc/1/comm"): "systemd\n",
                Path("/etc/os-release"): 'ID=ubuntu\nVERSION_ID="24.04"\n',
                probe.CGROUP_ROOT / "cgroup.controllers": "pids cpu memory\n",
            }
            return values[path]

        with (
            patch.object(probe.os, "geteuid", return_value=0, create=True),
            patch.object(probe.platform, "system", return_value="Linux"),
            patch.object(probe.Path, "exists", autospec=True, side_effect=exists),
            patch.object(probe.Path, "is_symlink", return_value=False),
            patch.object(probe.Path, "is_file", return_value=True),
            patch.object(probe.Path, "read_text", autospec=True, side_effect=read_text),
            patch.object(probe.os, "pidfd_open", create=True),
            patch.object(probe.signal, "pidfd_send_signal", create=True),
            self.assertRaisesRegex(probe.ProbeError, "ACTIVE_INSTALLATION_REFUSED"),
        ):
            probe._host_preflight(True)

    def test_target_readiness_requires_exactly_two_stable_identities(self) -> None:
        value = probe_identity()
        identities = {
            10: ProcessIdentity(10, 100),
            11: ProcessIdentity(11, 101),
            12: ProcessIdentity(12, 102),
        }
        with (
            patch.object(probe, "_validate_owner", return_value=Path("/target")),
            patch.object(probe, "_cgroup_processes", return_value=set(identities)),
            patch.object(probe, "identity", side_effect=lambda pid: identities[pid]),
            patch.object(probe.time, "monotonic", side_effect=[0.0, 0.1]),
            patch.object(probe.time, "sleep"),
            self.assertRaisesRegex(probe.ProbeError, "TARGET_READINESS_TIMEOUT"),
        ):
            probe._wait_target(value, 0.05)

    def test_strict_empty_does_not_treat_cgroup_disappearance_as_success(self) -> None:
        with patch.object(
            probe,
            "_validate_owner",
            side_effect=probe.ProbeError("CGROUP_IDENTITY_UNAVAILABLE"),
        ), self.assertRaisesRegex(probe.ProbeError, "CGROUP_IDENTITY_UNAVAILABLE"):
            probe._strict_empty(probe_identity(), probe.time.monotonic() + 1.0)

    def test_success_uses_production_kill_and_returns_only_allowlisted_fields(self) -> None:
        cgroup = probe_identity()
        canary = ProcessIdentity(20, 200)
        targets = (ProcessIdentity(30, 300), ProcessIdentity(31, 301))
        process = MagicMock()
        with (
            patch.object(probe, "_host_preflight"),
            patch.object(probe, "_source_identity", return_value=("d" * 40, "e" * 64)),
            patch.object(probe.secrets, "token_hex", return_value="a" * 32),
            patch.object(probe, "_assert_owner_available"),
            patch.object(probe, "_start_owner"),
            patch.object(probe, "_capture_owner", return_value=cgroup),
            patch.object(probe, "_spawn_canary", return_value=(process, canary, 40)),
            patch.object(
                probe,
                "_process_cgroup",
                side_effect=["/user.slice/session.scope", *(cgroup.control_group + "/target" for _ in targets)],
            ),
            patch.object(probe, "_spawn_target", return_value=process),
            patch.object(probe, "_wait_target", return_value=targets),
            patch.object(probe, "open_pidfd", side_effect=[50, 51]),
            patch.object(probe, "stop_pidfd", side_effect=[1_000_000, 1_000_100]),
            patch.object(probe, "_validate_owner", return_value=Path("/target")),
            patch.object(probe, "kill_path", return_value=(1_100_000, 1_100_100)) as direct,
            patch.object(probe, "_strict_empty", return_value=(2_000_000, 0, 1)),
            patch.object(probe, "_pidfd_alive", return_value=True),
            patch.object(probe, "_cleanup", return_value=True),
            patch.object(probe.signal, "signal", return_value=object()),
        ):
            receipt = probe.run_probe(acknowledged=True)
        self.assertEqual(probe.SUCCESS_KEYS, set(receipt))
        self.assertEqual("pidfd-stop+cgroup.kill", receipt["primitive"])
        self.assertEqual(2, receipt["target_processes"])
        self.assertTrue(receipt["canary_survived"])
        self.assertTrue(receipt["cleanup_complete"])
        self.assertEqual("d" * 40, receipt["source_commit"])
        self.assertEqual("e" * 64, receipt["source_tree_sha256"])
        direct.assert_called_once_with(Path("/target"))

    def test_cleanup_failure_overrides_a_stage_failure(self) -> None:
        with (
            patch.object(probe, "_host_preflight"),
            patch.object(probe, "_source_identity", return_value=("d" * 40, "e" * 64)),
            patch.object(probe, "_assert_owner_available"),
            patch.object(probe, "_start_owner", side_effect=probe.ProbeError("UNIT_START_FAILED")),
            patch.object(probe, "_cleanup", return_value=False),
            patch.object(probe.signal, "signal", return_value=object()),
            self.assertRaisesRegex(probe.ProbeError, "CLEANUP_INCOMPLETE"),
        ):
            probe.run_probe(acknowledged=True)

    def test_canary_is_reaped_when_pidfd_binding_fails(self) -> None:
        process = MagicMock(pid=20)
        canary = ProcessIdentity(20, 200)
        with (
            patch.object(probe.subprocess, "Popen", return_value=process),
            patch.object(probe, "identity", return_value=canary),
            patch.object(probe, "open_pidfd", side_effect=ProcessLookupError("vanished")),
            self.assertRaises(ProcessLookupError),
        ):
            probe._spawn_canary()
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=1)

    def test_target_spawn_revalidates_identity_before_open(self) -> None:
        with (
            patch.object(
                probe,
                "_validate_owner",
                side_effect=probe.ProbeError("TARGET_CGROUP_IDENTITY_DRIFT"),
            ),
            patch.object(probe.os, "open", side_effect=AssertionError("must not open")),
            self.assertRaisesRegex(probe.ProbeError, "TARGET_CGROUP_IDENTITY_DRIFT"),
        ):
            probe._spawn_target(probe_identity())

    def test_started_owner_without_captured_identity_is_still_stopped(self) -> None:
        resources = probe.ProbeResources(
            unit=f"lumi-eggcracker-probe-{'d' * 32}.service",
            owner_started=True,
            target_pidfds={},
        )
        completed = MagicMock(returncode=0)
        with (
            patch.object(probe, "_safe_run", return_value=completed) as run,
            patch.object(probe, "_load_state", return_value="not-found"),
        ):
            self.assertTrue(probe._cleanup(resources, deadline=probe.time.monotonic() + 1.0))
        self.assertEqual(
            [
                call([str(probe.SYSTEMCTL), "stop", resources.unit], timeout=2.0),
                call([str(probe.SYSTEMCTL), "reset-failed", resources.unit], timeout=2.0),
            ],
            run.call_args_list,
        )

    def test_canary_pidfd_is_closed_even_when_cleanup_signal_fails(self) -> None:
        resources = probe.ProbeResources(canary_pidfd=42, target_pidfds={})
        with (
            patch.object(probe, "_held_kill", side_effect=probe.ProbeError("PIDFD_LIVENESS_FAILED")),
            patch.object(probe.os, "close") as close,
        ):
            self.assertFalse(probe._cleanup(resources, deadline=probe.time.monotonic() + 1.0))
        close.assert_called_once_with(42)

    def test_interrupt_during_late_stages_can_never_return_success(self) -> None:
        cgroup = probe_identity()
        canary = ProcessIdentity(20, 200)
        targets = (ProcessIdentity(30, 300), ProcessIdentity(31, 301))
        process = MagicMock()

        for interrupted_stage in ("kill", "empty-proof", "canary-proof", "cleanup"):
            with self.subTest(stage=interrupted_stage):
                handlers: list[object] = []

                def register(
                    _signum: int, handler: object, bound_handlers: list[object] = handlers
                ) -> object:
                    if callable(handler):
                        bound_handlers.append(handler)
                    return object()

                def interrupt(
                    stage: str,
                    value: object,
                    bound_stage: str = interrupted_stage,
                    bound_handlers: list[object] = handlers,
                ) -> object:
                    if stage == bound_stage:
                        handler = bound_handlers[0]
                        assert callable(handler)
                        handler(15, None)
                    return value

                contexts = (
                    patch.object(probe, "_host_preflight"),
                    patch.object(probe, "_source_identity", return_value=("d" * 40, "e" * 64)),
                    patch.object(probe.secrets, "token_hex", return_value="a" * 32),
                    patch.object(probe, "_assert_owner_available"),
                    patch.object(probe, "_start_owner"),
                    patch.object(probe, "_capture_owner", return_value=cgroup),
                    patch.object(probe, "_spawn_canary", return_value=(process, canary, 40)),
                    patch.object(
                        probe,
                        "_process_cgroup",
                        side_effect=[
                            "/user.slice/session.scope",
                            *(cgroup.control_group + "/target" for _ in targets),
                        ],
                    ),
                    patch.object(probe, "_spawn_target", return_value=process),
                    patch.object(probe, "_wait_target", return_value=targets),
                    patch.object(probe, "open_pidfd", side_effect=[50, 51]),
                    patch.object(probe, "stop_pidfd", side_effect=[1_000_000, 1_000_100]),
                    patch.object(probe, "_validate_owner", return_value=Path("/target")),
                    patch.object(
                        probe,
                        "kill_path",
                        side_effect=lambda _path: interrupt("kill", (1_100_000, 1_100_100)),
                    ),
                    patch.object(
                        probe,
                        "_strict_empty",
                        side_effect=lambda *_args: interrupt("empty-proof", (2_000_000, 0, 1)),
                    ),
                    patch.object(
                        probe,
                        "_pidfd_alive",
                        side_effect=lambda _fd: interrupt("canary-proof", True),
                    ),
                    patch.object(
                        probe,
                        "_cleanup",
                        side_effect=lambda *_args, **_kwargs: interrupt("cleanup", True),
                    ),
                    patch.object(probe.signal, "signal", side_effect=register),
                    self.assertRaisesRegex(probe.ProbeError, "INTERRUPTED"),
                )
                with ExitStack() as stack:
                    for context in contexts:
                        stack.enter_context(context)
                    probe.run_probe(acknowledged=True)

    def test_public_module_has_no_network_or_install_dependency(self) -> None:
        source = Path(probe.__file__).read_text(encoding="utf-8")
        forbidden = ("import requests", "import socket", "import urllib", "pip install", "apt-get")
        self.assertFalse(any(item in source for item in forbidden))

    def test_script_wrapper_imports_the_probe_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertTrue(Path(raw).is_dir())
        self.assertTrue(probe.PROBE_RE.fullmatch(f"lumi-eggcracker-probe-{'f' * 32}.service"))

    def test_script_wrapper_refuses_top_level_import_shadowing(self) -> None:
        repository = Path(probe.__file__).resolve().parents[2]
        wrapper_source = repository / "scripts" / "containment_probe.py"
        for unexpected in ("hashlib.py", "subprocess"):
            with self.subTest(unexpected=unexpected), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                scripts = root / "scripts"
                package = root / "src" / "lumi_eggcracker"
                scripts.mkdir()
                package.mkdir(parents=True)
                wrapper = scripts / "containment_probe.py"
                wrapper.write_bytes(wrapper_source.read_bytes())
                (package / "__init__.py").write_text("", encoding="utf-8")
                (package / "containment_probe.py").write_text(
                    "def main():\n    return 0\n", encoding="utf-8"
                )
                unexpected_path = root / "src" / unexpected
                if unexpected_path.suffix:
                    unexpected_path.write_text("raise RuntimeError('executed')\n", encoding="utf-8")
                else:
                    unexpected_path.mkdir()
                    (unexpected_path / "__init__.py").write_text(
                        "raise RuntimeError('executed')\n", encoding="utf-8"
                    )

                completed = subprocess.run(
                    [sys.executable, "-I", "-S", str(wrapper)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                self.assertNotEqual(0, completed.returncode)
                self.assertEqual("", completed.stdout)
                self.assertEqual("SOURCE_IMPORT_PATH_UNQUALIFIED\n", completed.stderr)


if __name__ == "__main__":
    unittest.main()
