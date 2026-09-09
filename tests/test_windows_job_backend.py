"""Windows x64 layouts and call ordering against Python stubs, no native calls."""

import ast
import contextlib
import io
import json
import runpy
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from experiments.human_override import windows_job_backend as backend
from experiments.human_override import windows_job_probe as probe

ROOT = Path(__file__).resolve().parents[1]
APP = "F:\\synthetic\\python.exe"
CWD = "F:\\synthetic\\temp"
CONFIG = "a" * 64


class FakeKernel:
    """High-bit fake handles exercise pointer widths without OS objects."""

    def __init__(self):
        self.a = backend.make_abi()
        self.events = []
        self.fail = None
        self.error = 122
        self.job, self.process, self.thread, self.query = (0x100000001 + i for i in range(4))
        self.open_handles = set()
        self.creation = 0x123456789ABCDEF0
        self.image = APP
        self.pid = 75
        self.alive = True
        self.signaled = False
        self.exit_code = 91
        self.sizing = 256
        self.resume_count = 1
        self.on_resume = None
        self.on_create = None
        self.deleted = 0
        self.snapshot = {}
        self.api = backend.StubApi({name: self.callback(name) for name in self.a.signatures},
                                   lambda: self.error)

    def callback(self, name):
        def call(*args):
            self.events.append(name)
            if self.fail == name:
                return 0xFFFFFFFF if name in ("ResumeThread", "WaitForSingleObject") else 0
            return self.invoke(name, args)
        return call

    def ptr(self, value, kind):
        return self.a.c.cast(value, self.a.c.POINTER(kind)).contents

    def invoke(self, name, args):
        a = self.a
        if name == "CreateJobObjectW":
            if args != (None, None):
                raise ValueError("Job must be unnamed and non-inheritable")
            self.open_handles.add(self.job)
            return self.job
        if name == "SetInformationJobObject":
            if args[0] != self.job:
                raise ValueError("Wrong job")
            kind = a.ExtendedLimits if args[1] == 9 else a.CpuLimits
            value = self.ptr(args[2], kind)
            self.snapshot[args[1]] = bytes(value)
            if args[3] != a.c.sizeof(kind):
                raise ValueError("Wrong limit structure size")
            return 1
        if name == "InitializeProcThreadAttributeList":
            if args[1:3] != (1, 0):
                raise ValueError("Wrong attribute count/flags")
            self.ptr(args[3], a.SIZE_T).value = self.sizing
            return int(args[0] is not None)
        if name == "UpdateProcThreadAttribute":
            if (args[1:3] != (0, backend.JOB_LIST) or args[4:] != (8, None, None)
                    or self.ptr(args[3], a.HANDLE).value != self.job):
                raise ValueError("Atomic job list malformed")
            return 1
        if name == "DeleteProcThreadAttributeList":
            self.deleted += 1
            return None
        if name == "CreateProcessW":
            if args[2:6] != (None, None, 0, backend.CREATE_FLAGS):
                raise ValueError("Inheritance or creation flags malformed")
            startup = self.ptr(args[8], a.StartupInfoEx)
            if startup.StartupInfo.cb != 112 or not startup.lpAttributeList:
                raise ValueError("Wrong STARTUPINFOEX")
            if startup.StartupInfo.hStdOutput or startup.StartupInfo.hStdError:
                raise ValueError("Unexpected standard handle")
            self.snapshot["command"] = bytes(args[1]).decode("utf-16-le")
            self.snapshot["environment"] = bytes(args[6]).decode("utf-16-le")
            info = self.ptr(args[9], a.ProcessInformation)
            info.hProcess, info.hThread = self.process, self.thread
            info.dwProcessId, info.dwThreadId = self.pid, 76
            self.open_handles.update((self.process, self.thread))
            if self.on_create:
                self.on_create()
            return 1
        if name == "GetProcessTimes":
            creation = self.ptr(args[1], a.FileTime)
            creation.low, creation.high = self.creation & 0xFFFFFFFF, self.creation >> 32
            return 1
        if name == "GetProcessId":
            return self.pid
        if name == "QueryFullProcessImageNameW":
            data = self.image.encode("utf-16-le")
            units = (a.WORD * (len(data) // 2)).from_buffer_copy(data)
            for index, value in enumerate(units):
                args[2][index] = value
            self.ptr(args[3], a.DWORD).value = len(units)
            return 1
        if name == "ResumeThread":
            if args[0] != self.thread:
                raise ValueError("Wrong thread")
            if self.on_resume:
                self.on_resume()
            return self.resume_count
        if name == "TerminateProcess":
            if args != (self.process, 91):
                raise ValueError("Wrong termination target")
            return 1  # asynchronous dispatch, no signal yet
        if name == "GetCurrentProcess":
            return 0xFFFFFFFFFFFFFFFF
        if name == "DuplicateHandle":
            if args[:3] != (0xFFFFFFFFFFFFFFFF, self.process, 0xFFFFFFFFFFFFFFFF):
                raise ValueError("Wrong duplicate source")
            if args[4:] != (backend.QUERY_RIGHTS, 0, 0):
                raise ValueError("Observer rights/inheritance widened")
            self.ptr(args[3], a.HANDLE).value = self.query
            self.open_handles.add(self.query)
            return 1
        if name == "WaitForSingleObject":
            if args != (self.query, 0):
                raise ValueError("Wrong wait target or unbounded wait")
            return 0 if self.signaled else 258
        if name == "GetExitCodeProcess":
            self.ptr(args[1], a.DWORD).value = self.exit_code
            return 1
        if name == "CloseHandle":
            self.open_handles.remove(args[0])
            if args[0] == self.job:
                self.alive = False
            return 1
        raise ValueError(name)


class WindowsJobBackendTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeKernel()
        self.persisted = []
        self.persist_fail = None
        self.on_persist = None

        def persist(phase, identity):
            self.fake.events.append(phase)
            if self.on_persist:
                self.on_persist(phase)
            if phase == self.persist_fail:
                raise OSError("injected storage failure")
            self.persisted.append((phase, identity))
        self.owner = backend.RetainedJob(self.fake.api, persist)

    def start(self):
        return self.owner.start(APP, CWD, 1, CONFIG)

    def test_abi_layouts_and_offsets(self):
        a = self.fake.a
        expected = {"FileTime": 8, "BasicLimits": 64, "IoCounters": 48,
                    "ExtendedLimits": 144, "CpuLimits": 8, "StartupInfo": 104,
                    "StartupInfoEx": 112, "ProcessInformation": 24}
        for name, size in expected.items():
            self.assertEqual(a.c.sizeof(getattr(a, name)), size, name)
        self.assertEqual(a.BasicLimits.LimitFlags.offset, 16)
        self.assertEqual(a.BasicLimits.MinimumWorkingSetSize.offset, 24)
        self.assertEqual(a.BasicLimits.ActiveProcessLimit.offset, 40)
        self.assertEqual(a.ExtendedLimits.JobMemoryLimit.offset, 120)
        self.assertEqual(a.StartupInfo.hStdInput.offset, 80)
        self.assertEqual(a.StartupInfoEx.lpAttributeList.offset, 104)
        self.assertEqual(a.ProcessInformation.dwProcessId.offset, 16)
        self.assertEqual(a.c.sizeof(a.WORD), 2)
        self.assertEqual(a.c.sizeof(a.DWORD), 4)

    def test_api_pointer_widths_and_signatures(self):
        api, a = self.fake.api, self.fake.a
        self.assertEqual(a.c.sizeof(api.CreateJobObjectW.restype), 8)
        self.assertEqual(a.c.sizeof(api.GetCurrentProcess.restype), 8)
        self.assertEqual(a.c.sizeof(api.UpdateProcThreadAttribute.argtypes[2]), 8)
        self.assertEqual(a.c.sizeof(api.CreateProcessW.argtypes[4]), 4)
        self.assertEqual(api.DeleteProcThreadAttributeList.restype, None)
        self.assertNotIn("OpenProcess", a.signatures)
        with self.assertRaises(TypeError):
            api.CloseHandle()

    def test_non_native_constructor_refusal(self):
        for value in (None, object(), {}, self.fake):
            with self.assertRaises(TypeError):
                backend.RetainedJob(value, lambda *_: None)
        with self.assertRaises(TypeError):
            backend.StubApi({}, lambda: 0)
        with self.assertRaises(TypeError):
            backend.StubFunction(len, None, ())
        with self.assertRaises(PermissionError):
            backend.native_backend(authorized=True)

    def test_atomic_creation_persistence_and_minimal_environment(self):
        identity = self.start()
        self.assertEqual(identity.creation_time, self.fake.creation)
        self.assertEqual(self.owner.process, self.fake.process)
        events = self.fake.events
        ordered = ["START_INTENT", "CreateJobObjectW", "SetInformationJobObject",
                   "UpdateProcThreadAttribute", "CreateProcessW", "IDENTIFIED_SUSPENDED",
                   "ResumeThread", "RUNNING", "DeleteProcThreadAttributeList"]
        self.assertEqual([events.index(name) for name in ordered],
                         sorted(events.index(name) for name in ordered))
        self.assertEqual(self.fake.deleted, 1)
        self.assertIn('-I -S -B -c "import time; time.sleep(60)"', self.fake.snapshot["command"])
        self.assertEqual(self.fake.snapshot["environment"],
                         f"TEMP={CWD}\0TMP={CWD}\0TMPDIR={CWD}\0\0")

    def test_job_memory_cpu_child_and_breakaway_limits(self):
        self.start()
        a = self.fake.a
        limits = a.ExtendedLimits.from_buffer_copy(self.fake.snapshot[9])
        cpu = a.CpuLimits.from_buffer_copy(self.fake.snapshot[15])
        self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2208)
        self.assertEqual(limits.BasicLimitInformation.ActiveProcessLimit, 1)
        self.assertEqual(limits.JobMemoryLimit, 268435456)
        self.assertEqual((cpu.ControlFlags, cpu.CpuRate), (5, 1000))

    def test_startup_failures_close_owned_handles_never_resume(self):
        for name in ("CreateJobObjectW", "SetInformationJobObject",
                     "InitializeProcThreadAttributeList", "UpdateProcThreadAttribute",
                     "CreateProcessW", "GetProcessTimes", "GetProcessId",
                     "QueryFullProcessImageNameW"):
            with self.subTest(name=name):
                self.setUp()
                self.fake.fail = name
                with self.assertRaises((OSError, ValueError)):
                    self.start()
                self.assertNotIn("ResumeThread", self.fake.events)
                self.assertFalse(self.fake.open_handles)
                self.assertTrue(self.owner.stopped)

    def test_attribute_size_is_bounded(self):
        for size in (0, 65537):
            self.setUp()
            self.fake.sizing = size
            with self.assertRaises(ValueError):
                self.start()
            self.assertNotIn("CreateProcessW", self.fake.events)
            self.assertFalse(self.fake.open_handles)

    def test_identity_mismatch_closes_suspended_child(self):
        self.fake.image = "F:\\synthetic\\other.exe"
        with self.assertRaises(ValueError):
            self.start()
        self.assertNotIn("ResumeThread", self.fake.events)
        self.assertFalse(self.fake.alive)
        self.assertFalse(self.fake.open_handles)

    def test_persistence_failures_inhibit_and_clean_up(self):
        for phase in ("START_INTENT", "IDENTIFIED_SUSPENDED", "RUNNING"):
            self.setUp()
            self.persist_fail = phase
            with self.assertRaises(OSError):
                self.start()
            self.assertFalse(self.fake.open_handles)
            if phase != "RUNNING":
                self.assertNotIn("ResumeThread", self.fake.events)
            with self.assertRaises(ValueError):
                self.start()

    def test_stop_during_identity_persistence_prevents_resume(self):
        def interleave(phase):
            if phase == "IDENTIFIED_SUSPENDED":
                self.owner.stop()
        self.on_persist = interleave
        with self.assertRaises(ValueError):
            self.start()
        self.assertNotIn("ResumeThread", self.fake.events)
        self.assertFalse(self.fake.open_handles)

    def test_stop_during_create_prevents_resume(self):
        self.fake.on_create = self.owner.stop
        with self.assertRaises(ValueError):
            self.start()
        self.assertNotIn("ResumeThread", self.fake.events)
        self.assertFalse(self.fake.open_handles)

    def test_stop_dispatch_not_exit_and_persistence_failure_still_dispatches(self):
        identity = self.start()
        observer = self.owner.query_observer()
        self.assertEqual(observer.observe(identity), "STUB_RUNNING")
        self.persist_fail = "STOP_REQUESTED"
        self.assertEqual(self.owner.stop(), "STUB_STOP_DURABILITY_UNCONFIRMED")
        self.assertEqual(observer.observe(identity), "STUB_RUNNING")
        self.fake.signaled = True
        self.assertEqual(observer.observe(identity), "STUB_VERIFIED_PRIMARY_EXIT")

    def test_stop_checks_identity_and_never_reopens(self):
        self.start()
        self.fake.creation += 1
        self.assertEqual(self.owner.stop(), "UNKNOWN")
        self.assertNotIn("TerminateProcess", self.fake.events)
        self.owner.process = None  # simulate lost reference, not real handle cleanup
        self.assertEqual(self.owner.stop(), "UNKNOWN")

    def test_stop_failure_is_unknown_and_latched(self):
        self.start()
        self.fake.fail = "TerminateProcess"
        self.assertEqual(self.owner.stop(), "UNKNOWN")
        self.assertTrue(self.owner.stopped)
        with self.assertRaises(ValueError):
            self.start()

    def test_unexpected_suspend_count_closes_job(self):
        for count in (0, 2, 0xFFFFFFFF):
            self.setUp()
            self.fake.resume_count = count
            with self.assertRaises(ValueError):
                self.start()
            self.assertFalse(self.fake.open_handles)
            self.assertFalse(self.fake.alive)

    def test_observer_requires_identity_liveness_signal_and_query_success(self):
        identity = self.start()
        observer = self.owner.query_observer()
        self.fake.signaled = True
        self.assertEqual(observer.observe(identity), "UNKNOWN")
        self.fake.signaled = False
        self.assertEqual(observer.observe(replace(identity, generation=2)), "UNKNOWN")
        self.assertEqual(observer.observe(identity), "STUB_RUNNING")
        self.fake.signaled = True
        self.fake.fail = "GetExitCodeProcess"
        self.assertEqual(observer.observe(identity), "UNKNOWN")
        self.fake.fail = None
        self.fake.exit_code = 259
        self.assertEqual(observer.observe(identity), "STUB_VERIFIED_PRIMARY_EXIT")
        self.fake.fail = "WaitForSingleObject"
        self.assertEqual(observer.observe(identity), "UNKNOWN")
        self.owner.query_handles.clear()
        self.assertEqual(observer.observe(identity), "UNKNOWN")

    def test_duplicate_failure_does_not_issue_observer(self):
        self.start()
        self.fake.fail = "DuplicateHandle"
        with self.assertRaises(OSError):
            self.owner.query_observer()
        self.assertFalse(self.owner.query_handles)

    def test_observation_holds_same_lock_as_close(self):
        identity = self.start()
        observer = self.owner.query_observer()

        class CheckedLock:
            held = False

            def __enter__(lock):
                lock.held = True

            def __exit__(lock, *_args):
                lock.held = False

        lock = CheckedLock()
        self.owner.lock = lock
        original = self.owner._identity

        def checked_identity(*args):
            self.assertTrue(lock.held, "Query must serialize against owned-handle close")
            return original(*args)

        with patch.object(self.owner, "_identity", checked_identity):
            self.assertEqual(observer.observe(identity), "STUB_RUNNING")

    def test_close_once_and_failed_cleanup_is_not_success(self):
        self.start()
        self.owner.query_observer()
        self.fake.fail = "CloseHandle"
        self.assertEqual(self.owner.close(), "UNKNOWN")
        self.assertEqual(len(self.fake.open_handles), 4)
        self.fake.fail = None
        self.assertEqual(self.owner.close(), "UNKNOWN")  # history remains disclosed
        self.assertFalse(self.fake.open_handles)
        count = self.fake.events.count("CloseHandle")
        self.owner.close()
        self.assertEqual(self.fake.events.count("CloseHandle"), count)

    def test_cleanup_interrupt_still_attempts_other_handles(self):
        self.start()
        original = self.fake.api.CloseHandle.callback

        def interrupted_close(handle):
            if handle == self.fake.job:
                raise KeyboardInterrupt("injected close interruption")
            return original(handle)

        self.fake.api.CloseHandle.callback = interrupted_close
        self.assertEqual(self.owner.close(), "UNKNOWN")
        self.assertEqual(self.fake.open_handles, {self.fake.job})
        self.assertEqual(self.owner.cleanup_errors, ["job"])
        self.fake.api.CloseHandle.callback = original
        self.owner.close()
        self.assertFalse(self.fake.open_handles)

    def test_cleanup_interrupt_does_not_mask_start_failure(self):
        original = self.fake.api.CloseHandle.callback

        def interrupted_close(handle):
            if handle == self.fake.job:
                raise KeyboardInterrupt("injected close interruption")
            return original(handle)

        self.fake.api.CloseHandle.callback = interrupted_close
        self.persist_fail = "IDENTIFIED_SUSPENDED"
        with self.assertRaisesRegex(OSError, "storage failure"):
            self.start()
        self.assertEqual(self.fake.open_handles, {self.fake.job})

    def test_invalid_input_before_any_api_call(self):
        for path in ("python.exe", "C:\\other.exe", "F:\\x\\..\\y", 'F:\\a"b.exe', "F:\\a\0"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.owner.start(path, CWD, 1, CONFIG)
        for generation in (True, 0, -1, 2**63):
            with self.assertRaises(ValueError):
                self.owner.start(APP, CWD, generation, CONFIG)
        self.assertEqual(self.fake.events, [])

    def test_import_and_cli_have_no_native_loader(self):
        for name in ("windows_job_backend.py", "windows_job_probe.py"):
            path = ROOT / "experiments" / "human_override" / name
            tree = ast.parse(path.read_text(encoding="utf-8"))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
            self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in (
                "WinDLL", "CDLL", "windll", "cdll", "LoadLibrary", "Popen", "system")
                for node in ast.walk(tree)))
        with patch.object(sys, "argv", ["windows_job_probe.py"]), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as result:
                runpy.run_path(str(ROOT / probe.SOURCE_PATHS[1]), run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["status"], "SOURCE_ONLY_NOT_EXECUTABLE")
        self.assertFalse(data["native_api_calls"])
        self.assertEqual(len(data["source_sha256"]), 5)
        self.assertEqual(data, probe.proposal())

    def test_all_native_cli_modes_refuse(self):
        for mode in ("native-controller", "native-observer", "native-supervisor"):
            with contextlib.redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as result:
                    probe.main(["--mode", mode])
            self.assertEqual(result.exception.code, 2)
            self.assertIn("SOURCE_ONLY", error.getvalue())


if __name__ == "__main__":
    unittest.main()
