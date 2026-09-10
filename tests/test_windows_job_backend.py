"""Windows x64 layouts and call ordering against Python stubs, no native calls."""

import ast
import contextlib
import hashlib
import io
import json
import ntpath
import runpy
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from experiments.human_override import windows_job_backend as backend
from experiments.human_override import windows_job_probe as probe
from scripts.verify_release import FORBIDDEN

ROOT = Path(__file__).resolve().parents[1]
APP = "G:\\synthetic\\python.exe"
CWD = "G:\\synthetic\\temp"
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
            if args[2:6] != (None, None, 0, 0x08080404):
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
                    "ExtendedLimits": 144, "CpuLimits": 8, "BasicUiRestrictions": 4,
                    "StartupInfo": 104,
                    "StartupInfoEx": 112, "ProcessInformation": 24, "FileInformation": 52}
        for name, size in expected.items():
            self.assertEqual(a.c.sizeof(getattr(a, name)), size, name)
        self.assertEqual(a.BasicLimits.LimitFlags.offset, 16)
        self.assertEqual(a.BasicLimits.MinimumWorkingSetSize.offset, 24)
        self.assertEqual(a.BasicLimits.ActiveProcessLimit.offset, 40)
        self.assertEqual(a.ExtendedLimits.JobMemoryLimit.offset, 120)
        self.assertEqual(a.StartupInfo.hStdInput.offset, 80)
        self.assertEqual(a.StartupInfoEx.lpAttributeList.offset, 104)
        self.assertEqual(a.ProcessInformation.dwProcessId.offset, 16)
        self.assertEqual(a.FileInformation.write.offset, 20)
        self.assertEqual(a.FileInformation.volume.offset, 28)
        self.assertEqual(a.FileInformation.index_low.offset, 48)
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

    def test_retained_launch_rejects_creation_flag_injection(self):
        for flags in (backend.CREATE_FLAGS | 0x01000000, 0, True, 0x08080404 + 1):
            with self.subTest(flags=flags):
                self.setUp()
                with patch.object(backend, "CREATE_FLAGS", flags), self.assertRaises(ValueError):
                    self.start()
                self.assertNotIn("CreateProcessW", self.fake.events)
                self.assertNotIn("ResumeThread", self.fake.events)
                self.assertFalse(self.fake.open_handles)

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
        self.fake.image = "G:\\synthetic\\other.exe"
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
        for path in ("python.exe", "C:\\other.exe", "G:\\x\\..\\y", 'G:\\a"b.exe',
                     "G:\\a\0", "F:relative.exe", "G:relative.exe"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.owner.start(path, CWD, 1, CONFIG)
        for generation in (True, 0, -1, 2**63):
            with self.assertRaises(ValueError):
                self.owner.start(APP, CWD, generation, CONFIG)
        self.assertEqual(self.fake.events, [])

    def test_selected_source_obeys_existing_public_artifact_filter(self):
        for name in probe.SOURCE_PATHS:
            content = (ROOT / name).read_text(encoding="utf-8").lower()
            self.assertEqual([item for item in FORBIDDEN if item in content], [], name)

    def test_import_and_cli_have_no_reachable_native_loader(self):
        for name in ("windows_job_backend.py", "windows_job_probe.py"):
            path = ROOT / "experiments" / "human_override" / name
            tree = ast.parse(path.read_text(encoding="utf-8"))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
            self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in (
                "CDLL", "windll", "cdll", "LoadLibrary", "Popen", "system")
                for node in ast.walk(tree)))
            loaders = [node for node in ast.walk(tree)
                       if isinstance(node, ast.Attribute) and node.attr == "WinDLL"]
            if name == "windows_job_backend.py":
                native = next(node for node in tree.body
                              if isinstance(node, ast.ClassDef) and node.name == "NativeApi")
                constructor = next(node for node in native.body
                                   if isinstance(node, ast.FunctionDef) and node.name == "__init__")
                self.assertEqual(len(loaders), 2)
                for loader in loaders:
                    self.assertIn(loader, list(ast.walk(constructor)))
                dll_calls = [node for node in ast.walk(constructor)
                             if isinstance(node, ast.Call) and node.func in loaders]
                self.assertEqual({node.args[0].value for node in dll_calls},
                                 {"kernel32.dll", "advapi32.dll"})
                for call in dll_calls:
                    self.assertEqual({item.arg: item.value.value for item in call.keywords},
                                     {"use_last_error": True, "winmode": 0x800})
                gate = constructor.body[0]
                self.assertIsInstance(gate, ast.Expr)
                self.assertEqual(gate.value.func.id, "native_backend")
            else:
                self.assertEqual(loaders, [])
        with patch("ctypes.WinDLL", side_effect=AssertionError("Native loader called"), create=True):
            runpy.run_path(str(ROOT / probe.SOURCE_PATHS[0]))
        with (patch.object(backend, "make_abi", side_effect=AssertionError("Gate bypass")),
              self.assertRaises(PermissionError)):
            backend.NativeApi()
        with (patch.object(sys, "argv", ["windows_job_probe.py"]),
              contextlib.redirect_stdout(io.StringIO()) as out,
              self.assertRaises(SystemExit) as result):
            runpy.run_path(str(ROOT / probe.SOURCE_PATHS[1]), run_name="__main__")
        self.assertEqual(result.exception.code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["status"], "SOURCE_ONLY_NOT_EXECUTABLE")
        self.assertFalse(data["native_api_calls"])
        self.assertEqual(len(data["source_sha256"]), 5)
        self.assertEqual(data, probe.proposal())

    def test_all_native_cli_modes_refuse(self):
        for mode in ("native-controller", "native-observer", "native-supervisor"):
            with (contextlib.redirect_stderr(io.StringIO()) as error,
                  self.assertRaises(SystemExit) as result):
                probe.main(["--mode", mode])
            self.assertEqual(result.exception.code, 2)
            self.assertIn("SOURCE_ONLY", error.getvalue())


class RoleKernel:
    """In-memory separate handle tables and pipes; no native process exists."""

    def __init__(self):
        self.a = backend.make_abi()
        self.tables = {"supervisor": {}}
        self.roles = {}
        self.objects = {}
        self.next_id = 1
        self.next_handle = 0x100000001
        self.attributes = {}
        self.events = []
        self.tick = 0
        self.fail = None
        self.host_job = False
        self.ancestor_limits = self.a.ExtendedLimits()
        self.ancestor_ui = 0
        self.ancestor_queries = []
        self.membership_checks = []
        self.ordinal = 0
        self.fail_ordinal = None
        self.reject_dead_identity = False
        self.partial = None
        self.file_contents = {}
        self.bootstraps = {}
        self.pipe_writers = set()
        self.errors = {}
        self.token_elevation = 0
        self.token_length = 4

    def ptr(self, pointer, kind):
        return self.a.c.cast(pointer, self.a.c.POINTER(kind)).contents

    def new(self, owner, kind, **fields):
        identity = self.next_id
        self.next_id += 1
        self.objects[identity] = {"kind": kind, **fields}
        return self.handle(owner, identity)

    def handle(self, role, identity, rights=0x1FFFFF, inherit=False):
        handle = self.next_handle
        self.next_handle += 1
        self.tables[role][handle] = (identity, rights, inherit)
        return handle

    def object(self, role, handle):
        return self.objects[self.tables[role][handle][0]]

    def close(self, role, handle):
        self.pipe_writers.discard((role, handle))
        identity, _, _ = self.tables[role].pop(handle)
        obj = self.objects[identity]
        if obj["kind"] == "job" and 9 in obj and not any(
                identity == entry[0] for table in self.tables.values() for entry in table.values()):
            limits = self.a.ExtendedLimits.from_buffer_copy(obj[9])
            if not limits.BasicLimitInformation.LimitFlags & 0x2000:
                return
            for process_id, process in list(self.objects.items()):
                if process["kind"] == "process" and identity in process["jobs"]:
                    self.kill(process_id)

    def kill(self, identity):
        process = self.objects[identity]
        process["alive"] = False
        role = process["role"]
        if role in self.tables:
            for handle in list(self.tables[role]):
                self.close(role, handle)

    def factory(self, role, _process):
        return backend.StubApi({name: self.callback(role, name) for name in self.a.signatures},
                               lambda: self.errors.get(role, 122))

    def callback(self, role, name):
        def call(*args):
            self.events.append((role, name))
            self.ordinal += 1
            if self.fail == name or self.fail_ordinal == self.ordinal:
                if name == "ResumeThread":
                    return 0xFFFFFFFF
                return 0
            return self.invoke(role, name, args)
        return call

    def invoke(self, role, name, args):
        a = self.a
        if name == "GetCurrentProcess":
            return 0xFFFFFFFFFFFFFFFF
        if name == "OpenProcessToken":
            if args[:2] != (2**64 - 1, 0x0008):
                raise ValueError("Only current process TOKEN_QUERY is selected")
            self.ptr(args[2], a.HANDLE).value = self.new(role, "token")
            return 1
        if name == "GetTokenInformation":
            if (args[1] != 20 or args[3] != 4
                    or self.object(role, args[0])["kind"] != "token"):
                raise ValueError("Only fixed four-byte TokenElevation is selected")
            self.ptr(args[2], a.DWORD).value = self.token_elevation
            self.ptr(args[4], a.DWORD).value = self.token_length
            return 1
        if name == "CreateFileW":
            path = bytes(args[0]).decode("utf-16-le").rstrip("\0")
            content = self.file_contents.get(ntpath.normcase(path))
            return self.new(role, "artifact", path=path, content=content, offset=0)
        if name == "GetFileInformationByHandle":
            obj = self.object(role, args[0])
            info = self.ptr(args[1], a.FileInformation)
            info.attributes = 0x10 if obj["content"] is None else 0
            info.size_low = 0 if obj["content"] is None else len(obj["content"])
            info.volume, info.index_low = 1, self.tables[role][args[0]][0]
            return 1
        if name == "GetFinalPathNameByHandleW":
            path = self.object(role, args[0])["path"]
            units = backend.wide(a, path)
            for index, value in enumerate(units):
                args[1][index] = value
            return len(units) - 1
        if name == "ReadFile" and self.object(role, args[0])["kind"] == "artifact":
            obj = self.object(role, args[0])
            data = obj["content"][obj["offset"]:obj["offset"] + args[2]]
            obj["offset"] += len(data)
            a.c.memmove(args[1], data, len(data))
            self.ptr(args[3], a.DWORD).value = len(data)
            return 1
        if name == "IsProcessInJob":
            if args[0] == 2**64 - 1 and args[1] is None:
                answer = self.host_job
            else:
                process = self.object(role, args[0])
                job = self.tables[role][args[1]][0]
                self.membership_checks.append((process["role"], job, process["resumed"]))
                answer = job in process["jobs"]
            self.ptr(args[2], a.c.c_int32).value = int(answer)
            return 1
        if name == "CreateJobObjectW":
            return self.new(role, "job")
        if name == "SetInformationJobObject":
            obj = self.object(role, args[0])
            kind = a.ExtendedLimits if args[1] == 9 else a.CpuLimits
            obj[args[1]] = bytes(self.ptr(args[2], kind))
            return 1
        if name == "TerminateJobObject":
            identity = self.tables[role][args[0]][0]
            for process_id, process in list(self.objects.items()):
                if process["kind"] == "process" and identity in process["jobs"]:
                    self.kill(process_id)
            return 1
        if name == "QueryInformationJobObject":
            if args[0] is None:
                if not self.host_job or args[1] not in (4, 9):
                    raise ValueError("Unselected NULL job query")
                self.ancestor_queries.append((role, args[1]))
                info = (a.BasicUiRestrictions(self.ancestor_ui) if args[1] == 4
                        else self.ancestor_limits)
                if args[3] != a.c.sizeof(info):
                    raise ValueError("Wrong immediate job query size")
                a.c.memmove(args[2], a.c.byref(info), a.c.sizeof(info))
                self.ptr(args[4], a.DWORD).value = a.c.sizeof(info)
                return 1
            if args[1] != 1 or args[3] != a.c.sizeof(a.BasicAccounting):
                raise ValueError("Only fixed basic accounting query allowed")
            identity = self.tables[role][args[0]][0]
            info = self.ptr(args[2], a.BasicAccounting)
            processes = [(process_id, process) for process_id, process in self.objects.items()
                         if process["kind"] == "process" and identity in process["jobs"]]
            info.TotalProcesses = len(processes)
            info.ActiveProcesses = sum(
                process["alive"] or any(process_id == entry[0] or
                                        (self.objects[entry[0]]["kind"] == "thread" and
                                         self.objects[entry[0]]["process"] == process_id)
                                        for table in self.tables.values() for entry in table.values())
                for process_id, process in processes)
            self.ptr(args[4], a.DWORD).value = a.c.sizeof(info)
            return 1
        if name == "CreatePipe":
            reader = self.new(role, "pipe", data=bytearray())
            writer = self.handle(role, self.tables[role][reader][0])
            self.pipe_writers.add((role, writer))
            self.ptr(args[0], a.HANDLE).value = reader
            self.ptr(args[1], a.HANDLE).value = writer
            return 1
        if name == "InitializeProcThreadAttributeList":
            self.ptr(args[3], a.SIZE_T).value = 256
            if args[0] is not None:
                self.attributes[role] = {}
            return int(args[0] is not None)
        if name == "UpdateProcThreadAttribute":
            values = a.c.cast(args[3], a.c.POINTER(a.HANDLE))
            self.attributes[role][args[2]] = [values[i] for i in range(args[4] // 8)]
            return 1
        if name == "DeleteProcThreadAttributeList":
            return None
        if name == "DuplicateHandle":
            identity, rights, _ = self.tables[role][args[1]]
            destination = role if args[2] == 0xFFFFFFFFFFFFFFFF else self.object(role, args[2])["role"]
            selected = rights if args[6] == 2 else args[4]
            if selected & rights != selected:
                raise ValueError("Rights escalation")
            handle = self.handle(destination, identity, selected, bool(args[5]))
            if (role, args[1]) in self.pipe_writers:
                self.pipe_writers.add((destination, handle))
            self.ptr(args[3], a.HANDLE).value = handle
            return 1
        if name == "CreateProcessW":
            command = bytes(args[1]).decode("utf-16-le")
            if "native-observer" in command:
                child = "observer"
            elif "native-controller" in command:
                child = "controller"
            else:
                child = "target" if role == "controller" else "canary"
            if child in ("controller", "observer"):
                self.bootstraps[child] = command.split("--bootstrap ")[1].rstrip("\0")
            self.tables[child] = {}
            attrs = self.attributes[role]
            inherited = attrs.get(backend.HANDLE_LIST, [])
            if bool(args[4]) != bool(inherited) or args[5] != 0x08080404:
                raise ValueError("Wrong atomic launch flags")
            for handle in inherited:
                entry = self.tables[role][handle]
                if not entry[2] or self.objects[entry[0]]["kind"] == "job":
                    raise ValueError("Invalid inheritance")
                self.tables[child][handle] = entry
                if (role, handle) in self.pipe_writers:
                    self.pipe_writers.add((child, handle))
            jobs = [self.tables[role][handle][0] for handle in attrs[backend.JOB_LIST]]
            if role in self.roles:
                jobs = self.objects[self.roles[role]]["jobs"] + jobs
            for job in jobs:
                limits = a.ExtendedLimits.from_buffer_copy(self.objects[job][9])
                active = sum(1 for identity, obj in self.objects.items()
                             if obj["kind"] == "process" and job in obj["jobs"]
                             and (obj["alive"] or any(identity == entry[0]
                                  for table in self.tables.values() for entry in table.values())))
                if (limits.BasicLimitInformation.LimitFlags & 8
                        and active >= limits.BasicLimitInformation.ActiveProcessLimit):
                    return 0
            process = self.new(role, "process", role=child, jobs=jobs, alive=True,
                               resumed=False, image=bytes(args[0]).decode("utf-16-le").rstrip("\0"))
            identity = self.tables[role][process][0]
            self.roles[child] = identity
            thread = self.new(role, "thread", process=identity)
            info = self.ptr(args[9], a.ProcessInformation)
            info.hProcess, info.hThread, info.dwProcessId = process, thread, identity
            return 1
        if name == "ResumeThread":
            process = self.objects[self.object(role, args[0])["process"]]
            process["resumed"] = True
            process["resumed_at"] = self.tick
            return 1
        if name == "GetProcessId":
            return self.tables[role][args[0]][0]
        if name == "GetProcessTimes":
            if self.reject_dead_identity and not self.object(role, args[0])["alive"]:
                return 0
            self.ptr(args[1], a.FileTime).low = 100 + self.tables[role][args[0]][0]
            return 1
        if name == "QueryFullProcessImageNameW":
            if self.reject_dead_identity and not self.object(role, args[0])["alive"]:
                return 0
            data = self.object(role, args[0])["image"].encode("utf-16-le")
            units = (a.WORD * (len(data) // 2)).from_buffer_copy(data)
            for i, value in enumerate(units):
                args[2][i] = value
            self.ptr(args[3], a.DWORD).value = len(units)
            return 1
        if name == "WaitForSingleObject":
            return 258 if self.object(role, args[0])["alive"] else 0
        if name == "GetExitCodeProcess":
            self.ptr(args[1], a.DWORD).value = 91
            return 1
        if name == "TerminateProcess":
            identity, rights, _ = self.tables[role][args[0]]
            if not rights & 1:
                raise ValueError("Query handle cannot terminate")
            self.kill(identity)
            return 1
        if name in ("WriteFile", "ReadFile", "PeekNamedPipe"):
            data = self.object(role, args[0])["data"]
            if name == "PeekNamedPipe":
                identity = self.tables[role][args[0]][0]
                if not data and not any(self.tables[owner][handle][0] == identity
                                        for owner, handle in self.pipe_writers):
                    self.errors[role] = 109
                    return 0
                self.ptr(args[4], a.DWORD).value = len(data)
            elif name == "WriteFile":
                data.extend(a.c.string_at(args[1], args[2]))
                self.ptr(args[3], a.DWORD).value = args[2]
            else:
                chunk = bytes(data[:args[2]])
                del data[:args[2]]
                a.c.memmove(args[1], chunk, len(chunk))
                self.ptr(args[3], a.DWORD).value = len(chunk)
            if name == self.partial:
                self.ptr(args[3], a.DWORD).value = 1
            return 1
        if name == "CloseHandle":
            self.close(role, args[0])
            return 1
        raise ValueError(name)


class CompleteQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "python.exe").write_bytes(b"synthetic executable, never run")
        self.inventory = backend.runtime_inventory(root, ["python.exe"])
        self.kernel = RoleKernel()
        self.config = {"application": APP, "cwd": CWD,
                       "source": "G:\\synthetic\\windows_job_probe.py", "generation": 1,
                       "case": "human_stop"}

    def prepare(self, case="human_stop"):
        self.config["case"] = case
        self.grant = {"authority": "STUB_ONLY", "source_sha256": backend.source_digest(),
                      "config_sha256": hashlib.sha256(backend.bounded_json(self.config)).hexdigest(),
                      "runtime_sha256": hashlib.sha256(backend.bounded_json(self.inventory)).hexdigest()}

        def advance(amount):
            self.kernel.tick += amount
            for identity, obj in list(self.kernel.objects.items()):
                if (obj["kind"] == "process" and obj["resumed"] and obj["alive"]
                        and self.kernel.tick >= obj["resumed_at"] + 60 * backend.SECOND):
                    self.kernel.kill(identity)

        def persist(phase, _identity):
            if ((case == "identity_failure" and phase == "IDENTIFIED_SUSPENDED")
                    or (case == "stop_persistence_failure" and phase == "STOP_REQUESTED")):
                raise OSError("Injected persistence failure")

        self.hooks = (lambda role, process: self.kernel.factory(role, process),
                      lambda: self.kernel.tick, advance, persist)
        return backend.StubQualification(self.grant, dict(self.grant), self.config,
                                         self.inventory, *self.hooks)

    def test_connected_cases_truthful_exit_control_and_cleanup(self):
        for case in backend.CASES:
            with self.subTest(case=case):
                self.kernel = RoleKernel()
                run = self.prepare(case)
                result = run.run()
                expected = ("STUB_MATCHED_LIVE_CONTROL" if case == "no_stop_control" else
                            "UNKNOWN" if case in ("identity_failure", "suspended_stop",
                                                  "stop_persistence_failure", "observer_loss",
                                                  "supervisor_loss") else "STUB_EARLY_PRIMARY_EXIT")
                self.assertEqual(result["outcome"], expected)
                self.assertLessEqual(result["evidence_bytes"], 65536)
                self.assertEqual(result["restart_safety"], "UNQUALIFIED")
                if case == "supervisor_loss":
                    self.assertFalse(result["canary_live_before_cleanup"])
                    self.assertFalse(self.kernel.objects[self.kernel.roles["canary"]]["alive"])
                self.assertFalse(any(self.kernel.tables.values()), self.kernel.tables)
                with self.assertRaises(ValueError):
                    run.run()

    def test_grant_config_hash_failures_before_any_api_call(self):
        self.prepare()
        for field in self.grant:
            changed = dict(self.grant)
            changed[field] = "0" * 64
            with self.assertRaises((ValueError, PermissionError)):
                backend.StubQualification(changed, self.grant, self.config,
                                          self.inventory, *self.hooks)
        self.assertEqual(self.kernel.events, [])

    def test_runtime_json_roundtrip_and_changed_extra_missing_entries(self):
        restored = json.loads(backend.bounded_json(self.inventory))
        self.assertEqual(backend.verify_runtime_inventory(restored), restored)
        root = Path(self.temp.name)
        (root / "extra.py").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            backend.verify_runtime_inventory(restored)
        (root / "extra.py").unlink()
        (root / "python.exe").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            backend.verify_runtime_inventory(restored)
        (root / "python.exe").unlink()
        with self.assertRaises(FileNotFoundError):
            backend.verify_runtime_inventory(restored)

    def test_aliases_and_malformed_bounds_refuse(self):
        for name in ("../x", ".", "CON", "nul.txt", "CONIN$", "a.", "a ", "a\x01", "a:b"):
            with self.assertRaises(ValueError):
                backend._relative(name)
        with self.assertRaises(ValueError):
            backend.runtime_inventory(self.temp.name, ["python.exe", "PYTHON.EXE"])
        with self.assertRaises(ValueError):
            backend.bounded_json("a" * 1025)

    def test_evidence_bounds_and_tampering(self):
        evidence = backend.BoundedEvidence()
        for _ in range(128):
            evidence.record("supervisor", "fixed", 1, 0, "STUB")
        with self.assertRaises(ValueError):
            evidence.record("supervisor", "fixed", 1, 0, "STUB")
        evidence.bytes_written = 0
        with self.assertRaises(ValueError):
            evidence.finish()

    def test_limit_and_creation_failure_no_fallback_or_resume(self):
        for operation in ("SetInformationJobObject", "CreateProcessW", "UpdateProcThreadAttribute"):
            self.kernel = RoleKernel()
            run = self.prepare()
            self.kernel.fail = operation
            self.assertEqual(run.run()["outcome"], "UNKNOWN")
            self.assertNotIn("ResumeThread", [name for _, name in self.kernel.events])
            self.assertFalse(any(self.kernel.tables.values()))

    def test_supervisor_preexisting_job_refuses_without_launch(self):
        run = self.prepare()
        self.kernel.host_job = True
        self.assertEqual(run.run()["outcome"], "UNKNOWN")
        self.assertEqual([name for _, name in self.kernel.events], ["GetCurrentProcess", "IsProcessInJob"])

    def test_exact_query_only_transfer_and_nested_resource_arguments(self):
        run = self.prepare()
        run.setup()
        run.observer.step(run.now())
        handle = run.observer.handle
        self.assertEqual(self.kernel.tables["observer"][handle][1:], (backend.QUERY_RIGHTS, False))
        self.assertNotIn(handle, self.kernel.tables["controller"])
        target = self.kernel.objects[self.kernel.roles["target"]]
        observer = self.kernel.objects[self.kernel.roles["observer"]]
        canary = self.kernel.objects[self.kernel.roles["canary"]]
        self.assertEqual(len(target["jobs"]), 2)
        self.assertEqual(len(observer["jobs"]), 2)
        self.assertEqual(target["jobs"][0], observer["jobs"][0])
        self.assertNotEqual(target["jobs"][1], observer["jobs"][1])
        self.assertNotIn(canary["jobs"][0], target["jobs"])
        outer = self.kernel.objects[target["jobs"][0]]
        limits = self.kernel.a.ExtendedLimits.from_buffer_copy(outer[9])
        self.assertEqual(limits.BasicLimitInformation.ActiveProcessLimit, 3)
        self.assertEqual(limits.JobMemoryLimit, 640 * 1024 * 1024)
        self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2208)
        for job, memory, rate in ((target["jobs"][1], 256, 5000),
                                  (observer["jobs"][1], 128, 2500),
                                  (canary["jobs"][0], 128, 500)):
            obj = self.kernel.objects[job]
            selected = self.kernel.a.ExtendedLimits.from_buffer_copy(obj[9])
            cpu = self.kernel.a.CpuLimits.from_buffer_copy(obj[15])
            self.assertEqual(selected.BasicLimitInformation.LimitFlags, 0x2208)
            self.assertEqual(selected.BasicLimitInformation.ActiveProcessLimit, 1)
            self.assertEqual(selected.JobMemoryLimit, memory * 1024 * 1024)
            self.assertEqual((cpu.ControlFlags, cpu.CpuRate), (5, rate))
        self.assertIsNone(run.controller.destination)
        self.assertFalse(any(entry[1] == 0x40 for entry in self.kernel.tables["controller"].values()))
        self.assertFalse(target["resumed"])
        run.controller.step(run.now())
        self.assertTrue(target["resumed"])
        for owner in (run.controller_owner, run.observer_owner, run.supervisor):
            owner.cleanup()

    def test_protocol_rejects_generation_replay_future_tick_and_flood(self):
        for fault in ("generation", "sequence", "future", "flood", "digest"):
            self.kernel = RoleKernel()
            run = self.prepare()
            run.setup()
            channel = run.observer.inbox
            pipe = self.kernel.object("observer", channel.handle)["data"]
            fields = list(backend.WIRE.unpack(bytes(pipe)))
            if fault == "generation":
                fields[1] += 1
            elif fault == "sequence":
                fields[2] += 1
            elif fault == "future":
                fields[3] += 1
            elif fault == "digest":
                fields[7] = bytes(32)
            pipe[:] = backend.WIRE.pack(*fields)
            if fault == "flood":
                pipe.extend(bytes(16 * backend.WIRE.size))
            with self.assertRaises(ValueError):
                run.observer.step(run.now())
            self.assertFalse(self.kernel.objects[self.kernel.roles["target"]]["resumed"])
            for owner in (run.controller_owner, run.observer_owner, run.supervisor):
                owner.cleanup()

    def test_no_signal_without_prior_live_or_intervention_is_credited(self):
        run = self.prepare()
        original = self.kernel.callback

        def callback(role, name):
            invoke = original(role, name)

            def call(*args):
                if role == "observer" and name == "WaitForSingleObject":
                    return 0
                return invoke(*args)
            return call

        self.kernel.callback = callback
        self.assertEqual(run.run()["outcome"], "UNKNOWN")

    def test_backward_and_late_clocks_never_prove_exit(self):
        run = self.prepare("controller_deadline")

        def advance(amount):
            self.kernel.tick += amount if self.kernel.tick < 2 * backend.SECOND else 61 * backend.SECOND

        run.advance = advance
        self.assertEqual(run.run()["outcome"], "UNKNOWN")
        run.last_tick = 100
        self.kernel.tick = 99
        with self.assertRaises(ValueError):
            run.now()

    def test_natural_and_preintervention_exit_are_not_success(self):
        for delay in (60 * backend.SECOND, backend.SECOND // 2):
            self.kernel = RoleKernel()
            run = self.prepare()
            original = run.advance

            def advance(amount, selected=delay, advance_clock=original):
                advance_clock(selected if self.kernel.tick >= 200_000_000 else amount)
                if selected < backend.SECOND and self.kernel.tick >= selected:
                    self.kernel.kill(self.kernel.roles["target"])

            run.advance = advance
            self.assertEqual(run.run()["outcome"], "UNKNOWN")

    def test_exit_does_not_require_postmortem_image_queries(self):
        run = self.prepare()
        self.kernel.reject_dead_identity = True
        self.assertEqual(run.run()["outcome"], "STUB_EARLY_PRIMARY_EXIT")

    def test_partial_protocol_io_is_unknown(self):
        for name in ("ReadFile", "WriteFile"):
            self.kernel = RoleKernel()
            run = self.prepare()
            self.kernel.partial = name
            self.assertEqual(run.run()["outcome"], "UNKNOWN")
            self.assertFalse(any(self.kernel.tables.values()))

    def test_each_setup_call_failure_attempts_exact_cleanup(self):
        baseline = self.prepare()
        baseline.setup()
        events = list(self.kernel.events)
        for owner in (baseline.controller_owner, baseline.observer_owner, baseline.supervisor):
            owner.cleanup()
        selected = {"CreateJobObjectW", "SetInformationJobObject", "CreatePipe", "DuplicateHandle",
                    "CreateProcessW", "UpdateProcThreadAttribute", "InitializeProcThreadAttributeList",
                    "ResumeThread", "GetProcessTimes", "QueryFullProcessImageNameW", "WriteFile"}
        for ordinal, (_, name) in enumerate(events, 1):
            if name not in selected:
                continue
            with self.subTest(ordinal=ordinal, operation=name):
                self.kernel = RoleKernel()
                run = self.prepare()
                self.kernel.fail_ordinal = ordinal
                result = run.run()
                # Initial attribute-size calls intentionally return FALSE; failing
                # those while retaining the required size is not a failure signal.
                if name != "InitializeProcThreadAttributeList":
                    self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(any(self.kernel.tables.values()))

    def test_close_failure_retained_others_attempted_and_retry(self):
        run = self.prepare()
        run.setup()
        owner = run.controller_owner
        failed = owner.owned[0][0]
        original = owner.api.CloseHandle.callback

        def close(handle):
            if handle == failed:
                return 0
            return original(handle)

        owner.api.CloseHandle.callback = close
        self.assertFalse(owner.cleanup())
        self.assertEqual([handle for handle, _ in owner.owned], [failed])
        owner.api.CloseHandle.callback = original
        self.assertFalse(owner.cleanup())  # Sticky failure remains disclosed.
        self.assertEqual(owner.owned, [])
        run.observer_owner.cleanup()
        run.supervisor.cleanup()
        self.assertFalse(any(self.kernel.tables.values()))

    def test_observe_io_failures_are_unknown(self):
        for operation in ("WaitForSingleObject", "GetExitCodeProcess", "PeekNamedPipe", "ReadFile"):
            self.kernel = RoleKernel()
            run = self.prepare()
            original = self.kernel.callback

            def callback(role, name, fail=operation, factory=original):
                invoke = factory(role, name)

                def call(*args):
                    if name == fail:
                        return 0xFFFFFFFF if name == "WaitForSingleObject" else 0
                    return invoke(*args)
                return call

            self.kernel.callback = callback
            self.assertEqual(run.run()["outcome"], "UNKNOWN")
            self.assertFalse(any(self.kernel.tables.values()))

    def test_only_exact_stub_table_enters_role_primitives(self):
        with self.assertRaises(TypeError):
            backend.RoleHandles(object())

    def test_held_artifact_source_path_hash_and_reparse_checks(self):
        payload = b"fixed synthetic pinned file"
        selected = {APP: {"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}
        for fault in (None, "hash", "path", "reparse"):
            self.kernel = RoleKernel()
            api = self.kernel.factory("supervisor", None)
            owner = backend.RoleHandles(api)
            original = self.kernel.invoke

            def invoke(role, name, args, failure=fault, fallback=original):
                a = self.kernel.a
                if name == "CreateFileW":
                    path = bytes(args[0]).decode("utf-16-le").rstrip("\0")
                    directory = path != APP
                    self.assertEqual(args[2], 3 if directory else 1)
                    self.assertEqual(args[4:6], (3, 0x02200000))
                    return self.kernel.new(role, "artifact", path=path, directory=directory)
                if name == "GetFileInformationByHandle":
                    obj = self.kernel.object(role, args[0])
                    info = self.kernel.ptr(args[1], a.FileInformation)
                    info.attributes = 0x10 if obj["directory"] else 0
                    if failure == "reparse":
                        info.attributes |= 0x400
                    info.size_low = 0 if obj["directory"] else len(payload)
                    info.volume, info.index_low = 1, args[0] & 0xFFFFFFFF
                    return 1
                if name == "GetFinalPathNameByHandleW":
                    path = self.kernel.object(role, args[0])["path"]
                    if failure == "path":
                        path = "G:\\other"
                    units = backend.wide(a, path)
                    for index, value in enumerate(units):
                        args[1][index] = value
                    return len(units) - 1
                if name == "ReadFile" and self.kernel.object(role, args[0])["kind"] == "artifact":
                    data = b"x" * len(payload) if failure == "hash" else payload
                    a.c.memmove(args[1], data, len(data))
                    self.kernel.ptr(args[3], a.DWORD).value = len(data)
                    return 1
                return fallback(role, name, args)

            self.kernel.invoke = invoke
            artifacts = backend.HeldArtifacts(owner)
            if fault:
                with self.assertRaises(ValueError):
                    artifacts.acquire(selected)
                self.assertFalse(owner.owned)
            else:
                self.assertEqual(len(artifacts.acquire(selected)), 3)
                self.assertEqual(len(owner.owned), 3)
                owner.cleanup()

    def test_manifest_metadata_budget_accepts_realistic_and_maximum_sets(self):
        for count, length in ((149, 140), (256, 1024)):
            with self.subTest(count=count, length=length):
                kernel = RoleKernel()
                owner = backend.RoleHandles(kernel.factory("supervisor", None))
                # Shared shallow ancestors keep this within the separate 512-handle cap.
                prefix = "G:\\" + ("a" * 200 + "\\") * (4 if length == 1024 else 0)
                paths = [prefix + "b" * (length - len(prefix) - 8) + f"{i:04}.bin"
                         for i in range(count)]
                files = {path: {"size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
                         for path in paths}
                kernel.file_contents = {ntpath.normcase(path): b"x" for path in paths}
                with self.assertRaisesRegex(ValueError, "Bounded JSON byte budget"):
                    backend.bounded_json(files)  # Reproduces the old pre-API rejection.
                self.assertEqual(kernel.events, [])
                pins = backend.HeldArtifacts(owner)
                pins.acquire(files)
                self.assertEqual(owner.pin_index, count)
                self.assertLessEqual(len(owner.owned), 512)
                self.assertEqual(sum(name == "ReadFile" for _, name in kernel.events), count)
                self.assertFalse(any("Job" in name or name == "CreateProcessW"
                                     for _, name in kernel.events))
                self.assertTrue(owner.cleanup())
                self.assertEqual(backend.CASE_RESULT_LIMIT, 12288)

    def test_manifest_invalid_or_over_limit_has_zero_api_calls(self):
        good = {"size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
        invalid = [None, {}, {f"G:\\p{i}.bin": good for i in range(257)},
                   {"G:\\" + "a" * 1022: good},
                   {"G:\\p.bin": {**good, "size": 16 * 1024 * 1024 + 1}},
                   {f"G:\\p{i}.bin": {**good, "size": 16 * 1024 * 1024} for i in range(9)},
                   {"G:\\p.bin": {**good, "sha256": "z" * 64}},
                   {"G:\\p.bin": good, "g:\\P.BIN": good}]
        for files in invalid:
            with self.subTest(files_type=type(files).__name__):
                kernel = RoleKernel()
                owner = backend.RoleHandles(kernel.factory("supervisor", None))
                with self.assertRaises(ValueError):
                    backend.HeldArtifacts(owner).acquire(files)
                self.assertEqual(kernel.events, [])
                self.assertEqual(owner.owned, [])

    def test_realistic_149_pins_complete_the_independent_injected_journey(self):
        run = self.prepare_independent()
        for index in range(143):
            name = f"Lib/synthetic_module_{index:03}.py"
            self.inventory["files"][name] = {
                "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}
            path = ntpath.normpath(ntpath.join(self.inventory["root"], name))
            self.kernel.file_contents[ntpath.normcase(path)] = b"x"
        digest = hashlib.sha256(backend.bounded_json(self.inventory, 1024 * 1024)).hexdigest()
        run.grant["runtime_sha256"] = run.approved["runtime_sha256"] = digest
        result = run.run(self.independent_pause)
        self.assertEqual(len(self.inventory["files"]) + len(run.physical["sources"]), 149)
        self.assertTrue(result["case_matched_expected_observation"])
        self.assertIsNone(result["failure"])
        self.assertEqual(result["status"], "STUB_ONLY")
        self.assertFalse(any(self.kernel.tables.values()))

    def test_host_job_membership_and_deadline_have_distinct_fixed_stages(self):
        for fault, expected in (("membership", "HOST_JOB_MEMBERSHIP"),
                                ("deadline", "HOST_JOB_DEADLINE"),
                                ("both", "HOST_JOB_MEMBERSHIP"),
                                ("query", "HOST_JOB")):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                self.kernel.host_job = fault in ("membership", "both")
                self.kernel.fail = "IsProcessInJob" if fault == "query" else None
                original = self.kernel.invoke

                def invoke(role, name, args, selected=fault, fallback=original):
                    result = fallback(role, name, args)
                    if name == "IsProcessInJob" and selected in ("deadline", "both"):
                        self.kernel.tick = 29 * backend.SECOND
                    return result

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertEqual(result["failure"]["stage"], expected)
                self.assertEqual(result["failure"]["error_class"],
                                 "OS_ERROR" if fault == "query" else "VALUE")
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertEqual(result["launch_pins"], "HELD_STUB_OBJECTS")
                names = [name for _, name in self.kernel.events]
                self.assertEqual(names.count("IsProcessInJob"), 1)
                self.assertNotIn("CreateJobObjectW", names)
                self.assertNotIn("CreateProcessW", names)
                self.assertFalse(any(self.kernel.tables.values()))

    def test_host_job_preflight_success_reaches_owned_jobs(self):
        run = self.prepare_independent()
        self.kernel.fail = "CreateJobObjectW"
        result = run.run(self.independent_pause)
        self.assertEqual(result["failure"]["stage"], "JOBS")
        self.assertEqual(result["failure"]["error_class"], "VALUE")
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_mode_success_binds_result_roles_and_owned_memberships(self):
        self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
        self.kernel.host_job = True
        self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = 0x2400
        run = self.prepare_independent()
        result = run.run(self.independent_pause)
        self.assertTrue(result["case_matched_expected_observation"], (result, self.role_errors))
        self.assertEqual(result["supervisor_job_mode"], "REQUIRE_INHERITED_NESTED")
        self.assertTrue(result["supervisor_in_job"])
        self.assertEqual(result["immediate_job_limit_flags"], 0x2400)
        self.assertEqual(result["immediate_job_ui_restrictions"], 0)
        self.assertFalse(result["ancestor_chain_validated"])
        self.assertEqual(self.kernel.ancestor_queries, [("supervisor", 9), ("supervisor", 4)])
        for encoded in self.kernel.bootstraps.values():
            self.assertEqual(backend.decode_bootstrap(encoded)["supervisor_job_mode"],
                             "REQUIRE_INHERITED_NESTED")
        counts = {role: sum(row[0] == role for row in self.kernel.membership_checks)
                  for role in ("observer", "canary", "controller", "target")}
        self.assertEqual(counts, {"observer": 4, "canary": 2, "controller": 2, "target": 2})
        self.assertTrue(all(not resumed for _, _, resumed in self.kernel.membership_checks))
        self.assertFalse(any(self.kernel.tables.values()))

    def test_supervisor_job_mode_default_and_mismatched_membership_refuse(self):
        for mode, membership in ((None, True), ("OUTSIDE_ONLY", True),
                                  ("REQUIRE_INHERITED_NESTED", False)):
            with self.subTest(mode=mode):
                self.kernel = RoleKernel()
                self.config.pop("supervisor_job_mode", None)
                if mode is not None:
                    self.config["supervisor_job_mode"] = mode
                self.kernel.host_job = membership
                result = self.prepare_independent().run(self.independent_pause)
                self.assertEqual(result["failure"]["stage"], "HOST_JOB_MEMBERSHIP")
                self.assertEqual(result["supervisor_job_mode"], mode or "OUTSIDE_ONLY")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertEqual(self.kernel.ancestor_queries, [])
                self.assertNotIn("CreateJobObjectW", [name for _, name in self.kernel.events])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_mode_is_exact_and_hash_bound_before_api(self):
        self.prepare()
        for mode in (None, True, 1, [], {}, "nested", "", "REQUIRE_INHERITED_NESTED"):
            with self.subTest(mode=mode):
                changed = {**self.config, "supervisor_job_mode": mode}
                with self.assertRaises((ValueError, TypeError)):
                    backend.StubQualification(self.grant, self.grant, changed,
                                              self.inventory, *self.hooks)
        record = {**self.config, "config_sha256": self.grant["config_sha256"],
                  "started_ns": 0, "deadline_ns": 30 * backend.SECOND}
        for mode in ("OUTSIDE_ONLY", "REQUIRE_INHERITED_NESTED", False):
            with self.assertRaises(ValueError):
                backend.encode_bootstrap("controller", {**record, "supervisor_job_mode": mode},
                                         (101, 102, 103))
        self.assertEqual(self.kernel.events, [])

    def test_nested_query_failures_and_ambiguous_lengths_precede_jobs(self):
        for kind in (9, 4):
            for fault in ("api", "zero_length", "short", "long"):
                with self.subTest(kind=kind, fault=fault):
                    self.kernel = RoleKernel()
                    self.kernel.host_job = True
                    self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                    original = self.kernel.invoke

                    def invoke(role, name, args, selected=kind, failure=fault, fallback=original):
                        if name == "QueryInformationJobObject" and args[:2] == (None, selected):
                            if failure == "api":
                                return 0
                            answer = fallback(role, name, args)
                            self.kernel.ptr(args[4], self.kernel.a.DWORD).value = (
                                0 if failure == "zero_length" else args[3] +
                                (-1 if failure == "short" else 1))
                            return answer
                        return fallback(role, name, args)

                    self.kernel.invoke = invoke
                    result = self.prepare_independent().run(self.independent_pause)
                    self.assertEqual(result["failure"]["stage"],
                                     "HOST_JOB_LIMITS" if kind == 9 else "HOST_JOB_UI")
                    query = result["immediate_job_query"]
                    self.assertEqual(query["information_class"], kind)
                    self.assertEqual(query["refusal"], "API_FAILURE" if fault == "api" else "RETURN_SIZE")
                    self.assertEqual(query["returned_bytes"] is None, fault == "api")
                    self.assertIsNone(query["limit_flags"])
                    self.assertIsNone(query["ui_restrictions"])
                    self.assertEqual(result["outcome"], "UNKNOWN")
                    self.assertNotIn("CreateJobObjectW", [name for _, name in self.kernel.events])
                    self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_explicit_breakaway_permission_never_requests_escape(self):
        for flags in (0x800, 0x2800):
            with self.subTest(flags=flags):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = flags
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                submitted, original = [], self.kernel.invoke

                def invoke(role, name, args, fallback=original, seen=submitted):
                    if name == "CreateProcessW":
                        seen.append((role, args[5]))
                    if name == "SetInformationJobObject" and args[1] == 9:
                        limits = self.kernel.ptr(args[2], self.kernel.a.ExtendedLimits)
                        self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2208)
                        self.assertEqual(limits.BasicLimitInformation.LimitFlags & 0x1800, 0)
                    return fallback(role, name, args)

                self.kernel.invoke = invoke
                result = self.prepare_independent().run(self.independent_pause)
                self.assertTrue(result["case_matched_expected_observation"], result)
                self.assertEqual(result["immediate_job_limit_flags"], flags)
                self.assertTrue(result["immediate_job_breakaway_ok"])
                self.assertIsNone(result["immediate_job_query"]["refusal"])
                self.assertFalse(result["ancestor_chain_validated"])
                self.assertEqual(submitted, [("supervisor", 0x08080404)] * 3
                                 + [("controller", 0x08080404)])
                self.assertEqual(backend.CREATE_FLAGS & 0x01000000, 0)
                self.assertFalse(any(self.kernel.tables.values()))

    def test_each_fixed_role_rejects_creation_flag_injection_without_resume(self):
        for role in ("controller", "observer", "target", "canary"):
            with self.subTest(role=role):
                kernel = RoleKernel()
                owner = backend.RoleHandles(kernel.factory("supervisor", None))
                job = owner.job_limit(1, 256, 5000)
                with (patch.object(backend, "CREATE_FLAGS", backend.CREATE_FLAGS | 0x01000000),
                      self.assertRaises(ValueError)):
                    owner.launch(role, APP, CWD, "G:\\synthetic\\probe.py", (job,))
                self.assertNotIn("CreateProcessW", [name for _, name in kernel.events])
                self.assertNotIn("ResumeThread", [name for _, name in kernel.events])
                self.assertFalse(any(kernel.tables.values()))

    def test_nested_unknown_silent_breakaway_and_ui_flags_refuse_without_resume(self):
        cases = ((0x1000, 0), (0x1800, 0), (0xFFFFFFFF, 0), (0, 1), (0, 0xFFFFFFFF),
                 (0x2800, 1)) + tuple((1 << bit, 0) for bit in range(15, 32))
        for flags, ui in cases:
            with self.subTest(flags=flags, ui=ui):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = flags
                self.kernel.ancestor_ui = ui
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                result = self.prepare_independent().run(self.independent_pause)
                self.assertEqual(result["failure"]["stage"],
                                 "HOST_JOB_UI" if ui else "HOST_JOB_LIMITS")
                query = result["immediate_job_query"]
                self.assertEqual(query["refusal"], "UI_FLAGS" if ui else "LIMIT_FLAGS")
                self.assertEqual(query["returned_bytes"], 4 if ui else 144)
                self.assertEqual(query["ui_restrictions"] if ui else query["limit_flags"], ui or flags)
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertNotIn("CreateProcessW", [name for _, name in self.kernel.events])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_selected_limit_values_are_validated(self):
        for flags in (1, 2, 4, 8, 0x10, 0x20, 0x44, 0x100, 0x200, 0x4000):
            with self.subTest(flags=flags):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = flags
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                result = self.prepare_independent().run(self.independent_pause)
                self.assertEqual(result["failure"]["stage"], "HOST_JOB_LIMITS")
                self.assertFalse(any(self.kernel.tables.values()))
        self.kernel = RoleKernel()
        self.kernel.host_job = True
        limits = self.kernel.ancestor_limits
        basic = limits.BasicLimitInformation
        basic.LimitFlags = 0x67BF  # All recognized non-breakaway flags except PRESERVE_JOB_TIME.
        basic.MinimumWorkingSetSize, basic.MaximumWorkingSetSize = 1, 2
        basic.PerProcessUserTimeLimit = basic.PerJobUserTimeLimit = 1
        basic.ActiveProcessLimit, basic.Affinity, basic.PriorityClass = 1, 1, 0x20
        basic.SchedulingClass = 9
        limits.ProcessMemoryLimit = limits.JobMemoryLimit = 1
        owner = backend.RoleHandles(self.kernel.factory("supervisor", None))
        self.assertEqual(owner.immediate_job_information(9), 0x67BF)
        basic.SchedulingClass = 10
        with self.assertRaises(ValueError):
            owner.immediate_job_information(9)
        basic.SchedulingClass = 9
        basic.MinimumWorkingSetSize = 3
        with self.assertRaises(ValueError):
            owner.immediate_job_information(9)
        self.assertEqual(owner.owned, [])  # NULL queries never create ancestor ownership.

    def test_immediate_job_diagnostic_reasons_are_fixed_bounded_and_shape_gated(self):
        cases = ((1, "WORKING_SET"), (2, "PROCESS_TIME"), (4, "JOB_TIME"),
                 (0x44, "TIME_FLAGS"), (8, "ACTIVE_PROCESS"), (0x10, "AFFINITY"),
                 (0x20, "PRIORITY"), (0x80, "SCHEDULING"), (0x100, "PROCESS_MEMORY"),
                 (0x200, "JOB_MEMORY"), (0x4000, "SUBSET_AFFINITY"))
        for flags, expected in cases:
            with self.subTest(flags=flags):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                basic = self.kernel.ancestor_limits.BasicLimitInformation
                basic.LimitFlags = flags
                if expected == "TIME_FLAGS":
                    basic.PerJobUserTimeLimit = 1
                if expected == "SCHEDULING":
                    basic.SchedulingClass = 10
                owner = backend.RoleHandles(self.kernel.factory("supervisor", None))
                with self.assertRaises(ValueError):
                    owner.immediate_job_information(9)
                self.assertEqual(owner.immediate_job_query, {
                    "information_class": 9, "returned_bytes": 144, "limit_flags": flags,
                    "ui_restrictions": None, "refusal": expected})
                self.assertLess(len(backend.bounded_json(owner.immediate_job_query)), 256)
                self.assertEqual(owner.owned, [])
                basic.LimitFlags = 0
                self.assertEqual(owner.immediate_job_information(9), 0)
                self.assertIsNone(owner.immediate_job_query["refusal"])
                self.assertEqual(owner.immediate_job_information(4), 0)
                self.assertEqual(owner.immediate_job_query, {
                    "information_class": 4, "returned_bytes": 4, "limit_flags": None,
                    "ui_restrictions": 0, "refusal": None})

    def test_each_owned_role_membership_rechecked_before_resume(self):
        for child in ("observer", "canary", "controller", "target"):
            for phase in ("creation", "resume"):
                with self.subTest(child=child, phase=phase):
                    self.kernel = RoleKernel()
                    self.kernel.host_job = True
                    self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                    original, seen = self.kernel.invoke, [0]

                    def invoke(role, name, args, selected=child, when=phase, fallback=original,
                               counts=seen):
                        answer = fallback(role, name, args)
                        if name == "IsProcessInJob" and args[1] is not None:
                            process = self.kernel.object(role, args[0])
                            if process["role"] == selected:
                                counts[0] += 1
                                rejection = 1 if when == "creation" else (3 if selected == "observer" else 2)
                                if counts[0] == rejection:
                                    self.kernel.ptr(args[2], self.kernel.a.c.c_int32).value = 0
                        return answer

                    self.kernel.invoke = invoke
                    result = self.prepare_independent().run(self.independent_pause)
                    self.assertFalse(result["case_matched_expected_observation"], result)
                    self.assertFalse(self.kernel.objects[self.kernel.roles[child]]["resumed"])
                    self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_shared_ancestor_loss_is_unknown_not_stop_success(self):
        self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
        self.kernel.host_job = True
        run = self.prepare_independent()
        pause = self.independent_pause
        killed = [False]

        def lose_ancestor(amount):
            pause(amount)
            if run.live_tick is not None and not killed[0]:
                killed[0] = True
                for identity in list(self.kernel.roles.values()):
                    self.kernel.kill(identity)

        result = run.run(lose_ancestor)
        self.assertTrue(killed[0])
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertFalse(result["case_matched_expected_observation"])
        self.assertFalse(result["canary_live_before_cleanup"])
        self.assertFalse(result["ancestor_chain_validated"])

    def test_nested_admission_deadline_and_ambiguous_membership_fail_closed(self):
        for fault in ("deadline", "ambiguous"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                original = self.kernel.invoke

                def invoke(role, name, args, selected=fault, fallback=original):
                    answer = fallback(role, name, args)
                    if selected == "deadline" and name == "QueryInformationJobObject":
                        self.kernel.tick = 29 * backend.SECOND
                    if selected == "ambiguous" and name == "IsProcessInJob":
                        self.kernel.ptr(args[2], self.kernel.a.c.c_int32).value = -1
                    return answer

                self.kernel.invoke = invoke
                result = self.prepare_independent().run(self.independent_pause)
                self.assertEqual(result["failure"]["stage"],
                                 "HOST_JOB_DEADLINE" if fault == "deadline" else "HOST_JOB")
                self.assertNotIn("CreateJobObjectW", [name for _, name in self.kernel.events])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_owned_membership_api_and_ambiguous_values_prevent_resume(self):
        for fault in ("api", "unchanged", "ambiguous"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                original = self.kernel.invoke

                def invoke(role, name, args, selected=fault, fallback=original):
                    if name == "IsProcessInJob" and args[1] is not None:
                        if selected == "api":
                            return 0
                        if selected == "ambiguous":
                            self.kernel.ptr(args[2], self.kernel.a.c.c_int32).value = 2
                        return 1
                    return fallback(role, name, args)

                self.kernel.invoke = invoke
                result = self.prepare_independent().run(self.independent_pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertFalse(any(self.kernel.objects[key]["resumed"]
                                     for key in self.kernel.roles.values()))
                self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_owned_cleanup_failure_retains_pins_without_ancestor_control(self, flags=0):
        for fault in ("terminate", "query", "nonzero"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = flags
                run = self.prepare_independent()
                original = self.kernel.invoke
                controls = []

                def invoke(role, name, args, selected=fault, fallback=original, calls=controls):
                    if name in ("SetInformationJobObject", "TerminateJobObject"):
                        self.assertIsNotNone(args[0])
                        self.assertEqual(self.kernel.object(role, args[0])["kind"], "job")
                        calls.append((role, name, args[0]))
                    if selected == "terminate" and name == "TerminateJobObject":
                        return 0
                    if name == "QueryInformationJobObject" and args[0] is not None:
                        if selected == "query":
                            return 0
                        answer = fallback(role, name, args)
                        if selected == "nonzero":
                            self.kernel.ptr(args[2], self.kernel.a.BasicAccounting).ActiveProcesses = 1
                        return answer
                    return fallback(role, name, args)

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertTrue(controls)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertTrue(result["cleanup_responsibility_retained"])
                self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
                self.assertTrue(any(kind == "job" for _, kind in run.owner.owned))
                self.kernel.invoke = original
                run.owner.cleanup()
                self.assertFalse(any(self.kernel.tables.values()))

    def test_nested_creation_and_limit_failures_do_not_fall_back(self):
        for operation in ("CreateJobObjectW", "SetInformationJobObject",
                          "UpdateProcThreadAttribute", "CreateProcessW"):
            with self.subTest(operation=operation):
                self.kernel = RoleKernel()
                self.kernel.host_job = True
                self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                run = self.prepare_independent()
                self.kernel.fail = operation
                result = run.run(self.independent_pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertNotIn("ResumeThread", [name for _, name in self.kernel.events])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_fixed_failure_diagnostics_identify_pin_api_and_redact_details(self):
        for operation, phase in (("CreateFileW", "OPEN_DIRECTORY"),
                                 ("GetFileInformationByHandle", "FILE_IDENTITY"),
                                 ("ReadFile", "HASH_FILE")):
            with self.subTest(operation=operation):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                self.kernel.fail = operation
                result = run.run(self.independent_pause)
                self.assertEqual(result["failure"], {
                    "stage": "PIN_ADMISSION", "error_class": "OS_ERROR", "code": 122,
                    "code_domain": "ERRNO", "pin_phase": phase, "pin_index": 1,
                    "cleanup_operation": None})
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertNotIn("CreateJobObjectW", [name for _, name in self.kernel.events])
                self.assertLess(len(backend.bounded_json(result)), backend.CASE_RESULT_LIMIT)
                self.assertNotIn("synthetic", json.dumps(result))

    def test_failure_fields_are_bounded_first_only_and_never_format_exception(self):
        class PrivateError(Exception):
            def __str__(self):
                raise AssertionError("Exception text must never be accessed")

        for error, category in ((PrivateError(), "OTHER"), (ValueError("private"), "VALUE"),
                                (TypeError("private"), "TYPE"), (KeyboardInterrupt(), "INTERRUPTED"),
                                (PermissionError("private"), "PERMISSION")):
            run = self.prepare_independent()
            run.stage = "private" * 1000
            run.note_failure(error)
            first = dict(run.failure)
            run.stage = "CLEANUP"
            run.note_failure(OSError(5, "later private path"))
            self.assertEqual(run.failure, first)
            self.assertEqual(first["stage"], "UNKNOWN")
            self.assertEqual(first["error_class"], category)
            self.assertIsNone(first["code"])
            self.assertLess(len(backend.bounded_json(first, 2048)), 256)
            self.assertNotIn("private", json.dumps(first))
        for code in (None, True, -1, 2**32, "private", 122):
            run = self.prepare_independent()
            error = OSError("private")
            error.errno = code
            run.note_failure(error)
            self.assertEqual(run.failure["code"], 122 if code == 122 else None)
        run = self.prepare_independent()
        error = OSError("private")
        error.errno, error.winerror = 5, 123
        run.note_failure(error)
        self.assertEqual((run.failure["code"], run.failure["code_domain"]), (123, "WINERROR"))

    def test_session_output_failure_retains_bounded_diagnostic_without_rewrite(self):
        session = self.prepare_session()
        session.execute(self.independent_pause)
        original = session.payload
        output = Path(self.temp.name) / "diagnostic-output.json"
        with patch("os.fsync", side_effect=OSError(5, "private path and credentials")):
            session.write_result(output)
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(session.run.failure["stage"], "OUTPUT")
        self.assertEqual(session.run.failure["code"], 5)
        self.assertNotIn("private", json.dumps(session.run.failure))
        self.assertEqual(session.exit_code(), 3)

    def test_connected_strict_pin_mapping_holds_before_any_job(self):
        # Virtual file objects exercise the full strict mapping/lock path. This
        # is explicitly NOT physical Windows file identity or an OS launch.
        runtime_root = "G:\\synthetic\\runtime"
        source_root = "G:\\synthetic\\repository"
        self.inventory["root"] = runtime_root
        self.config["application"] = ntpath.join(runtime_root, "python.exe")
        self.config["source"] = ntpath.normpath(ntpath.join(source_root, backend.SOURCE_FILES[1]))
        self.kernel.file_contents[ntpath.normcase(self.config["application"])] = (
            Path(self.temp.name) / "python.exe").read_bytes()
        records = {}
        for name in backend.SOURCE_FILES:
            content = (ROOT / name).read_bytes()
            records[name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            self.kernel.file_contents[ntpath.normcase(ntpath.join(source_root, name))] = content
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            run = self.prepare()
            run.physical = {"source_root": source_root, "sources": records}
            result = run.run()
        self.assertEqual(result["outcome"], "STUB_EARLY_PRIMARY_EXIT")
        self.assertEqual(result["launch_pins"], "HELD_STUB_OBJECTS")
        names = [name for _, name in self.kernel.events]
        self.assertLess(names.index("CreateFileW"), names.index("CreateJobObjectW"))
        self.assertFalse(any(self.kernel.tables.values()))

    def test_strict_pin_mapping_rejects_unrelated_launch_before_api(self):
        run = self.prepare()
        run.physical = {"source_root": "G:\\synthetic", "sources": {
            name: {"size": 1, "sha256": "a" * 64} for name in backend.SOURCE_FILES}}
        self.assertEqual(run.run()["outcome"], "UNKNOWN")
        self.assertEqual(self.kernel.events, [])

    def test_bounded_role_bootstrap_roundtrip_and_refusals(self):
        record = {**self.config, "config_sha256": hashlib.sha256(backend.bounded_json(self.config)).hexdigest(),
                  "started_ns": 0,
                  "deadline_ns": 30 * backend.SECOND}
        encoded = backend.encode_bootstrap("controller", record, (101, 102, 103))
        value = backend.decode_bootstrap(encoded)
        self.assertEqual(value["handles"], [101, 102, 103])
        self.assertEqual(value["application"], APP)
        for invalid in ("0" * 16386, "gg", "0", "5b" * 1000, "74727565"):
            with self.assertRaises(ValueError):
                backend.decode_bootstrap(invalid)
        for handles in ((1, 1, 2), (True, 2, 3), (0, 2, 3), (1, 2), (1, 2, 2**63)):
            with self.assertRaises(ValueError):
                backend.encode_bootstrap("observer", record, handles)
        altered = {**record, "deadline_ns": 31 * backend.SECOND}
        with self.assertRaises(ValueError):
            backend.encode_bootstrap("observer", altered, (1, 2, 3))
        with (contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result):
            probe.main(["--mode", "native-controller", "--bootstrap", encoded])
        self.assertEqual(result.exception.code, 2)

    def prepare_independent(self, case="human_stop"):
        runtime_root, source_root = "G:\\synthetic\\runtime", "G:\\synthetic\\repository"
        self.inventory["root"] = runtime_root
        self.config["application"] = ntpath.join(runtime_root, "python.exe")
        self.config["source"] = ntpath.normpath(ntpath.join(source_root, backend.SOURCE_FILES[1]))
        self.kernel.file_contents[ntpath.normcase(self.config["application"])] = (
            Path(self.temp.name) / "python.exe").read_bytes()
        records = {}
        for name in backend.SOURCE_FILES:
            content = (ROOT / name).read_bytes()
            records[name] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            self.kernel.file_contents[ntpath.normcase(ntpath.join(source_root, name))] = content
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            self.prepare(case)  # Reuse exact grant and trusted synthetic clock/persistence hooks.
            run = backend.PreparedQualification(
                self.grant, dict(self.grant), self.config, self.inventory,
                {"source_root": source_root, "sources": records}, self.hooks[0], self.hooks[1])
        self.independent_roles, self.iterators = {}, {}
        self.schedule = {"observer": 1, "controller": 1}
        self.freeze = set()
        self.role_errors = []
        self.pause_count = 0

        def pause(amount):
            # Test driver alone knows all synthetic tables. The supervisor's
            # code has no child object, callback, table or resumed_at access.
            self.pause_count += 1
            for role in ("observer", "controller"):
                identity = self.kernel.roles.get(role)
                if identity is None or not self.kernel.objects[identity]["alive"]:
                    continue
                if not self.kernel.objects[identity]["resumed"]:
                    continue
                if role not in self.independent_roles:
                    worker = backend.PreparedRole(self.kernel.bootstraps[role],
                                                  self.kernel.factory(role, None),
                                                  self.hooks[1], self.hooks[3])
                    self.independent_roles[role] = worker
                    self.iterators[role] = worker.steps()
                if role in self.freeze or self.pause_count % self.schedule[role]:
                    continue
                try:
                    next(self.iterators[role])
                except (OSError, ValueError, StopIteration) as error:
                    self.role_errors.append((role, type(error).__name__))
                    self.kernel.kill(identity)  # Model process exit; no native call.
            self.hooks[2](amount)

        self.independent_pause = pause
        return run

    def test_independent_prepared_all_cases_and_strict_pins(self):
        for case in backend.CASES:
            with self.subTest(case=case):
                self.kernel = RoleKernel()
                run = self.prepare_independent(case)
                result = run.run(self.independent_pause)
                expected = ("STUB_MATCHED_LIVE_CONTROL" if case == "no_stop_control" else
                            "UNKNOWN" if case in ("identity_failure", "suspended_stop",
                                                  "stop_persistence_failure", "observer_loss",
                                                  "supervisor_loss") else "STUB_EARLY_PRIMARY_EXIT")
                self.assertEqual(result["outcome"], expected, (result, self.role_errors))
                self.assertEqual(result["launch_pins"], "HELD_STUB_OBJECTS")
                self.assertTrue(result["owned_stub_cleanup"])
                self.assertFalse(any(self.kernel.tables.values()))
                self.assertLessEqual(result["evidence_bytes"] + 3 * 4096 + 2 * 16384, 65536)
                names = [name for _, name in self.kernel.events]
                self.assertLess(names.index("CreateFileW"), names.index("CreateJobObjectW"))
                self.assertEqual(set(self.kernel.bootstraps), {"controller", "observer"})
                for role, encoded in self.kernel.bootstraps.items():
                    value = backend.decode_bootstrap(encoded)
                    self.assertEqual(value["role"], role)
                    self.assertEqual(value["config_sha256"], self.grant["config_sha256"])
                with self.assertRaises(ValueError):
                    run.run(self.independent_pause)

    def test_independent_skewed_role_schedules(self):
        for case in ("human_stop", "controller_crash", "no_stop_control"):
            with self.subTest(case=case):
                self.kernel = RoleKernel()
                run = self.prepare_independent(case)
                self.schedule = {"observer": 3, "controller": 2}
                result = run.run(self.independent_pause)
                expected = ("STUB_MATCHED_LIVE_CONTROL" if case == "no_stop_control"
                            else "STUB_EARLY_PRIMARY_EXIT")
                self.assertEqual(result["outcome"], expected, result)

    def test_independent_controller_stall_cannot_stall_supervisor(self):
        run = self.prepare_independent("controller_deadline")
        fallback = self.independent_pause

        def pause(amount):
            if self.kernel.tick > 2 * backend.SECOND:
                self.freeze.add("controller")
            fallback(amount)

        result = run.run(pause)
        self.assertEqual(result["outcome"], "STUB_EARLY_PRIMARY_EXIT", result)
        rows = [dict(row) for row in result["evidence"]]
        action = next(row for row in rows if row["event"] == "deadline_intervention")
        self.assertEqual(action["monotonic_ns"], 29 * backend.SECOND)
        self.assertFalse(any(self.kernel.tables.values()))

    def test_independent_late_deadline_cleanup_not_success(self):
        run = self.prepare_independent("controller_deadline")
        fallback = self.independent_pause

        def pause(amount):
            fallback(amount)
            if self.kernel.tick == 28_900_000_000:
                self.kernel.tick = 30_100_000_000

        result = run.run(pause)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertTrue(result["owned_stub_cleanup"])
        self.assertFalse(any(self.kernel.tables.values()))

    def test_independent_missing_observer_or_initialization_is_unknown(self):
        for role in ("observer", "controller"):
            with self.subTest(role=role):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                self.freeze.add(role)
                result = run.run(self.independent_pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertTrue(result["owned_stub_cleanup"])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_independent_pins_are_mandatory_and_bootstrap_refuses_before_api(self):
        self.prepare_independent()
        for physical in (None, {}, {"source_root": "G:\\synthetic"}):
            with (patch.object(backend, "verify_runtime_inventory", return_value=self.inventory),
                  self.assertRaises(ValueError)):
                backend.PreparedQualification(self.grant, self.grant, self.config, self.inventory,
                                              physical, self.hooks[0], self.hooks[1])
        with self.assertRaises(ValueError):
            backend.PreparedRole("0" * 16386, self.kernel.factory("supervisor", None),
                                 self.hooks[1], self.hooks[3])
        self.assertEqual(self.kernel.events, [])

    def test_independent_exit_without_intervention_cannot_pass(self):
        run = self.prepare_independent("controller_deadline")
        fallback = self.independent_pause

        def pause(amount):
            fallback(amount)
            if self.kernel.tick == 2 * backend.SECOND:
                self.kernel.kill(self.kernel.roles["controller"])

        result = run.run(pause)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertIn("observed_exit_report", [dict(row)["event"] for row in result["evidence"]])

    def test_independent_intent_without_exit_cannot_pass(self):
        run = self.prepare_independent()
        fallback = self.kernel.invoke

        def invoke(role, name, args):
            if role == "controller" and name == "TerminateProcess":
                return 1  # Dispatch success lies; observer must still query LIVE.
            return fallback(role, name, args)

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertNotIn("observed_exit_report", [dict(row)["event"] for row in result["evidence"]])
        self.assertFalse(any(self.kernel.tables.values()))

    def test_independent_malformed_control_retains_exit_evidence_not_success(self):
        run = self.prepare_independent("controller_deadline")
        fallback = self.independent_pause

        def pause(amount):
            fallback(amount)
            if self.kernel.tick == backend.SECOND:
                worker = self.independent_roles["controller"]
                worker.frame(worker.machine.outbox, 7, self.kernel.tick)  # Wrong direction/state.
            if self.kernel.tick == 2 * backend.SECOND:
                self.kernel.kill(self.kernel.roles["controller"])

        result = run.run(pause)
        events = [dict(row)["event"] for row in result["evidence"]]
        self.assertIn("role_failure", events)
        self.assertIn("observed_exit_report", events)
        self.assertEqual(result["outcome"], "UNKNOWN")

    def test_independent_natural_exit_and_observer_report_failure_are_unknown(self):
        for fault in ("natural", "report"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                run = self.prepare_independent("controller_deadline")
                fallback = self.independent_pause

                def pause(amount, selected=fault, advance=fallback):
                    advance(amount)
                    if self.kernel.tick == 2 * backend.SECOND:
                        if selected == "natural":
                            self.hooks[2](60 * backend.SECOND)
                        else:
                            self.freeze.add("observer")

                result = run.run(pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertTrue(result["owned_stub_cleanup"])

    def test_independent_failed_cleanup_retains_pins_and_exact_handles(self):
        run = self.prepare_independent()
        fallback = self.kernel.invoke

        def invoke(role, name, args):
            if (role == "supervisor" and name == "CloseHandle" and run.jobs
                    and args[0] == run.jobs[0]):
                return 0
            return fallback(role, name, args)

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertTrue(result["cleanup_responsibility_retained"])
        self.assertTrue(run.owner.owned)
        self.assertTrue(any(self.kernel.object("supervisor", handle)["kind"] == "artifact"
                            for handle, _ in run.owner.owned))
        self.assertLessEqual(self.kernel.tick, 35 * backend.SECOND)
        self.kernel.invoke = fallback
        self.assertTrue(run.owner.cleanup())
        self.assertFalse(any(self.kernel.tables.values()))

    def test_fixed_loader_and_dispatch_with_no_search_path_mutation(self):
        before = list(sys.path)
        loaded = probe.load_prepared_backend()
        self.assertEqual(sys.path, before)
        self.assertEqual(Path(loaded.__file__).resolve(), (ROOT / backend.SOURCE_FILES[0]).resolve())
        with self.assertRaises(PermissionError):
            loaded.NativeApi()
        record = {**self.config, "config_sha256": hashlib.sha256(backend.bounded_json(self.config)).hexdigest(),
                  "started_ns": 0, "deadline_ns": 30 * backend.SECOND}
        encoded = backend.encode_bootstrap("observer", record, (101, 102, 103))
        calls = []

        def factory(_loaded):
            calls.append("factory")

        with self.assertRaises(ValueError):
            probe.prepared_role_entry("native-controller", encoded, factory,
                                      lambda: 0, lambda _: None, lambda *_: None)
        self.assertEqual(calls, [])
        for mode in ("native-controller", "native-observer", "native-supervisor"):
            with (patch.object(probe, "load_prepared_backend", side_effect=AssertionError("gate")),
                  contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result):
                probe.main(["--mode", mode, "--bootstrap", encoded])
            self.assertEqual(result.exception.code, 2)

    def test_owned_job_accounting_abi_and_invalid_handles(self):
        a = self.kernel.a
        self.assertEqual(a.c.sizeof(a.BasicAccounting), 48)
        self.assertEqual(a.BasicAccounting.ActiveProcesses.offset, 40)
        self.assertEqual(a.BasicAccounting.TotalTerminatedProcesses.offset, 44)
        owner = backend.RoleHandles(self.kernel.factory("supervisor", None))
        for invalid in (0, 0xFFFFFFFFFFFFFFFF, 1234):
            with self.assertRaises(ValueError):
                owner.active_processes(invalid)
            with self.assertRaises(ValueError):
                owner.terminate_outer(invalid)
        self.assertEqual(self.kernel.events, [])
        canary_job = owner.job_limit(1, 128, 500)
        with self.assertRaises(ValueError):
            owner.terminate_outer(canary_job)
        self.assertEqual(owner.active_processes(canary_job), 0)
        owner.cleanup()

    def test_delayed_target_exit_holds_pins_until_accounting_zero(self):
        run = self.prepare_independent("observer_loss")
        kill, invoke, pause = self.kernel.kill, self.kernel.invoke, self.independent_pause
        pending, nonempty = {}, []

        def deferred_kill(identity):
            process = self.kernel.objects[identity]
            if process["role"] == "target" and process["alive"]:
                pending.setdefault(identity, self.kernel.tick + 300_000_000)
            else:
                kill(identity)

        def delayed_pause(amount):
            pause(amount)
            for identity, due in list(pending.items()):
                if self.kernel.tick >= due:
                    kill(identity)
                    del pending[identity]

        def checked_invoke(role, name, args):
            result = invoke(role, name, args)
            if name == "QueryInformationJobObject":
                info = self.kernel.ptr(args[2], self.kernel.a.BasicAccounting)
                if info.ActiveProcesses:
                    nonempty.append(self.kernel.tick)
                    self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
            return result

        self.kernel.kill, self.kernel.invoke = deferred_kill, checked_invoke
        result = run.run(delayed_pause)
        self.assertTrue(nonempty)
        self.assertTrue(result["owned_stub_cleanup"])
        self.assertEqual(result["outcome"], "UNKNOWN")  # Missing judge stays UNKNOWN despite cleanup.
        self.assertFalse(any(self.kernel.tables.values()))

    def test_job_cleanup_failures_and_nonzero_counts_retain_pins(self):
        for fault in ("terminate", "query", "short", "inconsistent", "nonzero"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                fallback = self.kernel.invoke

                def invoke(role, name, args, selected=fault, original=fallback):
                    if ((selected == "terminate" and name == "TerminateJobObject")
                            or (selected == "query" and name == "QueryInformationJobObject")):
                        return 0
                    result = original(role, name, args)
                    if name == "QueryInformationJobObject":
                        info = self.kernel.ptr(args[2], self.kernel.a.BasicAccounting)
                        if selected == "short":
                            self.kernel.ptr(args[4], self.kernel.a.DWORD).value = 47
                        elif selected in ("inconsistent", "nonzero"):
                            info.ActiveProcesses = info.TotalProcesses + 1 if selected == "inconsistent" else 1
                    return result

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertTrue(result["cleanup_responsibility_retained"])
                self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
                self.assertTrue(any(kind == "job" for _, kind in run.owner.owned))
                self.kernel.invoke = fallback
                run.owner.cleanup()
                self.assertFalse(any(self.kernel.tables.values()))

    def test_explicit_breakaway_permission_does_not_weaken_cleanup(self):
        self.test_nested_owned_cleanup_failure_retains_pins_without_ancestor_control(0x2800)

    def test_explicit_breakaway_permission_partial_setup_requires_cleanup(self):
        self.test_partial_job_and_process_setup_requires_accounted_cleanup(0x2800)

    def test_partial_job_and_process_setup_requires_accounted_cleanup(self, flags=None):
        for api_name, maximum in (("CreateJobObjectW", 3), ("CreateProcessW", 3)):
            for ordinal in range(1, maximum + 1):
                with self.subTest(api=api_name, ordinal=ordinal):
                    self.kernel = RoleKernel()
                    if flags is not None:
                        self.config["supervisor_job_mode"] = "REQUIRE_INHERITED_NESTED"
                        self.kernel.host_job = True
                        self.kernel.ancestor_limits.BasicLimitInformation.LimitFlags = flags
                    run = self.prepare_independent()
                    fallback = self.kernel.invoke
                    counts = {api_name: 0}

                    def invoke(role, name, args, selected=api_name, at=ordinal,
                               original=fallback, call_counts=counts):
                        if role == "supervisor" and name == selected:
                            call_counts[selected] += 1
                            if call_counts[selected] == at:
                                return 0
                        return original(role, name, args)

                    self.kernel.invoke = invoke
                    result = run.run(self.independent_pause)
                    self.assertEqual(result["outcome"], "UNKNOWN")
                    self.assertTrue(result["owned_stub_cleanup"], result)
                    self.assertFalse(any(self.kernel.tables.values()))

    def test_outer_job_cleanup_preserves_canary_until_its_own_disposal(self):
        run = self.prepare_independent()
        fallback = self.kernel.invoke
        checked = []

        def invoke(role, name, args):
            result = fallback(role, name, args)
            if name == "TerminateJobObject":
                self.assertEqual(args[0], run.outer)
                self.assertTrue(self.kernel.objects[self.kernel.roles["canary"]]["alive"])
                checked.append(True)
            return result

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertTrue(checked)
        self.assertTrue(result["canary_live_before_cleanup"])

    def test_cleanup_terminate_after_exit_race_requires_exact_signaled_recheck(self):
        for selected in ("observer", "controller", "canary"):
            with self.subTest(role=selected):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                original = self.kernel.invoke
                attempts, rechecks, accounting = [], [], []

                def invoke(role, name, args, target=selected):
                    if role == "supervisor" and run.cleanup_started:
                        if name in ("WaitForSingleObject", "TerminateProcess"):
                            obj = self.kernel.object(role, args[0])
                            if obj.get("role") == target:
                                if name == "WaitForSingleObject" and not attempts:
                                    return backend.WAIT_TIMEOUT
                                if name == "TerminateProcess":
                                    attempts.append(args[0])
                                    self.kernel.kill(self.kernel.tables[role][args[0]][0])
                                    self.kernel.errors[role] = 5
                                    return 0
                                rechecks.append(args[0])
                                self.kernel.errors[role] = 123  # Last-error must already be captured.
                        if name == "QueryInformationJobObject":
                            result = original(role, name, args)
                            accounting.append(self.kernel.ptr(args[2], self.kernel.a.BasicAccounting)
                                              .ActiveProcesses)
                            return result
                    return original(role, name, args)

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertEqual(len(attempts), 1)
                self.assertTrue(rechecks and all(handle == attempts[0] for handle in rechecks))
                self.assertTrue(accounting and all(count == 0 for count in accounting))
                self.assertTrue(result["owned_cleanup_confirmed"], result)
                self.assertEqual(result["outcome"], "STUB_EARLY_PRIMARY_EXIT")
                self.assertEqual(result["cleanup_termination_rechecks"][0]["error_code"], 5)
                self.assertEqual(result["cleanup_termination_rechecks"][0]["wait_state"], "SIGNALED")
                self.assertTrue(result["canary_live_before_cleanup"])
                self.assertFalse(any(self.kernel.tables.values()))

    def test_cleanup_failed_termination_recheck_never_waives_ambiguity(self):
        for code, wait in ((5, backend.WAIT_TIMEOUT), (5, 0xFFFFFFFF), (5, 17),
                           (6, backend.WAIT_OBJECT_0)):
            with self.subTest(code=code, wait=wait):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                original = self.kernel.invoke
                attempts, rechecks = [], []

                def invoke(role, name, args, error_code=code, wait_state=wait):
                    if role == "supervisor" and run.cleanup_started:
                        if name in ("WaitForSingleObject", "TerminateProcess"):
                            if self.kernel.object(role, args[0]).get("role") == "canary":
                                if name == "TerminateProcess":
                                    attempts.append(args[0])
                                    self.kernel.errors[role] = error_code
                                    return 0
                                if attempts:
                                    rechecks.append(args[0])
                                    return wait_state
                    return original(role, name, args)

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertEqual(len(attempts), 1)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertEqual(result["failure"]["code"], code)
                self.assertEqual(result["failure"]["cleanup_operation"], "TERMINATE_PROCESS")
                self.assertEqual(len(result["cleanup_termination_rechecks"]), int(code == 5))
                self.assertTrue(result["cleanup_responsibility_retained"])
                self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
                self.assertTrue(any(kind == "job" for _, kind in run.owner.owned))
                self.kernel.invoke = original
                run.owner.cleanup()

    def test_cleanup_outer_error_five_is_not_a_process_exit_race(self):
        run = self.prepare_independent()
        original = self.kernel.invoke

        def invoke(role, name, args):
            if role == "supervisor" and name == "TerminateJobObject":
                self.kernel.errors[role] = 5
                return 0
            return original(role, name, args)

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertEqual(result["failure"]["cleanup_operation"], "TERMINATE_OUTER")
        self.assertEqual(result["cleanup_termination_rechecks"], [])
        self.assertTrue(result["cleanup_responsibility_retained"])
        self.kernel.invoke = original
        run.owner.cleanup()

    def test_cleanup_query_and_close_error_five_remain_unknown(self):
        for api_name, expected in (("QueryInformationJobObject", "QUERY_EMPTY"),
                                   ("CloseHandle", "CLOSE_DEAD")):
            with self.subTest(api=api_name):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                original = self.kernel.invoke

                def invoke(role, name, args, selected=api_name):
                    if role == "supervisor" and run.cleanup_started and name == selected:
                        self.kernel.errors[role] = 5
                        return 0
                    return original(role, name, args)

                self.kernel.invoke = invoke
                result = run.run(self.independent_pause)
                self.assertEqual(result["failure"]["cleanup_operation"], expected)
                self.assertEqual(result["cleanup_termination_rechecks"], [])
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertTrue(result["cleanup_responsibility_retained"])
                self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
                self.kernel.invoke = original
                run.owner.cleanup()

    def test_cleanup_delayed_signal_does_not_waive_failed_immediate_recheck(self):
        run = self.prepare_independent()
        original = self.kernel.invoke
        attempts, waits = [], []

        def invoke(role, name, args):
            if (role == "supervisor" and run.cleanup_started
                    and name in ("TerminateProcess", "WaitForSingleObject")
                    and self.kernel.object(role, args[0]).get("role") == "canary"):
                if name == "TerminateProcess":
                    attempts.append(args[0])
                    self.kernel.errors[role] = 5
                    return 0
                if attempts:
                    waits.append(args[0])
                    self.kernel.kill(self.kernel.tables[role][args[0]][0])
                    if len(waits) == 1:
                        return backend.WAIT_TIMEOUT
            return original(role, name, args)

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(len(result["cleanup_termination_rechecks"]), 1)
        self.assertEqual(result["cleanup_termination_rechecks"][0]["wait_state"], "TIMEOUT")
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertTrue(result["cleanup_responsibility_retained"])
        self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
        self.kernel.invoke = original
        run.owner.cleanup()

    def test_serial_case_bound_and_unresolved_cleanup_prevents_next_case(self):
        first = self.prepare_independent()
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            self.config["case"] = "controller_crash"
            grant = {**self.grant, "config_sha256": hashlib.sha256(
                backend.bounded_json(self.config)).hexdigest()}
            second = backend.PreparedQualification(grant, grant, self.config, self.inventory,
                                                   first.physical, self.hooks[0], self.hooks[1])
        for cases in ((), (first,) * 11, (first, first)):
            with self.assertRaises(ValueError):
                backend.run_serial_prepared(cases, self.independent_pause)
        self.assertEqual(self.kernel.events, [])
        fallback = self.kernel.invoke

        def invoke(role, name, args):
            return 0 if name == "QueryInformationJobObject" else fallback(role, name, args)

        self.kernel.invoke = invoke
        results = backend.run_serial_prepared((first, second), self.independent_pause)
        self.assertEqual(len(results), 1)
        self.assertFalse(second.used)
        self.assertIsNone(second.owner)
        self.kernel.invoke = fallback
        first.owner.cleanup()

    def test_launch_temporary_close_failure_retains_actual_jobs_and_pins(self):
        run = self.prepare_independent()
        fallback = self.kernel.invoke
        failed = []

        def invoke(role, name, args):
            if (role == "supervisor" and name == "CloseHandle" and not failed
                    and (args[0], "temporary") in run.owner.owned):
                failed.append(args[0])
                return 0
            return fallback(role, name, args)

        self.kernel.invoke = invoke
        result = run.run(self.independent_pause)
        self.assertTrue(failed)
        self.assertEqual(result["outcome"], "UNKNOWN")
        self.assertTrue(result["cleanup_responsibility_retained"])
        self.assertIn("inheritance", run.owner.cleanup_errors)
        self.assertTrue(any(kind == "job" for _, kind in run.owner.owned))
        self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
        self.kernel.invoke = fallback
        run.owner.cleanup()
        self.assertFalse(any(self.kernel.tables.values()))

    def test_dormant_native_entries_refuse_before_loading_or_packet_reads(self):
        with patch.object(probe, "load_prepared_backend", side_effect=AssertionError("native gate")):
            with self.assertRaises(PermissionError):
                probe.native_role_entry("native-controller", "00")
            with self.assertRaises(PermissionError):
                probe.native_supervisor_entry("G:\\absent\\packet.json", "a" * 64)
        source = ast.parse((ROOT / backend.SOURCE_FILES[1]).read_text())
        entries = [node for node in source.body if isinstance(node, ast.FunctionDef)
                   and node.name in ("native_role_entry", "native_supervisor_entry")]
        self.assertEqual(len(entries), 2)
        for entry in entries:
            self.assertEqual(entry.body[0].value.func.id, "native_refusal")

    def test_case_journal_is_exclusive_bounded_and_not_restart_authority(self):
        identity = backend.Identity(1, CONFIG, 10, 20, APP)
        journal = backend.CaseJournal(self.temp.name, "human_stop")
        try:
            with self.assertRaises(ValueError):
                journal.persist("STOP_REQUESTED", identity)
            journal.persist("START_INTENT", None)
            journal.persist("IDENTIFIED_SUSPENDED", identity)
            journal.persist("STOP_REQUESTED", identity)
            with self.assertRaises(ValueError):
                journal.persist("START_INTENT", None)
            self.assertLessEqual(journal.size, backend.JOURNAL_LIMIT)
        finally:
            journal.close()
        content = (Path(self.temp.name) / "controller-journal.jsonl").read_bytes()
        self.assertEqual(len(content.splitlines()), 3)
        with self.assertRaises(FileExistsError):
            backend.CaseJournal(self.temp.name, "human_stop")
        self.assertEqual((Path(self.temp.name) / "controller-journal.jsonl").read_bytes(), content)

    def test_run_packet_binds_separate_approval_before_wiring(self):
        prepared = self.prepare_independent()
        packet = {"schema": "windows-harmless-run.v1", "config": dict(self.config),
                  "grant": {**self.grant, "authority": "NATIVE_QUALIFICATION"},
                  "inventory": self.inventory, "physical": prepared.physical,
                  "trusted_host": {"machine": "SYNTHETIC", "account": "synthetic-operator",
                                   "unprivileged_attested": True,
                                   "system_dlls": "TRUSTED_WINDOWS_SYSTEM32",
                                   "runtime_loading": "TRUSTED_PINNED_RUNTIME_ON_TRUSTED_HOST"}}
        raw = backend.bounded_json(packet, 1024 * 1024)
        approved = hashlib.sha256(raw).hexdigest()
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            self.assertEqual(backend.decode_run_packet(raw, approved), packet)
        for wrong_approval in ("0" * 64, packet["grant"], None):
            with self.assertRaises(PermissionError):
                backend.decode_run_packet(raw, wrong_approval)
        with self.assertRaises(PermissionError):
            backend.decode_run_packet(b"x" * (1024 * 1024 + 1), approved)
        for malformed in (raw + b" ", b'{"schema":1,"schema":2}'):
            with self.assertRaises(ValueError):
                backend.decode_run_packet(malformed, hashlib.sha256(malformed).hexdigest())
        self.assertEqual(self.kernel.events, [])
        # Exercise the post-admission orchestration exclusively with injected
        # APIs. The independently scheduled test driver runs the fixed roles.
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            session = probe.wired_supervisor_body(
                backend, packet, self.hooks[0], self.hooks[1], self.independent_pause)
        self.assertTrue(session.run.cleaned)
        self.assertLessEqual(len(session.payload), backend.CASE_RESULT_LIMIT)
        self.assertEqual(json.loads(session.payload)["outcome"], "STUB_EARLY_PRIMARY_EXIT")
        self.assertFalse(any(self.kernel.tables.values()))

    def test_fixed_polling_wrapper_has_no_arbitrary_wait(self):
        import time

        with patch.object(time, "sleep") as sleep:
            clock, pause = probe.fixed_clock_and_pause()
            self.assertIsInstance(clock(), int)
            pause(100_000_000)
            sleep.assert_called_once_with(0.1)
            for value in (0, -1, 100_000_001, True, 100_000_000.0):
                with self.assertRaises(ValueError):
                    pause(value)

    def test_token_elevation_abi_success_and_fixed_rights(self):
        owner = backend.RoleHandles(self.kernel.factory("supervisor", None))
        a, api = owner.a, owner.api
        self.assertEqual(api.OpenProcessToken.argtypes, (a.HANDLE, a.DWORD, a.c.POINTER(a.HANDLE)))
        self.assertEqual(api.GetTokenInformation.argtypes,
                         (a.HANDLE, a.c.c_int32, a.c.c_void_p, a.DWORD, a.c.POINTER(a.DWORD)))
        self.assertTrue(owner.require_non_elevated())
        self.assertEqual([name for _, name in self.kernel.events], [
            "GetCurrentProcess", "OpenProcessToken", "GetTokenInformation", "CloseHandle"])
        self.assertEqual(owner.owned, [])
        self.assertFalse(any(self.kernel.tables.values()))

    def test_elevation_refusals_before_any_pin_job_or_role(self):
        for fault in ("elevated", "unwritten", "short", "large", "open", "query", "close"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                self.kernel.token_elevation = {"elevated": 1, "unwritten": 0xFFFFFFFF}.get(fault, 0)
                self.kernel.token_length = {"short": 3, "large": 5}.get(fault, 4)
                self.kernel.fail = {"open": "OpenProcessToken", "query": "GetTokenInformation",
                                    "close": "CloseHandle"}.get(fault)
                result = run.run(self.independent_pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["current_process_non_elevated"])
                self.assertEqual(result["failure"]["stage"], "TOKEN_PREFLIGHT")
                names = [name for _, name in self.kernel.events]
                self.assertFalse(set(names) & {"CreateFileW", "CreateJobObjectW", "CreateProcessW"})
                if fault == "open":
                    self.assertNotIn("GetTokenInformation", names)
                    self.assertNotIn("CloseHandle", names)
                elif fault == "close":
                    self.assertTrue(result["cleanup_responsibility_retained"])
                    self.assertEqual([kind for _, kind in run.owner.owned], ["token"])
                else:
                    self.assertFalse(any(self.kernel.tables.values()))

    def test_invalid_token_return_is_not_closed_or_used(self):
        for returned in (None, 2**64 - 1):
            self.kernel = RoleKernel()
            original = self.kernel.invoke

            def invoke(role, name, args, value=returned, fallback=original):
                if name == "OpenProcessToken":
                    self.kernel.ptr(args[2], self.kernel.a.HANDLE).value = value
                    return 1
                return fallback(role, name, args)

            self.kernel.invoke = invoke
            owner = backend.RoleHandles(self.kernel.factory("supervisor", None))
            with self.assertRaises(ValueError):
                owner.require_non_elevated()
            self.assertEqual([name for _, name in self.kernel.events],
                             ["GetCurrentProcess", "OpenProcessToken"])
            self.assertEqual(owner.owned, [])

    def test_supervisor_pause_interruption_aborts_once_without_generator_finally(self):
        for phase in ("setup", "observe", "cleanup"):
            with self.subTest(phase=phase):
                self.kernel = RoleKernel()
                run = self.prepare_independent()
                ordinary = self.independent_pause
                original = self.kernel.invoke
                pauses = []

                def invoke(role, name, args, fallback=original, selected=phase):
                    result = fallback(role, name, args)
                    if selected == "cleanup" and name == "QueryInformationJobObject":
                        self.kernel.ptr(args[2], self.kernel.a.BasicAccounting).ActiveProcesses = 1
                    return result

                def pause(amount, driver=ordinary, selected=phase, active=run, seen=pauses):
                    seen.append(amount)
                    if (selected == "setup" or (selected == "observe" and active.live_tick is not None)
                            or (selected == "cleanup" and active.cleanup_started)):
                        raise KeyboardInterrupt
                    driver(amount)

                self.kernel.invoke = invoke
                result = run.run(pause)
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertFalse(result["case_matched_expected_observation"])
                self.assertTrue(run.abort_started)
                before = tuple(self.kernel.events)
                run.abort_owned_once()
                self.assertEqual(tuple(self.kernel.events), before)
                if phase == "cleanup":
                    self.assertTrue(result["cleanup_responsibility_retained"])
                    self.assertTrue(any(kind == "job" for _, kind in run.owner.owned))
                    self.assertTrue(any(kind == "artifact" for _, kind in run.owner.owned))
                else:
                    self.assertTrue(result["owned_cleanup_confirmed"])
                self.assertLess(len(pauses), 351)

    def prepare_session(self):
        prepared = self.prepare_independent()
        packet = {"grant": {**self.grant, "authority": "NATIVE_QUALIFICATION"},
                  "config": self.config, "inventory": self.inventory, "physical": prepared.physical}
        with patch.object(backend, "verify_runtime_inventory", return_value=self.inventory):
            return probe.SupervisorSession(backend, packet, self.hooks[0], self.hooks[1])

    def test_session_success_requires_durable_output_and_remains_stub(self):
        session = self.prepare_session()
        session.execute(self.independent_pause)
        self.assertEqual(session.result["status"], "STUB_ONLY")
        self.assertEqual(session.result["schema"], "windows-harmless-result.v1")
        for key in ("source_sha256", "config_sha256", "runtime_sha256"):
            self.assertEqual(session.result[key], session.run.grant[key])
        self.assertEqual(session.result["generation"], session.run.config["generation"])
        self.assertTrue(session.result["case_matched_expected_observation"])
        self.assertEqual(session.exit_code(), 3)
        output = Path(self.temp.name) / "result.json"
        session.write_result(output)
        self.assertEqual(session.exit_code(), 0)
        self.assertEqual(output.read_bytes(), session.payload)
        self.assertLessEqual(len(session.payload), backend.CASE_RESULT_LIMIT)

    def test_session_serialization_failure_keeps_ownership_and_no_retry(self):
        session = self.prepare_session()
        self.kernel.fail = "QueryInformationJobObject"
        with patch.object(session.run.evidence, "finish", side_effect=ValueError("bad evidence")):
            session.execute(self.independent_pause)
        self.assertTrue(session.entry_failed)
        self.assertEqual(json.loads(session.payload)["outcome"], "UNKNOWN")
        self.assertTrue(any(kind == "artifact" for _, kind in session.run.owner.owned))
        self.assertTrue(any(kind == "job" for _, kind in session.run.owner.owned))
        self.assertEqual(session.exit_code(), 3)

    def test_session_output_failure_never_releases_unconfirmed_pins(self):
        for fault in ("exists", "write", "flush", "fsync"):
            with self.subTest(fault=fault):
                self.kernel = RoleKernel()
                session = self.prepare_session()
                self.kernel.fail = "QueryInformationJobObject"
                session.execute(self.independent_pause)
                before = tuple(session.run.owner.owned)
                output = Path(self.temp.name) / (fault + ".json")
                if fault == "exists":
                    with output.open("xb") as stream:
                        stream.write(b"preserve")
                    session.write_result(output)
                    self.assertEqual(output.read_bytes(), b"preserve")
                elif fault == "fsync":
                    with patch("os.fsync", side_effect=OSError("injected")):
                        session.write_result(output)
                else:
                    with patch.object(Path, "open") as opened:
                        stream = opened.return_value.__enter__.return_value
                        stream.write.return_value = 0 if fault == "write" else len(session.payload)
                        stream.flush.side_effect = OSError("injected")
                        session.write_result(output)
                self.assertEqual(tuple(session.run.owner.owned), before)
                self.assertTrue(session.entry_failed)
                self.assertFalse(session.output_durable)
                self.assertEqual(session.exit_code(), 3)

    def test_fixed_loader_compiles_source_not_cached_code(self):
        import importlib.machinery

        with patch.object(importlib.machinery.SourceFileLoader, "get_code",
                          side_effect=AssertionError("Unpinned cached-code loader")):
            loaded = probe.load_prepared_backend()
        self.assertEqual(loaded.SOURCE_FILES, backend.SOURCE_FILES)
        with self.assertRaises(PermissionError):
            loaded.NativeApi()

    def test_second_supervisor_admission_cannot_replace_owner(self):
        session = self.prepare_session()
        self.assertFalse(self.kernel.events)
        with patch.object(probe, "_RETAINED_SUPERVISOR", None):
            probe.require_unused_supervisor()
            probe.retain_supervisor(session)
            with self.assertRaises(PermissionError):
                probe.require_unused_supervisor()
            with self.assertRaises(PermissionError):
                probe.retain_supervisor(session)
            self.assertIs(probe._RETAINED_SUPERVISOR, session)
            self.assertFalse(self.kernel.events)

    def test_elevation_failure_in_each_role_precedes_target_operations(self):
        for role in ("controller", "observer"):
            for fault in ("elevated", "short", "query", "close"):
                with self.subTest(role=role, fault=fault):
                    self.kernel = RoleKernel()
                    self.prepare_independent()
                    self.kernel.tables[role] = {}
                    handles = tuple(self.kernel.new(role, "pipe", data=bytearray()) for _ in range(3))
                    record = {**self.config, "config_sha256": hashlib.sha256(
                        backend.bounded_json(self.config)).hexdigest(), "started_ns": 0,
                        "deadline_ns": 30 * backend.SECOND}
                    encoded = backend.encode_bootstrap(role, record, handles)
                    worker = backend.PreparedRole(encoded, self.kernel.factory(role, None),
                                                  self.hooks[1], self.hooks[3])
                    self.kernel.token_elevation = int(fault == "elevated")
                    self.kernel.token_length = 3 if fault == "short" else 4
                    self.kernel.fail = {"query": "GetTokenInformation", "close": "CloseHandle"}.get(fault)
                    with self.assertRaises((PermissionError, OSError)):
                        worker.run(self.hooks[2])
                    names = [name for _, name in self.kernel.events]
                    self.assertNotIn("CreateJobObjectW", names)
                    self.assertNotIn("CreateProcessW", names)
                    if fault == "close":
                        self.assertTrue(any(kind == "token" for _, kind in worker.owner.owned))
                    else:
                        self.assertFalse(any(self.kernel.tables.values()))

    def test_fsync_failure_with_complete_success_bytes_is_exit_three(self):
        session = self.prepare_session()
        session.execute(self.independent_pause)
        self.assertTrue(session.result["case_matched_expected_observation"])
        output = Path(self.temp.name) / "complete-but-unconfirmed.json"
        with patch("os.fsync", side_effect=OSError("injected durability failure")):
            session.write_result(output)
        self.assertEqual(output.read_bytes(), session.payload)
        self.assertTrue(json.loads(output.read_bytes())["case_matched_expected_observation"])
        self.assertEqual(session.exit_code(), 3)
        self.assertFalse(session.output_durable)
        self.assertTrue(session.entry_failed)


if __name__ == "__main__":
    unittest.main()
