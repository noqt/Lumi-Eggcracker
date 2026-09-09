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
                self.assertEqual(len(loaders), 1)
                self.assertIn(loaders[0], list(ast.walk(constructor)))
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
        self.ordinal = 0
        self.fail_ordinal = None
        self.reject_dead_identity = False
        self.partial = None
        self.file_contents = {}

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
                               lambda: 122)

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
            self.ptr(args[2], a.c.c_int32).value = int(self.host_job)
            return 1
        if name == "CreateJobObjectW":
            return self.new(role, "job")
        if name == "SetInformationJobObject":
            obj = self.object(role, args[0])
            kind = a.ExtendedLimits if args[1] == 9 else a.CpuLimits
            obj[args[1]] = bytes(self.ptr(args[2], kind))
            return 1
        if name == "CreatePipe":
            reader = self.new(role, "pipe", data=bytearray())
            writer = self.handle(role, self.tables[role][reader][0])
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
            self.tables[child] = {}
            attrs = self.attributes[role]
            inherited = attrs.get(backend.HANDLE_LIST, [])
            if bool(args[4]) != bool(inherited) or args[5] != backend.CREATE_FLAGS:
                raise ValueError("Wrong atomic launch flags")
            for handle in inherited:
                entry = self.tables[role][handle]
                if not entry[2] or self.objects[entry[0]]["kind"] == "job":
                    raise ValueError("Invalid inheritance")
                self.tables[child][handle] = entry
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


if __name__ == "__main__":
    unittest.main()
