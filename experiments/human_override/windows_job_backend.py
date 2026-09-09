"""Source-only Windows x64 ABI and retained-handle adapter, injected stubs ONLY.

No DLL loader is present. This is not connected to MockKernel or admission.
Callbacks are trusted test code, not a sandbox for arbitrary Python code.
"""

import ntpath
import threading
from dataclasses import dataclass
from types import FunctionType, SimpleNamespace

JOB_LIST = 0x0002000D
CREATE_FLAGS = 0x00000004 | 0x00080000 | 0x08000000 | 0x00000400
JOB_FLAGS = 0x00002000 | 0x00000200 | 0x00000008
QUERY_RIGHTS = 0x00100000 | 0x00001000
MEMORY_BYTES = 256 * 1024 * 1024
CPU_RATE = 1000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
ERROR_INSUFFICIENT_BUFFER = 122


def native_backend(*_args, **_kwargs):
    """No flag, environment variable or argument can grant native execution."""
    raise PermissionError("SOURCE_ONLY: native loading and execution are not released")


def make_abi():
    """Construct data layouts lazily; never load kernel32 or call Win32.

    Fixed-width integers and UTF-16 avoid Linux c_long/c_wchar ABI mismatches.
    Only x64 pointer layouts are selected. No packed or guessed x86 fallback.
    """
    import ctypes as c

    if c.sizeof(c.c_void_p) != 8:
        raise ValueError("Only the Windows x64 ABI layout is selected")
    dword, word, size, handle = c.c_uint32, c.c_uint16, c.c_size_t, c.c_void_p

    class FileTime(c.Structure):
        _fields_ = [("low", dword), ("high", dword)]

    class BasicLimits(c.Structure):
        _fields_ = [("PerProcessUserTimeLimit", c.c_int64),
                    ("PerJobUserTimeLimit", c.c_int64), ("LimitFlags", dword),
                    ("MinimumWorkingSetSize", size), ("MaximumWorkingSetSize", size),
                    ("ActiveProcessLimit", dword), ("Affinity", size),
                    ("PriorityClass", dword), ("SchedulingClass", dword)]

    class IoCounters(c.Structure):
        _fields_ = [(name, c.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class ExtendedLimits(c.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", size), ("JobMemoryLimit", size),
                    ("PeakProcessMemoryUsed", size), ("PeakJobMemoryUsed", size)]

    class CpuLimits(c.Structure):
        # Only the CpuRate union arm is used; both union and DWORD are 4 bytes.
        _fields_ = [("ControlFlags", dword), ("CpuRate", dword)]

    class StartupInfo(c.Structure):
        _fields_ = [("cb", dword), ("lpReserved", handle), ("lpDesktop", handle),
                    ("lpTitle", handle)] + [(name, dword) for name in (
                        "dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars",
                        "dwYCountChars", "dwFillAttribute", "dwFlags")] + [
                    ("wShowWindow", word), ("cbReserved2", word),
                    ("lpReserved2", handle), ("hStdInput", handle),
                    ("hStdOutput", handle), ("hStdError", handle)]

    class StartupInfoEx(c.Structure):
        _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", handle)]

    class ProcessInformation(c.Structure):
        _fields_ = [("hProcess", handle), ("hThread", handle),
                    ("dwProcessId", dword), ("dwThreadId", dword)]

    p, v, b, w = c.POINTER, c.c_void_p, c.c_int32, c.POINTER(word)
    signatures = {
        "CreateJobObjectW": (handle, (v, w)),
        "SetInformationJobObject": (b, (handle, c.c_int32, v, dword)),
        "InitializeProcThreadAttributeList": (b, (v, dword, dword, p(size))),
        "UpdateProcThreadAttribute": (b, (v, dword, size, v, size, v, p(size))),
        "DeleteProcThreadAttributeList": (None, (v,)),
        "CreateProcessW": (b, (w, w, v, v, b, dword, v, w,
                                p(StartupInfo), p(ProcessInformation))),
        "GetProcessTimes": (b, (handle, p(FileTime), p(FileTime),
                                 p(FileTime), p(FileTime))),
        "QueryFullProcessImageNameW": (b, (handle, dword, w, p(dword))),
        "GetProcessId": (dword, (handle,)),
        "ResumeThread": (dword, (handle,)),
        "TerminateProcess": (b, (handle, dword)),
        "GetCurrentProcess": (handle, ()),
        "DuplicateHandle": (b, (handle, handle, handle, p(handle), dword, b, dword)),
        "WaitForSingleObject": (dword, (handle, dword)),
        "GetExitCodeProcess": (b, (handle, p(dword))),
        "CloseHandle": (b, (handle,)),
    }
    return SimpleNamespace(c=c, DWORD=dword, WORD=word, SIZE_T=size, HANDLE=handle,
                           FileTime=FileTime, BasicLimits=BasicLimits,
                           IoCounters=IoCounters, ExtendedLimits=ExtendedLimits,
                           CpuLimits=CpuLimits, StartupInfo=StartupInfo,
                           StartupInfoEx=StartupInfoEx, ProcessInformation=ProcessInformation,
                           signatures=signatures)


class StubFunction:
    def __init__(self, callback, restype, argtypes):
        if type(callback) is not FunctionType:
            raise TypeError("Only explicit Python test functions are accepted")
        self.callback, self.restype, self.argtypes = callback, restype, argtypes

    def __call__(self, *args):
        if len(args) != len(self.argtypes):
            raise TypeError("Wrong ABI argument count")
        return self.callback(*args)


class StubApi:
    """Bind signature metadata to Python fakes, never a native DLL object."""

    def __init__(self, callbacks, last_error):
        self.abi = make_abi()
        if type(callbacks) is not dict or set(callbacks) != set(self.abi.signatures):
            raise TypeError("An exact, complete stub function table is required")
        if type(last_error) is not FunctionType:
            raise TypeError("An injected last-error function is required")
        self.last_error = last_error
        for name, (result, args) in self.abi.signatures.items():
            setattr(self, name, StubFunction(callbacks[name], result, args))


def wide(abi, value):
    raw = value.encode("utf-16-le") + b"\0\0"
    return (abi.WORD * (len(raw) // 2)).from_buffer_copy(raw)


def exact_path(value):
    if (type(value) is not str or not 4 <= len(value) <= 1024
            or any(ch in value for ch in '\x00"\r\n')
            or value[:3].upper() not in ("F:\\", "G:\\")
            or ntpath.normpath(value) != value):
        raise ValueError("Require a normalized absolute task path on F: or G:")
    return ntpath.normcase(value)


@dataclass(frozen=True)
class Identity:
    generation: int
    config_sha256: str
    pid: int
    creation_time: int
    image: str


class RetainedJob:
    """One-shot stub adapter. Persistence/authentication remain caller obligations.

    Its lock serializes start/stop linearization. There is no reset, PID reopen,
    recovery launch, native factory, or integration with accepted admission code.
    """

    def __init__(self, api, persist):
        if type(api) is not StubApi or type(persist) is not FunctionType:
            raise TypeError("SOURCE_ONLY: exact stub API and persistence hook required")
        self.api, self.a, self.persist = api, api.abi, persist
        self.lock = threading.RLock()
        self.job = self.process = self.thread = None
        self.identity = None
        self.used = self.stopped = False
        self.cleanup_errors = []
        self.query_handles = []

    def _ok(self, result, operation):
        if not result:
            raise OSError(self.api.last_error(), operation)

    def _identity(self, handle, generation, config_sha256):
        a, api = self.a, self.api
        creation, exit_time, kernel, user = (a.FileTime() for _ in range(4))
        self._ok(api.GetProcessTimes(handle, a.c.byref(creation), a.c.byref(exit_time),
                                    a.c.byref(kernel), a.c.byref(user)), "GetProcessTimes")
        pid = api.GetProcessId(handle)
        self._ok(pid, "GetProcessId")
        buffer, length = (a.WORD * 1025)(), a.DWORD(1025)
        self._ok(api.QueryFullProcessImageNameW(handle, 0, buffer, a.c.byref(length)),
                 "QueryFullProcessImageNameW")
        if not 0 < length.value < 1025 or buffer[length.value] != 0:
            raise ValueError("Invalid image length")
        path = bytes(buffer)[:length.value * 2].decode("utf-16-le")
        timestamp = (creation.high << 32) | creation.low
        if not timestamp:
            raise ValueError("Missing creation identity")
        return Identity(generation, config_sha256, pid, timestamp, exact_path(path))

    def start(self, application, cwd, generation, config_sha256):
        """Fixed harmless sleep only; source tests never create a process."""
        with self.lock:
            image = exact_path(application)
            exact_path(cwd)
            if (type(generation) is not int or not 1 <= generation < 2**63
                    or type(config_sha256) is not str or len(config_sha256) != 64
                    or any(ch not in "0123456789abcdef" for ch in config_sha256)):
                raise ValueError("Invalid generation/configuration binding")
            if self.used or self.stopped:
                raise ValueError("One-shot adapter is inhibited")
            self.used = True
            a, api = self.a, self.api
            attribute_list = None
            initialized = False
            try:
                self.persist("START_INTENT", None)
                if self.stopped:
                    raise ValueError("Stop before allocation")
                job = api.CreateJobObjectW(None, None)
                self._ok(job, "CreateJobObjectW")
                self.job = job
                limits = a.ExtendedLimits()
                limits.BasicLimitInformation.LimitFlags = JOB_FLAGS
                limits.BasicLimitInformation.ActiveProcessLimit = 1
                limits.JobMemoryLimit = MEMORY_BYTES
                self._ok(api.SetInformationJobObject(self.job, 9, a.c.byref(limits),
                                                     a.c.sizeof(limits)), "JobLimits")
                cpu = a.CpuLimits(0x1 | 0x4, CPU_RATE)
                self._ok(api.SetInformationJobObject(self.job, 15, a.c.byref(cpu),
                                                     a.c.sizeof(cpu)), "CpuLimits")
                needed = a.SIZE_T()
                sized = api.InitializeProcThreadAttributeList(None, 1, 0, a.c.byref(needed))
                if sized or api.last_error() != ERROR_INSUFFICIENT_BUFFER:
                    raise ValueError("Unexpected attribute sizing result")
                if not 0 < needed.value <= 65536:
                    raise ValueError("Unbounded attribute list")
                attribute_list = a.c.create_string_buffer(needed.value)
                self._ok(api.InitializeProcThreadAttributeList(attribute_list, 1, 0,
                                                               a.c.byref(needed)), "Attributes")
                initialized = True
                jobs = (a.HANDLE * 1)(self.job)
                self._ok(api.UpdateProcThreadAttribute(attribute_list, 0, JOB_LIST, jobs,
                                                       a.c.sizeof(jobs), None, None), "JobList")
                startup = a.StartupInfoEx()
                startup.StartupInfo.cb = a.c.sizeof(startup)
                startup.lpAttributeList = a.c.cast(attribute_list, a.c.c_void_p)
                process_info = a.ProcessInformation()
                command = wide(a, f'"{application}" -I -S -B -c "import time; time.sleep(60)"')
                # Explicit minimal environment, not inherited secrets or Python settings.
                environment = wide(a, f"TEMP={cwd}\0TMP={cwd}\0TMPDIR={cwd}\0")
                self._ok(api.CreateProcessW(wide(a, application), command, None, None, 0,
                                           CREATE_FLAGS, environment, wide(a, cwd),
                                           a.c.cast(a.c.byref(startup),
                                                    a.c.POINTER(a.StartupInfo)),
                                           a.c.byref(process_info)), "CreateProcessW")
                # Capture both returned handles before any operation that can fail.
                self.process, self.thread = process_info.hProcess, process_info.hThread
                if not self.process or not self.thread:
                    raise ValueError("Missing owned process/thread handles")
                self.identity = self._identity(self.process, generation, config_sha256)
                if self.identity.pid != process_info.dwProcessId or self.identity.image != image:
                    raise ValueError("Created process identity mismatch")
                self.persist("IDENTIFIED_SUSPENDED", self.identity)
                if self.stopped or self._identity(self.process, generation, config_sha256) != self.identity:
                    raise ValueError("Stopped or changed before resume")
                if api.ResumeThread(self.thread) != 1:
                    raise ValueError("Unexpected suspend count; do not retry")
                self.persist("RUNNING", self.identity)
                return self.identity
            except BaseException:
                self.stopped = True
                self.close()
                raise
            finally:
                if initialized:
                    try:
                        api.DeleteProcThreadAttributeList(attribute_list)
                    except BaseException:
                        self.stopped = True
                        self.close()
                        raise

    def stop(self):
        with self.lock:
            self.stopped = True
            durable = True
            try:
                self.persist("STOP_REQUESTED", self.identity)
            except Exception:
                durable = False
            if self.process is None or self.identity is None:
                return "UNKNOWN"
            try:
                old = self.identity
                if self._identity(self.process, old.generation, old.config_sha256) != old:
                    return "UNKNOWN"
                self._ok(self.api.TerminateProcess(self.process, 91), "TerminateProcess")
            except (OSError, ValueError):
                return "UNKNOWN"
            return "STUB_STOP_DISPATCHED" if durable else "STUB_STOP_DURABILITY_UNCONFIRMED"

    def query_observer(self):
        """Issue a local, non-inheritable query handle. No process transfer yet."""
        with self.lock:
            if self.process is None or self.identity is None:
                raise ValueError("No retained identity")
            a, api = self.a, self.api
            current = api.GetCurrentProcess()  # pseudo-handle is borrowed, never closed
            duplicate = a.HANDLE()
            self._ok(api.DuplicateHandle(current, self.process, current, a.c.byref(duplicate),
                                         QUERY_RIGHTS, 0, 0), "DuplicateHandle")
            if not duplicate.value:
                raise ValueError("Missing duplicate")
            self.query_handles.append(duplicate.value)
            return QueryObserver(self, duplicate.value, self.identity)

    def close(self):
        """Attempt every owned close even after failure. Never report verified exit.

        Failed handles stay retained for a later cleanup attempt; successful
        closes are never retried. Closing the job intentionally sacrifices work.
        """
        with self.lock:
            self.stopped = True
            for field in ("job", "thread", "process"):
                handle = getattr(self, field)
                if handle is not None:
                    try:
                        self._ok(self.api.CloseHandle(handle), "CloseHandle")
                        setattr(self, field, None)
                    except BaseException:
                        self.cleanup_errors.append(field)
            for handle in self.query_handles[:]:
                try:
                    self._ok(self.api.CloseHandle(handle), "CloseQueryHandle")
                    self.query_handles.remove(handle)
                except BaseException:
                    self.cleanup_errors.append("query")
            return "UNKNOWN" if self.cleanup_errors else "STUB_HANDLES_CLOSED"


class QueryObserver:
    """In-process stub observer; NOT the separately trusted native judge."""

    def __init__(self, owner, handle, identity):
        self.owner, self.handle, self.identity = owner, handle, identity
        self.seen_running = False

    def observe(self, expected):
        # Prevent another controller thread from closing/reusing the numeric
        # handle between the membership check and the last query. This lock is
        # in-process only; native transfer needs separate exclusive ownership.
        with self.owner.lock:
            return self._observe_locked(expected)

    def _observe_locked(self, expected):
        if (type(expected) is not Identity or expected != self.identity
                or self.handle not in self.owner.query_handles):
            return "UNKNOWN"
        old, api, a = self.identity, self.owner.api, self.owner.a
        try:
            if self.owner._identity(self.handle, old.generation, old.config_sha256) != old:
                return "UNKNOWN"
            status = api.WaitForSingleObject(self.handle, 0)
            if status == WAIT_TIMEOUT:
                self.seen_running = True
                return "STUB_RUNNING"
            if status != WAIT_OBJECT_0 or not self.seen_running:
                return "UNKNOWN"
            code = a.DWORD()
            self.owner._ok(api.GetExitCodeProcess(self.handle, a.c.byref(code)), "ExitCode")
            # Even exit code STILL_ACTIVE (259) is an exit code after signaling.
            return "STUB_VERIFIED_PRIMARY_EXIT"
        except (OSError, ValueError):
            return "UNKNOWN"
