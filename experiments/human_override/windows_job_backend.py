"""Source-only Windows x64 ABI and retained-handle adapter, injected stubs ONLY.

The lazy DLL binder is behind unconditional refusal. Mock admission is unchanged.
Callbacks are trusted test code, not a sandbox for arbitrary Python code.
"""

import hashlib
import json
import ntpath
import os
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
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
HANDLE_LIST = 0x00020002
CREATE_LOCK = threading.RLock()
SECOND = 1_000_000_000
JOURNAL_LIMIT = 8192
CASE_RESULT_LIMIT = 65536 - 3 * 4096 - 2 * 16384 - JOURNAL_LIMIT
JOB_MODES = ("OUTSIDE_ONLY", "REQUIRE_INHERITED_NESTED")
CONFIG_FIELDS = {"application", "cwd", "source", "generation", "case"}
ANCESTOR_KNOWN_FLAGS = 0x7FFF
ANCESTOR_SILENT_BREAKAWAY = 0x1000


def fixed_creation_flags():
    """Only suspended atomic job-list creation; never request parent breakaway."""
    if type(CREATE_FLAGS) is not int or CREATE_FLAGS != 0x08080404:
        raise ValueError("Unselected process creation flags")
    return 0x08080404


def supervisor_job_mode(config):
    """Omitted mode preserves the original outside-only contract and digest."""
    mode = config.get("supervisor_job_mode", "OUTSIDE_ONLY")
    if type(mode) is not str or mode not in JOB_MODES:
        raise ValueError("Unknown supervisor job mode")
    return mode


def native_backend(*_args, **_kwargs):
    """No flag, environment variable or argument can grant native execution."""
    raise PermissionError("SOURCE_ONLY: native loading and execution are not released")


def _bind_prototypes(library, abi, names=None):
    """Set signatures only; tests supply Python functions, never a DLL."""
    for name, (result, args) in abi.signatures.items():
        if names is not None and name not in names:
            continue
        function = getattr(library, name)
        function.restype = result
        function.argtypes = args


class NativeApi:
    """Prepared Win64 binding body. Construction always refuses in this revision."""

    def __init__(self):
        native_backend()  # Unconditional gate before imports, DLL loading or symbol access.
        self.abi = make_abi()
        # Only a later, separately reviewed execution release can reach this body.
        library = self.abi.c.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
        security = self.abi.c.WinDLL("advapi32.dll", use_last_error=True, winmode=0x800)
        security_names = {"OpenProcessToken", "GetTokenInformation"}
        _bind_prototypes(library, self.abi, set(self.abi.signatures) - security_names)
        _bind_prototypes(security, self.abi, security_names)
        for name in self.abi.signatures:
            setattr(self, name, getattr(security if name in security_names else library, name))
        self.last_error = self.abi.c.get_last_error


def _physical(path):
    """Read-only inventory check, not a Windows handle-lock/TOCTOU guarantee."""
    for part in reversed((path, *path.parents)):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Reparse/symlink path refused")
    return path.resolve(strict=True)


def _relative(value):
    if (type(value) is not str or not 1 <= len(value) <= 240
            or "\\" in value or ":" in value or "\0" in value):
        raise ValueError("Invalid inventory name")
    relative = PurePosixPath(value)
    reserved = {"con", "prn", "aux", "nul", "conin$", "conout$", *(f"com{i}" for i in range(10)),
                *(f"lpt{i}" for i in range(10))}
    if (relative.is_absolute() or str(relative) != value or not relative.parts
            or any(part in (".", "..") or part.endswith((".", " "))
                   or part.split(".")[0].lower() in reserved
                   or any(ch in part for ch in '<>"|?*')
                   or any(ord(ch) < 32 for ch in part) for part in relative.parts)):
        raise ValueError("Inventory traversal refused")
    return relative


def runtime_inventory(root, relative_files):
    """Hash an exact selected runtime boundary; never load/execute its files.

    Directory name snapshots detect added/removed import candidates in selected
    directories. Only selected file bytes are hashed; this is not a complete
    Windows DLL inventory. Native use must additionally hold path/file handles.
    """
    if type(relative_files) not in (list, tuple) or not 1 <= len(relative_files) <= 256:
        raise ValueError("Bounded exact file selection required")
    names = [_relative(name).as_posix() for name in relative_files]
    if len({ntpath.normcase(name) for name in names}) != len(names):
        raise ValueError("Duplicate inventory entry")
    base = _physical(Path(root).absolute())
    if not base.is_dir():
        raise ValueError("Runtime root must be a directory")
    files, directories, total = {}, {}, 0
    entry_count = name_bytes = 0
    for name in sorted(names):
        path = _physical(base / name)
        if not path.is_relative_to(base) or not path.is_file():
            raise ValueError("Runtime file escaped boundary")
        before = path.stat()
        if not 0 <= before.st_size <= 16 * 1024 * 1024:
            raise ValueError("Runtime file size exceeds inventory bound")
        total += before.st_size
        if total > 128 * 1024 * 1024:
            raise ValueError("Runtime inventory total exceeds bound")
        digest, count = hashlib.sha256(), 0
        with path.open("rb") as source:
            while block := source.read(65536):
                count += len(block)
                if count > before.st_size:
                    raise ValueError("Runtime file grew while hashing")
                digest.update(block)
        after = path.stat()
        if (count != before.st_size or (before.st_dev, before.st_ino, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_mtime_ns)):
            raise ValueError("Runtime file changed while hashing")
        files[name] = {"size": count, "sha256": digest.hexdigest()}
        directory = path.parent
        while directory.is_relative_to(base):
            key = directory.relative_to(base).as_posix()
            if key not in directories:
                if len(directories) >= 128:
                    raise ValueError("Too many selected runtime directories")
                entries = []
                lookup_names = set()
                for child in directory.iterdir():
                    if len(entries) >= 4096 or len(child.name) > 240:
                        raise ValueError("Runtime directory listing exceeds bound")
                    info = child.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        raise ValueError("Reparse entry in selected import directory")
                    if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                        raise ValueError("Unsupported runtime entry kind")
                    entry_count += 1
                    name_bytes += len(child.name.encode("utf-8"))
                    if entry_count > 8192 or name_bytes > 512 * 1024:
                        raise ValueError("Aggregate runtime listing bound")
                    lookup = ntpath.normcase(child.name)
                    if lookup in lookup_names:
                        raise ValueError("Ambiguous runtime entry alias")
                    lookup_names.add(lookup)
                    entries.append([child.name, "directory" if stat.S_ISDIR(info.st_mode) else "file"])
                directories[key] = sorted(entries)
            if directory == base:
                break
            directory = directory.parent
    return {"schema": "selected-runtime-inventory.v1", "root": str(base),
            "files": files, "directories": directories,
            "system_dlls_verified": False, "path_handles_held": False}


def verify_runtime_inventory(expected):
    if type(expected) is not dict or set(expected) != {
        "schema", "root", "files", "directories", "system_dlls_verified", "path_handles_held"
    }:
        raise ValueError("Malformed runtime inventory")
    bounded_json(expected, 1024 * 1024)
    if (expected["schema"] != "selected-runtime-inventory.v1"
            or type(expected["root"]) is not str or not 1 <= len(expected["root"]) <= 1024
            or expected["system_dlls_verified"] is not False
            or expected["path_handles_held"] is not False
            or type(expected["files"]) is not dict or not 1 <= len(expected["files"]) <= 256):
        raise ValueError("Invalid runtime inventory")
    observed = runtime_inventory(expected["root"], list(expected["files"]))
    if observed != expected:
        raise ValueError("Runtime inventory mismatch")
    return observed


def bounded_json(value, limit=65536):
    """Reject types, depth and aggregate content BEFORE calling the JSON encoder."""
    budget = [0, 0]

    def check(item, depth):
        budget[0] += 1
        if depth > 8 or budget[0] > 40000:
            raise ValueError("Bounded JSON structure limit")
        if type(item) is str:
            if len(item) > 1024:
                raise ValueError("Bounded JSON string limit")
            budget[1] += 6 * len(item) + 2
        elif type(item) in (int, bool) or item is None:
            if type(item) is int and not -(2**63) <= item < 2**64:
                raise ValueError("Bounded JSON integer limit")
            budget[1] += 24
        elif type(item) in (list, tuple, dict):
            if len(item) > 8192:
                raise ValueError("Bounded JSON container limit")
            budget[1] += len(item) + 2
            for key in item:
                if type(item) is dict:
                    if type(key) is not str:
                        raise ValueError("Bounded JSON key type")
                    check(key, depth + 1)
                    check(item[key], depth + 1)
                else:
                    check(key, depth + 1)
        else:
            raise ValueError("Bounded JSON type")
        if budget[1] > limit:
            raise ValueError("Bounded JSON byte budget")

    check(value, 0)
    result = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(result) > limit:
        raise ValueError("Bounded JSON encoded limit")
    return result


class BoundedEvidence:
    """Fixed-schema records; bound values/count BEFORE serialization/allocation."""

    def __init__(self):
        self.rows = []
        self.bytes_written = 0

    def record(self, role, event, generation, monotonic_ns, outcome):
        if (type(role) is not str or role not in (
                "supervisor", "controller", "target", "observer", "canary")
                or type(event) is not str or not 1 <= len(event) <= 32
                or not event.isascii() or not event.replace("_", "").isalnum()
                or type(outcome) is not str or outcome not in (
                    "INTENDED", "STUB", "OBSERVED", "UNKNOWN", "REFUSED")
                or type(generation) is not int or not 1 <= generation < 2**63
                or type(monotonic_ns) is not int or not 0 <= monotonic_ns < 2**63
                or len(self.rows) >= 128):
            raise ValueError("Evidence schema/count limit")
        row = {"role": role, "event": event, "generation": generation,
               "monotonic_ns": monotonic_ns, "outcome": outcome}
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        # Reserve pipe buffers and both bounded role bootstrap wire records.
        if self.bytes_written + len(encoded) > CASE_RESULT_LIMIT:
            raise ValueError("Evidence byte limit")
        self.rows.append(row)
        self.bytes_written += len(encoded)
        return encoded

    def finish(self):
        if type(self.rows) is not list or len(self.rows) > 128:
            raise ValueError("Invalid final evidence")
        checked = BoundedEvidence()
        for row in self.rows:
            if type(row) is not dict or set(row) != {
                    "role", "event", "generation", "monotonic_ns", "outcome"}:
                raise ValueError("Invalid final evidence schema")
            checked.record(**row)
        if checked.bytes_written != self.bytes_written:
            raise ValueError("Evidence accounting changed")
        return tuple(tuple(sorted(row.items())) for row in checked.rows)


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

    class BasicUiRestrictions(c.Structure):
        _fields_ = [("UIRestrictionsClass", dword)]

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

    class FileInformation(c.Structure):
        _fields_ = [("attributes", dword), ("creation", FileTime), ("access", FileTime),
                    ("write", FileTime), ("volume", dword), ("size_high", dword),
                    ("size_low", dword), ("links", dword), ("index_high", dword),
                    ("index_low", dword)]

    class BasicAccounting(c.Structure):
        _fields_ = [("TotalUserTime", c.c_int64), ("TotalKernelTime", c.c_int64),
                    ("ThisPeriodTotalUserTime", c.c_int64), ("ThisPeriodTotalKernelTime", c.c_int64),
                    ("TotalPageFaultCount", dword), ("TotalProcesses", dword),
                    ("ActiveProcesses", dword), ("TotalTerminatedProcesses", dword)]

    p, v, b, w = c.POINTER, c.c_void_p, c.c_int32, c.POINTER(word)
    signatures = {
        "CreateJobObjectW": (handle, (v, w)),
        "SetInformationJobObject": (b, (handle, c.c_int32, v, dword)),
        "TerminateJobObject": (b, (handle, dword)),
        "QueryInformationJobObject": (b, (handle, c.c_int32, v, dword, p(dword))),
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
        "OpenProcessToken": (b, (handle, dword, p(handle))),
        "GetTokenInformation": (b, (handle, c.c_int32, v, dword, p(dword))),
        "DuplicateHandle": (b, (handle, handle, handle, p(handle), dword, b, dword)),
        "WaitForSingleObject": (dword, (handle, dword)),
        "GetExitCodeProcess": (b, (handle, p(dword))),
        "CloseHandle": (b, (handle,)),
        "CreatePipe": (b, (p(handle), p(handle), v, dword)),
        "PeekNamedPipe": (b, (handle, v, dword, p(dword), p(dword), p(dword))),
        "ReadFile": (b, (handle, v, dword, p(dword), v)),
        "WriteFile": (b, (handle, v, dword, p(dword), v)),
        "IsProcessInJob": (b, (handle, handle, p(b))),
        "CreateFileW": (handle, (w, dword, dword, v, dword, dword, handle)),
        "GetFileInformationByHandle": (b, (handle, p(FileInformation))),
        "GetFinalPathNameByHandleW": (dword, (handle, w, dword, dword)),
    }
    return SimpleNamespace(c=c, DWORD=dword, WORD=word, SIZE_T=size, HANDLE=handle,
                           FileTime=FileTime, BasicLimits=BasicLimits,
                           IoCounters=IoCounters, ExtendedLimits=ExtendedLimits,
                           CpuLimits=CpuLimits, BasicUiRestrictions=BasicUiRestrictions,
                           StartupInfo=StartupInfo,
                           StartupInfoEx=StartupInfoEx, ProcessInformation=ProcessInformation,
                           FileInformation=FileInformation, BasicAccounting=BasicAccounting,
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
            or ntpath.splitdrive(value)[0].upper() not in ("F:", "G:")
            or not ntpath.isabs(value)
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
        if type(api) not in (StubApi, NativeApi) or type(persist) is not FunctionType:
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
                                           fixed_creation_flags(), environment, wide(a, cwd),
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
            except Exception:  # noqa: BLE001 - any failed persistence must leave emergency stop usable
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
                    except BaseException:  # noqa: BLE001 - finish other closes, retain UNKNOWN
                        self.cleanup_errors.append(field)
            for handle in self.query_handles[:]:
                try:
                    self._ok(self.api.CloseHandle(handle), "CloseQueryHandle")
                    self.query_handles.remove(handle)
                except BaseException:  # noqa: BLE001 - finish other closes, retain UNKNOWN
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


class RoleHandles(RetainedJob):
    """Prepared role-local primitives. Only the exact injected StubApi is accepted.

    Each instance represents ONE process handle table in the stub scheduler.
    It is not a native process or security boundary. Job handles are never
    transferred; the observer receives only a query/synchronize target handle.
    """

    def __init__(self, api):
        if type(api) not in (StubApi, NativeApi):
            raise TypeError("SOURCE_ONLY: exact injected StubApi required")
        super().__init__(api, lambda *_: None)
        self.owned = []
        self.bound_identities = {}
        self.job_contracts = {}
        self.requires_accounted_cleanup = False
        self.pin_phase, self.pin_index = "NOT_STARTED", 0
        self.resume_jobs = {}
        self.immediate_job_query = None

    def own(self, handle, kind):
        if type(handle) is not int or not 0 < handle < 2**64 - 1:
            raise ValueError("Invalid returned owned handle")
        if any(existing == handle for existing, _ in self.owned):
            raise ValueError("Duplicate local ownership")
        self.owned.append((handle, kind))
        return handle

    def release(self, handle):
        entries = [entry for entry in self.owned if entry[0] == handle]
        if len(entries) != 1:
            raise ValueError("Handle not owned by this role")
        self._ok(self.api.CloseHandle(handle), "CloseRoleHandle")
        self.owned.remove(entries[0])
        self.bound_identities.pop(handle, None)
        self.job_contracts.pop(handle, None)
        self.resume_jobs.pop(handle, None)

    def cleanup(self):
        for handle, _ in sorted(self.owned[:], key=lambda entry: entry[1] != "job"):
            try:
                self.release(handle)
            except BaseException:  # noqa: BLE001 - attempt every exact close, retain failures
                self.cleanup_errors.append("role_handle")
        return not self.owned and not self.cleanup_errors

    def require_non_elevated(self):
        """Current process only; fixed TOKEN_QUERY/TokenElevation, never a PID.

        Zero elevation is not an identity, integrity-level or privilege audit.
        Token ownership starts on successful open; a failed close is retained.
        """
        a = self.a
        current = self.api.GetCurrentProcess()
        if current != 2**64 - 1:
            raise ValueError("Expected current-process pseudo-handle")
        token = a.HANDLE()
        self._ok(self.api.OpenProcessToken(current, 0x0008, a.c.byref(token)), "OpenCurrentToken")
        handle = self.own(token.value, "token")
        try:
            elevated, returned = a.DWORD(0xFFFFFFFF), a.DWORD()
            self._ok(self.api.GetTokenInformation(handle, 20, a.c.byref(elevated), 4,
                                                  a.c.byref(returned)), "CurrentTokenElevation")
            if returned.value != 4 or elevated.value != 0:
                raise PermissionError("Elevated or ambiguous current-process token")
        finally:
            try:
                self.release(handle)
            except BaseException:  # Preserve exact token on failed close, then re-raise.
                self.cleanup_errors.append("token")
                raise
        return True

    def job_limit(self, processes, memory_mib, cpu_rate):
        if (processes, memory_mib, cpu_rate) not in (
                (3, 640, 2000), (1, 256, 5000), (1, 128, 2500), (1, 128, 500)):
            raise ValueError("Non-fixed role resource contract")
        a = self.a
        job = self.own(self.api.CreateJobObjectW(None, None), "job")
        limits = a.ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = JOB_FLAGS
        limits.BasicLimitInformation.ActiveProcessLimit = processes
        limits.JobMemoryLimit = memory_mib * 1024 * 1024
        self._ok(self.api.SetInformationJobObject(job, 9, a.c.byref(limits),
                                                 a.c.sizeof(limits)), "RoleJobLimits")
        cpu = a.CpuLimits(5, cpu_rate)
        self._ok(self.api.SetInformationJobObject(job, 15, a.c.byref(cpu),
                                                 a.c.sizeof(cpu)), "RoleCpuLimit")
        self.job_contracts[job] = (processes, memory_mib, cpu_rate)
        return job

    def membership(self, process, job):
        """Exact current/retained process and optional retained job only."""
        if process != 2**64 - 1 and (process, "process") not in self.owned:
            raise ValueError("Membership requires exact owned process")
        if job is not None and (job, "job") not in self.owned:
            raise ValueError("Membership requires exact owned job")
        value = self.a.c.c_int32(-1)
        self._ok(self.api.IsProcessInJob(process, job, self.a.c.byref(value)), "JobMembership")
        if value.value not in (0, 1):
            raise ValueError("Ambiguous membership result")
        return bool(value.value)

    def immediate_job_information(self, kind):
        """Fixed read-only NULL queries; no ancestor handle is obtained."""
        if kind not in (4, 9):
            raise ValueError("Unselected immediate-job query")
        info = self.a.BasicUiRestrictions() if kind == 4 else self.a.ExtendedLimits()
        returned, size = self.a.DWORD(), self.a.c.sizeof(info)
        diagnostic = {"information_class": kind, "returned_bytes": None,
                      "limit_flags": None, "ui_restrictions": None,
                      "refusal": "API_FAILURE"}
        self.immediate_job_query = diagnostic
        self._ok(self.api.QueryInformationJobObject(None, kind, self.a.c.byref(info), size,
                                                   self.a.c.byref(returned)), "ImmediateJobQuery")
        diagnostic["returned_bytes"] = returned.value
        if returned.value != size:
            diagnostic["refusal"] = "RETURN_SIZE"
            raise ValueError("Malformed immediate-job return size")
        if kind == 4:
            diagnostic["ui_restrictions"] = info.UIRestrictionsClass
            if info.UIRestrictionsClass != 0:
                diagnostic["refusal"] = "UI_FLAGS"
                raise ValueError("Immediate-job UI restrictions refused")
            diagnostic["refusal"] = None
            return 0
        basic, flags = info.BasicLimitInformation, info.BasicLimitInformation.LimitFlags
        diagnostic["limit_flags"] = flags
        if flags & (~ANCESTOR_KNOWN_FLAGS | ANCESTOR_SILENT_BREAKAWAY):
            diagnostic["refusal"] = "LIMIT_FLAGS"
            raise ValueError("Unknown or silent-breakaway immediate-job flags")
        checks = (
            (flags & 1 and not 0 < basic.MinimumWorkingSetSize <= basic.MaximumWorkingSetSize,
             "WORKING_SET"),
            (flags & 2 and basic.PerProcessUserTimeLimit <= 0, "PROCESS_TIME"),
            (flags & 4 and basic.PerJobUserTimeLimit <= 0, "JOB_TIME"),
            (flags & 0x44 == 0x44, "TIME_FLAGS"),
            (flags & 8 and basic.ActiveProcessLimit == 0, "ACTIVE_PROCESS"),
            (flags & 0x10 and basic.Affinity == 0, "AFFINITY"),
            (flags & 0x20 and basic.PriorityClass not in
             (0x20, 0x40, 0x80, 0x100, 0x4000, 0x8000), "PRIORITY"),
            (flags & 0x80 and basic.SchedulingClass > 9, "SCHEDULING"),
            (flags & 0x100 and info.ProcessMemoryLimit == 0, "PROCESS_MEMORY"),
            (flags & 0x200 and info.JobMemoryLimit == 0, "JOB_MEMORY"),
            (flags & 0x4000 and not flags & 0x10, "SUBSET_AFFINITY"),
        )
        for rejected, reason in checks:
            if rejected:
                diagnostic["refusal"] = reason
                raise ValueError("Malformed selected immediate-job limits")
        diagnostic["refusal"] = None
        return flags

    def terminate_outer(self, job):
        if ((job, "job") not in self.owned
                or self.job_contracts.get(job) != (3, 640, 2000)):
            raise ValueError("Only exact retained supervisor outer job may be terminated")
        self._ok(self.api.TerminateJobObject(job, 91), "OwnedOuterTermination")

    def active_processes(self, job):
        if (job, "job") not in self.owned:
            raise ValueError("Job accounting requires exact retained owned job")
        info, returned = self.a.BasicAccounting(), self.a.DWORD()
        size = self.a.c.sizeof(info)
        self._ok(self.api.QueryInformationJobObject(job, 1, self.a.c.byref(info), size,
                                                   self.a.c.byref(returned)), "OwnedJobAccounting")
        if returned.value != size or info.ActiveProcesses > info.TotalProcesses:
            raise ValueError("Malformed fixed job accounting")
        return info.ActiveProcesses

    def pipe(self):
        read, write = self.a.HANDLE(), self.a.HANDLE()
        self._ok(self.api.CreatePipe(self.a.c.byref(read), self.a.c.byref(write), None, 4096),
                 "CreatePipe")
        return self.own(read.value, "pipe"), self.own(write.value, "pipe")

    def duplicate(self, handle, destination, rights=QUERY_RIGHTS, inherit=False):
        if rights not in (0, 0x40, QUERY_RIGHTS) or type(inherit) is not bool:
            raise ValueError("Unselected transfer rights")
        duplicate = self.a.HANDLE()
        current = self.api.GetCurrentProcess()
        self._ok(self.api.DuplicateHandle(current, handle, destination,
                                         self.a.c.byref(duplicate), rights, int(inherit),
                                         2 if rights == 0 else 0), "RoleDuplicate")
        if not duplicate.value:
            raise ValueError("Missing role duplicate")
        if destination == current:
            self.own(duplicate.value, "temporary")
        # A remote duplicate belongs ONLY to destination, never CloseHandle here.
        return duplicate.value

    def launch(self, role, application, cwd, source, jobs, inheritance=(), bootstrap=None):
        """Atomic suspended launch; temporary inheritance is globally serialized.

        Source role commands are fixed, not caller code. CLI roles still refuse.
        Bootstrap values are exact inherited local handles, never reopened IDs.
        """
        if role not in ("controller", "observer", "target", "canary"):
            raise ValueError("Invalid fixed role")
        for path in (application, cwd, source):
            exact_path(path)
        if not 1 <= len(jobs) <= 2 or len(inheritance) > 3:
            raise ValueError("Invalid role handle count")
        if bootstrap is not None:
            checked = decode_bootstrap(encode_bootstrap(role, bootstrap, (1, 2, 3)))
            if any(checked[name] != path for name, path in (
                    ("application", application), ("cwd", cwd), ("source", source))):
                raise ValueError("Bootstrap differs from fixed launch paths")
        a, api = self.a, self.api
        temporary, arrays, initialized = [], [], False
        attributes = None
        with CREATE_LOCK:
            try:
                for handle, rights in inheritance:
                    temporary.append(self.duplicate(handle, api.GetCurrentProcess(), rights, True))
                count = 1 + bool(temporary)
                needed = a.SIZE_T()
                sized = api.InitializeProcThreadAttributeList(None, count, 0, a.c.byref(needed))
                if sized or api.last_error() != 122 or not 0 < needed.value <= 65536:
                    raise ValueError("Invalid role attribute size")
                attributes = a.c.create_string_buffer(needed.value)
                self._ok(api.InitializeProcThreadAttributeList(attributes, count, 0,
                                                               a.c.byref(needed)), "RoleAttributes")
                initialized = True
                for key, handles in ((JOB_LIST, jobs), (HANDLE_LIST, temporary)):
                    if handles:
                        array = (a.HANDLE * len(handles))(*handles)
                        arrays.append(array)  # All attribute values live through list deletion.
                        self._ok(api.UpdateProcThreadAttribute(attributes, 0, key, array,
                                                               a.c.sizeof(array), None, None),
                                 "RoleAttribute")
                startup, info = a.StartupInfoEx(), a.ProcessInformation()
                startup.StartupInfo.cb = a.c.sizeof(startup)
                startup.lpAttributeList = a.c.cast(attributes, a.c.c_void_p)
                if role in ("target", "canary"):
                    command = f'"{application}" -I -S -B -c "import time; time.sleep(60)"'
                else:
                    encoded = (encode_bootstrap(role, bootstrap, temporary) if bootstrap is not None
                               else ",".join(str(handle) for handle in temporary))
                    command = (f'"{application}" -I -S -B "{source}" '
                               f'--mode native-{role} --bootstrap {encoded}')
                if len(command) >= 16384:
                    raise ValueError("Fixed role command exceeds bound")
                result = api.CreateProcessW(wide(a, application), wide(a, command), None, None,
                                            int(bool(temporary)), fixed_creation_flags(),
                                            wide(a, f"TEMP={cwd}\0TMP={cwd}\0TMPDIR={cwd}\0"),
                                            wide(a, cwd), a.c.cast(a.c.byref(startup),
                                                                 a.c.POINTER(a.StartupInfo)),
                                            a.c.byref(info))
                self._ok(result, "RoleCreateSuspended")
                process = self.own(info.hProcess, "process")
                thread = self.own(info.hThread, "thread")
                self.resume_jobs[thread] = (process, tuple(jobs))
                self.verify_resume_jobs(thread)
                return process, thread, tuple(temporary)
            except BaseException:
                if not self.requires_accounted_cleanup:
                    self.cleanup()
                raise
            finally:
                try:
                    if initialized:
                        api.DeleteProcThreadAttributeList(attributes)
                finally:
                    for handle in temporary:
                        if any(entry[0] == handle for entry in self.owned):
                            try:
                                self.release(handle)
                            except BaseException:  # noqa: BLE001 - fail closed after every close
                                self.cleanup_errors.append("inheritance")
                    if self.cleanup_errors:
                        if not self.requires_accounted_cleanup:
                            self.cleanup()
                        raise OSError("Temporary inheritance cleanup failed")

    def verify_resume_jobs(self, thread):
        if (thread, "thread") not in self.owned or thread not in self.resume_jobs:
            raise ValueError("Resume requires exact created thread/job binding")
        process, jobs = self.resume_jobs[thread]
        if not all(self.membership(process, job) for job in jobs):
            raise ValueError("Created process missing expected owned job")

    def resume(self, thread):
        self.verify_resume_jobs(thread)
        if self.api.ResumeThread(thread) != 1:
            raise ValueError("Unexpected role suspend count")

    def terminate(self, process):
        if (process, "process") not in self.owned:
            raise ValueError("Termination requires retained created process")
        self._ok(self.api.TerminateProcess(process, 91), "ExactRoleTermination")

    def state(self, handle, identity):
        if not any(entry[0] == handle for entry in self.owned) or type(identity) is not Identity:
            raise ValueError("Missing exclusively retained role handle")
        state = self.api.WaitForSingleObject(handle, 0)
        if state == WAIT_TIMEOUT:
            if self._identity(handle, identity.generation, identity.config_sha256) != identity:
                raise ValueError("Role identity changed")
            self.bound_identities[handle] = identity
            return "LIVE"
        if state != WAIT_OBJECT_0 or self.bound_identities.get(handle) != identity:
            raise ValueError("Role wait failed or no prior live identity")
        code = self.a.DWORD()
        self._ok(self.api.GetExitCodeProcess(handle, self.a.c.byref(code)), "RoleExitCode")
        return "EXIT"


class HeldArtifacts:
    """Prepared held-file verification, exercised only with an injected API.

    Retained directory handles reject rename/delete of those opened directory
    objects; they do NOT prevent adding child entries. This is not dependency
    closure or a substitute for an accepted trusted runtime/OS loading baseline.
    Keep this owner alive across every selected launch and until role cleanup.
    """

    def __init__(self, owner):
        if type(owner) is not RoleHandles or type(owner.api) not in (StubApi, NativeApi):
            raise TypeError("SOURCE_ONLY: exact stub artifact owner required")
        self.owner = owner
        self.handles = {}
        self.used = False

    @staticmethod
    def _path(path):
        if type(path) is str and len(path) == 3 and path[2] == "\\" and path[:2].upper() in ("F:", "G:"):
            return ntpath.normcase(path)
        return exact_path(path)

    def _open(self, path, directory):
        owner, a = self.owner, self.owner.a
        owner.pin_phase = "OPEN_DIRECTORY" if directory else "OPEN_FILE"
        if self._path(path) in self.handles:
            raise ValueError("Duplicate held artifact path")
        handle = owner.api.CreateFileW(wide(a, path), 0 if directory else 0x80000000,
                                      3 if directory else 1, None, 3, 0x02200000, None)
        owner._ok(handle and handle != 2**64 - 1, "OpenPinnedArtifact")
        owner.own(handle, "artifact")
        owner.pin_phase = "FILE_IDENTITY"
        info = a.FileInformation()
        owner._ok(owner.api.GetFileInformationByHandle(handle, a.c.byref(info)), "ArtifactIdentity")
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
            raise ValueError("Reparse/wrong artifact kind")
        buffer = (a.WORD * 1025)()
        owner.pin_phase = "FINAL_PATH"
        length = owner.api.GetFinalPathNameByHandleW(handle, buffer, 1025, 0)
        if not 0 < length < 1025 or buffer[length] != 0:
            raise ValueError("Unbounded final artifact path")
        final = bytes(buffer)[:length * 2].decode("utf-16-le")
        final = final.removeprefix("\\\\?\\")
        if self._path(final) != self._path(path):
            raise ValueError("Artifact path substitution")
        self.handles[self._path(path)] = handle
        return handle, info

    def acquire(self, files):
        self.owner.pin_phase, self.owner.pin_index = "MANIFEST", 0
        if self.used or type(files) is not dict or not 1 <= len(files) <= 256:
            raise ValueError("One-shot exact artifact set required")
        # Metadata only: 256 maximum-length paths plus fixed hash/size records.
        # The default 64 KiB case-evidence budget cannot admit realistic pins.
        bounded_json(files, 2 * 1024 * 1024)
        normalized, total = {}, 0
        for path, expected in files.items():
            key = exact_path(path)
            if (key in normalized or type(expected) is not dict
                    or set(expected) != {"size", "sha256"}
                    or type(expected["size"]) is not int
                    or not 0 <= expected["size"] <= 16 * 1024 * 1024
                    or type(expected["sha256"]) is not str or len(expected["sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in expected["sha256"])):
                raise ValueError("Malformed exact artifact pin")
            total += expected["size"]
            if total > 128 * 1024 * 1024:
                raise ValueError("Artifact total size bound")
            normalized[key] = path
        self.used = True
        owner, a = self.owner, self.owner.a
        try:
            for index, (path, expected) in enumerate(files.items(), 1):
                owner.pin_phase, owner.pin_index = "ANCESTORS", index
                parents, parent = [], ntpath.dirname(path)
                while parent and self._path(parent) not in self.handles:
                    parents.append(parent)
                    next_parent = ntpath.dirname(parent)
                    if next_parent == parent:
                        break
                    parent = next_parent
                if len(self.handles) + len(parents) + 1 > 512:
                    raise ValueError("Artifact ancestor handle bound")
                for directory in reversed(parents):
                    self._open(directory, True)
                handle, before = self._open(path, False)
                owner.pin_phase = "HASH_FILE"
                size = (before.size_high << 32) | before.size_low
                if size != expected["size"]:
                    raise ValueError("Artifact size changed")
                digest, remaining = hashlib.sha256(), size
                while remaining:
                    count = min(65536, remaining)
                    buffer, read = a.c.create_string_buffer(count), a.DWORD()
                    owner._ok(owner.api.ReadFile(handle, buffer, count, a.c.byref(read), None),
                              "HashHeldArtifact")
                    if not 0 < read.value <= count:
                        raise ValueError("Unexpected held artifact read")
                    digest.update(buffer.raw[:read.value])
                    remaining -= read.value
                after = a.FileInformation()
                owner.pin_phase = "RECHECK_FILE"
                owner._ok(owner.api.GetFileInformationByHandle(handle, a.c.byref(after)),
                          "RecheckHeldArtifact")
                # Last-access updates are not content changes.
                fields = ("attributes", "volume", "size_high", "size_low", "index_high", "index_low")
                if (any(getattr(before, name) != getattr(after, name) for name in fields)
                        or bytes(before.write) != bytes(after.write)
                        or digest.hexdigest() != expected["sha256"]):
                    raise ValueError("Held artifact identity/hash changed")
            return tuple(sorted(self.handles))
        except BaseException:
            owner.cleanup()
            raise

    def hold_directory(self, path):
        """Hold the approved case directory and ancestors against rename/delete."""
        pending = []
        parent = path
        while self._path(parent) not in self.handles:
            pending.append(parent)
            next_parent = ntpath.dirname(parent)
            if next_parent == parent:
                break
            parent = next_parent
        if len(self.handles) + len(pending) > 512:
            raise ValueError("Case directory ancestor bound")
        for directory in reversed(pending):
            self._open(directory, True)


WIRE = struct.Struct("<7Q32s")


class FixedChannel:
    """Single reader/writer, at most 16 fixed 88-byte frames per pipe/case.

    Writers run only in expendable controller/observer roles, never supervisor.
    Synchronous writes may stall: the independent supervisor owns their deadline.
    The supervisor only reads a complete available frame using PeekNamedPipe.
    """

    def __init__(self, owner, handle, generation, config_sha256):
        self.owner, self.handle = owner, handle
        self.generation, self.digest = generation, bytes.fromhex(config_sha256)
        self.sent = self.received = 0
        self.last_tick = -1

    def send(self, kind, tick, handle=0, pid=0, creation=0):
        fields = (kind, self.generation, self.sent + 1, tick, handle, pid, creation)
        if (self.sent >= 16 or kind not in range(1, 10)
                or any(type(value) is not int or not 0 <= value < 2**63 for value in fields)):
            raise ValueError("Invalid bounded protocol frame")
        packet = WIRE.pack(*fields, self.digest)
        a, api = self.owner.a, self.owner.api
        written = a.DWORD()
        buffer = a.c.create_string_buffer(packet)
        self.owner._ok(api.WriteFile(self.handle, buffer, len(packet), a.c.byref(written), None),
                       "WriteFrame")
        if written.value != WIRE.size:
            raise ValueError("Partial protocol write")
        self.sent += 1

    def receive(self, now, allow_eof=False):
        a, api = self.owner.a, self.owner.api
        available = a.DWORD()
        peeked = api.PeekNamedPipe(self.handle, None, 0, None, a.c.byref(available), None)
        if not peeked and allow_eof and api.last_error() == 109:
            return None  # Only a closed writer, never malformed evidence.
        self.owner._ok(peeked, "PeekFrame")
        if available.value > 16 * WIRE.size or self.received >= 16:
            raise ValueError("Protocol flood")
        if available.value < WIRE.size:
            return None
        buffer, read = a.c.create_string_buffer(WIRE.size), a.DWORD()
        self.owner._ok(api.ReadFile(self.handle, buffer, WIRE.size, a.c.byref(read), None),
                       "ReadFrame")
        if read.value != WIRE.size:
            raise ValueError("Partial protocol read")
        kind, generation, sequence, tick, handle, pid, creation, digest = WIRE.unpack(buffer.raw)
        if (kind not in range(1, 10) or generation != self.generation or digest != self.digest
                or sequence != self.received + 1 or not self.last_tick <= tick <= now):
            raise ValueError("Stale/forged/out-of-order protocol frame")
        self.last_tick, self.received = tick, sequence
        return kind, tick, handle, pid, creation


class QualificationObserver:
    """Independent-role source state machine, driven in a separate stub table."""

    def __init__(self, owner, inbox, ackbox, outbox, application, generation, config_sha256):
        self.owner, self.inbox, self.ackbox, self.outbox = owner, inbox, ackbox, outbox
        self.application, self.generation, self.config = exact_path(application), generation, config_sha256
        self.handle = self.identity = None
        self.live = False
        self.exited = False
        self.resumed = False

    def step(self, now):
        if self.handle is None:
            frame = self.inbox.receive(now)
            if frame is None:
                return
            kind, _, handle, pid, creation = frame
            if kind != 1 or not handle or not pid or not creation:
                raise ValueError("Missing suspended target handshake")
            self.handle = self.owner.own(handle, "query")
            self.identity = Identity(self.generation, self.config, pid, creation, self.application)
            if self.owner.state(handle, self.identity) != "LIVE":
                raise ValueError("Target exited before identity acknowledgement")
            self.ackbox.send(2, now, handle, pid, creation)
            return
        if self.exited:
            return
        if not self.resumed:
            frame = self.inbox.receive(now)
            if frame is None:
                return
            kind, _, handle, pid, creation = frame
            if (kind != 2 or handle != self.handle or pid != self.identity.pid
                    or creation != self.identity.creation_time):
                raise ValueError("Invalid resume handshake")
            self.resumed = True
        state = self.owner.state(self.handle, self.identity)
        if state == "LIVE" and not self.live:
            self.live = True
            self.outbox.send(3, now, self.handle, self.identity.pid, self.identity.creation_time)
        elif state == "EXIT" and self.live:
            self.exited = True
            self.outbox.send(4, now, self.handle, self.identity.pid, self.identity.creation_time)


class QualificationController:
    """Controller-only target ownership; never shares the kill-on-close job."""

    def __init__(self, owner, destination, outbox, inbox, application, cwd, source, generation, config):
        self.owner, self.destination, self.outbox, self.inbox = owner, destination, outbox, inbox
        self.application, self.cwd, self.source = application, cwd, source
        self.generation, self.config = generation, config
        self.process = self.thread = self.identity = None
        self.inhibited = False
        self.resumed_at = None
        self.remote = None

    def prepare(self, now, persist):
        if self.inhibited or self.process is not None:
            raise ValueError("Restart inhibited")
        persist("START_INTENT", None)
        job = self.owner.job_limit(1, 256, 5000)
        self.process, self.thread, _ = self.owner.launch(
            "target", self.application, self.cwd, self.source, (job,))
        self.identity = self.owner._identity(self.process, self.generation, self.config)
        if self.identity.image != exact_path(self.application):
            raise ValueError("Wrong created target image")
        persist("IDENTIFIED_SUSPENDED", self.identity)
        self.remote = self.owner.duplicate(self.process, self.destination)
        # Fault separation among trusted roles only: PROCESS_DUP_HANDLE is
        # substantial authority. Retain it for no longer than this one transfer.
        self.owner.release(self.destination)
        self.destination = None
        self.outbox.send(1, now, self.remote, self.identity.pid, self.identity.creation_time)

    def step(self, now):
        if self.resumed_at is not None or self.inhibited:
            return
        frame = self.inbox.receive(now)
        if frame is None:
            return
        kind, _, handle, pid, creation = frame
        if (kind != 2 or self.identity is None or handle != self.remote
                or pid != self.identity.pid or creation != self.identity.creation_time):
            raise ValueError("Invalid identity acknowledgement")
        self.resume()
        self.resumed_at = now
        self.outbox.send(2, now, handle, pid, creation)

    def resume(self):
        if self.inhibited or self.identity is None:
            raise ValueError("No admitted target")
        if self.owner.state(self.process, self.identity) != "LIVE":
            raise ValueError("Target identity lost")
        self.owner.resume(self.thread)

    def stop(self, persist):
        self.inhibited = True
        durable = True
        try:
            persist("STOP_REQUESTED", self.identity)
        except Exception:  # noqa: BLE001 - emergency action survives persistence failure
            durable = False
        if self.identity is not None and self.owner.state(self.process, self.identity) == "LIVE":
            self.owner.terminate(self.process)
        return durable


CASES = ("human_stop", "controller_crash", "controller_deadline", "identity_failure",
         "stop_persistence_failure", "suspended_stop", "observer_loss", "supervisor_loss",
         "no_stop_control", "same_instance_restart_refused")
SOURCE_FILES = (
    "experiments/human_override/windows_job_backend.py",
    "experiments/human_override/windows_job_probe.py",
    "tests/test_windows_job_backend.py",
    "docs/windows-whole-vm-human-stop.md",
    "experiments/human_override/windows_vm_contract.v1.json",
)


def encode_bootstrap(role, record, handles):
    """Fixed, bounded parent-created role bootstrap; never caller target code."""
    if type(record) is not dict:
        raise ValueError("Exact role bootstrap required")
    value = dict(record)
    value["role"], value["handles"] = role, list(handles)
    raw = bounded_json(value, 8192)
    encoded = raw.hex()
    decode_bootstrap(encoded)
    return encoded


def decode_bootstrap(encoded):
    # The raw argv string is bounded BEFORE decoding or parsing JSON.
    if (type(encoded) is not str or not 2 <= len(encoded) <= 16384 or len(encoded) % 2
            or any(ch not in "0123456789abcdef" for ch in encoded)):
        raise ValueError("Invalid bounded role bootstrap encoding")
    raw = bytes.fromhex(encoded)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Invalid role bootstrap JSON") from error
    if bounded_json(value, 8192) != raw:
        raise ValueError("Noncanonical/duplicate bootstrap encoding")
    fields = {
            "role", "handles", "application", "cwd", "source", "generation", "case",
            "config_sha256", "started_ns", "deadline_ns"}
    if type(value) is not dict or set(value) not in (fields, fields | {"supervisor_job_mode"}):
        raise ValueError("Unexpected bootstrap fields")
    if type(value["role"]) is not str or value["role"] not in ("controller", "observer"):
        raise ValueError("Invalid independent role")
    handles = value["handles"]
    if (type(handles) is not list or len(handles) != 3
            or any(type(handle) is not int or not 0 < handle < 2**63 for handle in handles)
            or len(set(handles)) != 3):
        raise ValueError("Exact three distinct inherited handles required")
    for name in ("application", "cwd", "source"):
        exact_path(value[name])
    digest = value["config_sha256"]
    if (type(digest) is not str or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
            or type(value["case"]) is not str or value["case"] not in CASES
            or type(value["generation"]) is not int or not 1 <= value["generation"] < 2**63
            or any(type(value[name]) is not int for name in ("started_ns", "deadline_ns"))
            or not 0 <= value["started_ns"] < value["deadline_ns"] < 2**63
            or value["deadline_ns"] - value["started_ns"] != 30 * SECOND):
        raise ValueError("Invalid bootstrap identity/deadline")
    supervisor_job_mode(value)
    config = {name: value[name] for name in CONFIG_FIELDS | {"supervisor_job_mode"} if name in value}
    if hashlib.sha256(bounded_json(config)).hexdigest() != digest:
        raise ValueError("Bootstrap configuration hash mismatch")
    return value


def source_digest():
    root = Path(__file__).resolve().parents[2]
    values = {}
    for name in SOURCE_FILES:
        with (root / name).open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("Source size bound")
        values[name] = hashlib.sha256(content).hexdigest()
    return hashlib.sha256(bounded_json(values)).hexdigest()


def stub_admission(grant, approved, config, inventory, authority="STUB_ONLY"):
    """Compare with a separately trusted exact approval; NEVER native authority.

    Synthetic application aliases are permitted only here, not artifact locks.
    Recomputed inventory is read-only and reports its explicit native gaps.
    No job/process/pipe function may run until this routine has returned.
    """
    if authority not in ("STUB_ONLY", "NATIVE_QUALIFICATION"):
        raise PermissionError("Unselected qualification authority")
    if type(config) is not dict or set(config) not in (
            CONFIG_FIELDS, CONFIG_FIELDS | {"supervisor_job_mode"}):
        raise ValueError("Exact fixed probe configuration required")
    supervisor_job_mode(config)
    for key in ("application", "cwd", "source"):
        exact_path(config[key])
    if (type(config["generation"]) is not int or not 1 <= config["generation"] < 2**63
            or type(config["case"]) is not str or config["case"] not in CASES):
        raise ValueError("Invalid probe generation/case")
    for value in (grant, approved):
        bounded_json(value)
        if type(value) is not dict or set(value) != {
                "authority", "source_sha256", "config_sha256", "runtime_sha256"}:
            raise ValueError("Exact out-of-band stub grant required")
        if value["authority"] != authority:
            raise PermissionError("Native execution not released")
        for key in ("source_sha256", "config_sha256", "runtime_sha256"):
            digest = value[key]
            if (type(digest) is not str or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)):
                raise ValueError("Malformed approval hash")
    if grant != approved:
        raise PermissionError("Grant is not the trusted exact approval")
    if (grant["source_sha256"] != source_digest()
            or grant["config_sha256"] != hashlib.sha256(bounded_json(config)).hexdigest()
            or grant["runtime_sha256"] != hashlib.sha256(bounded_json(inventory, 1024 * 1024)).hexdigest()):
        raise ValueError("Source/config/runtime grant mismatch")
    verify_runtime_inventory(inventory)
    return grant["config_sha256"]


def pin_physical_launch(owner, grant, approved, config, inventory, source_root, sources,
                        authority="STUB_ONLY"):
    """Bind intended launch paths to approved file bytes, then retain file locks.

    Only an injected owner is possible in this revision. No alias fallback:
    application MUST be inventory-root/python.exe and source MUST be the pinned
    probe under source_root. Extra import candidates/system DLLs still require
    an accepted loading baseline; held selected files do not close that gap.
    """
    if type(owner) is not RoleHandles or type(owner.api) not in (StubApi, NativeApi):
        raise TypeError("SOURCE_ONLY: exact artifact owner required")
    owner.pin_phase, owner.pin_index = "BINDING", 0
    for value in (config, grant, approved, sources):
        bounded_json(value)
    bounded_json(inventory, 1024 * 1024)
    if (authority not in ("STUB_ONLY", "NATIVE_QUALIFICATION")
            or type(grant) is not dict or grant != approved or grant.get("authority") != authority
            or type(sources) is not dict or set(sources) != set(SOURCE_FILES)
            or type(inventory) is not dict or type(inventory.get("files")) is not dict):
        raise ValueError("Missing exact physical source/runtime approval")
    runtime_root = exact_path(inventory["root"])
    exact_path(source_root)
    if (exact_path(config["application"]) != exact_path(ntpath.join(runtime_root, "python.exe"))
            or exact_path(config["source"]) != exact_path(
                ntpath.normpath(ntpath.join(source_root, SOURCE_FILES[1])))):
        raise ValueError("Launch application/source not bound to approved roots")
    source_hashes = {}
    pins = {}
    for name, record in sources.items():
        if type(record) is not dict or set(record) != {"sha256", "size"}:
            raise ValueError("Malformed physical source record")
        source_hashes[name] = record["sha256"]
        pins[ntpath.normpath(ntpath.join(source_root, name))] = record
    for name, record in inventory["files"].items():
        relative = _relative(name)
        path = ntpath.normpath(ntpath.join(runtime_root, relative.as_posix()))
        if path in pins:
            raise ValueError("Overlapping source/runtime pin")
        pins[path] = record
    if ("python.exe" not in inventory["files"]
            or hashlib.sha256(bounded_json(source_hashes)).hexdigest() != grant.get("source_sha256")
            or hashlib.sha256(bounded_json(config)).hexdigest() != grant.get("config_sha256")
            or hashlib.sha256(bounded_json(inventory, 1024 * 1024)).hexdigest()
            != grant.get("runtime_sha256")):
        raise ValueError("Physical pin approval hash mismatch")
    artifacts = HeldArtifacts(owner)
    artifacts.acquire(pins)
    if authority == "NATIVE_QUALIFICATION":
        owner.pin_index = 0  # The case directory is not a manifest file ordinal.
        artifacts.hold_directory(config["cwd"])
    return artifacts


class CaseJournal:
    """Exclusive bounded qualification log, NOT durable restart admission.

    Native wiring first validates and holds the approved case directory. Tests
    may use their own disposable directory. Existing files are never replaced.
    """

    def __init__(self, directory, case):
        self.directory = Path(directory)
        _physical(self.directory)
        if not self.directory.is_absolute() or not self.directory.is_dir() or case not in CASES:
            raise ValueError("Exact case directory required")
        self.case, self.count, self.size = case, 0, 0
        self.stream = (self.directory / "controller-journal.jsonl").open("xb")

    def persist(self, phase, identity):
        if (phase not in ("START_INTENT", "IDENTIFIED_SUSPENDED", "STOP_REQUESTED")
                or self.count >= 3 or (identity is not None and type(identity) is not Identity)):
            raise ValueError("Invalid bounded journal phase/identity")
        expected = ("START_INTENT", "IDENTIFIED_SUSPENDED", "STOP_REQUESTED")[self.count]
        if phase != expected or (phase == "START_INTENT") != (identity is None):
            raise ValueError("Out-of-order qualification persistence")
        if ((self.case == "identity_failure" and phase == "IDENTIFIED_SUSPENDED")
                or (self.case == "stop_persistence_failure" and phase == "STOP_REQUESTED")):
            raise OSError("Selected synthetic persistence-failure case")
        record = {"phase": phase, "identity": None if identity is None else {
            "generation": identity.generation, "config_sha256": identity.config_sha256,
            "pid": identity.pid, "creation_time": identity.creation_time}}
        payload = bounded_json(record, 2048) + b"\n"
        if self.size + len(payload) > JOURNAL_LIMIT:
            raise ValueError("Qualification journal byte limit")
        if self.stream.write(payload) != len(payload):
            raise OSError("Partial qualification journal write")
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.count += 1
        self.size += len(payload)

    def close(self):
        self.stream.close()


def decode_run_packet(raw, approved_sha256):
    """Pure bounded packet admission; approval digest is supplied out of band.

    Knowing a digest is not privilege or cryptographic operator authentication.
    The separate trusted run grant must name this exact digest and command.
    This decoder performs no native call and never creates NativeApi.
    """
    if (type(raw) is not bytes or not 1 <= len(raw) <= 1024 * 1024
            or type(approved_sha256) is not str or len(approved_sha256) != 64
            or hashlib.sha256(raw).hexdigest() != approved_sha256):
        raise PermissionError("Packet differs from separately approved identity")
    try:
        packet = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Malformed bounded run packet") from error
    if bounded_json(packet, 1024 * 1024) != raw:
        raise ValueError("Noncanonical or duplicate packet fields")
    if type(packet) is not dict or set(packet) != {
            "schema", "grant", "config", "inventory", "physical", "trusted_host"}:
        raise ValueError("Exact qualification packet required")
    if packet["schema"] != "windows-harmless-run.v1":
        raise ValueError("Unknown qualification packet schema")
    host = packet["trusted_host"]
    if (type(host) is not dict or set(host) != {
            "machine", "account", "unprivileged_attested", "system_dlls", "runtime_loading"}
            or any(type(host[key]) is not str or not 1 <= len(host[key]) <= 128
                   for key in ("machine", "account"))
            or host["unprivileged_attested"] is not True
            or host["system_dlls"] != "TRUSTED_WINDOWS_SYSTEM32"
            or host["runtime_loading"] != "TRUSTED_PINNED_RUNTIME_ON_TRUSTED_HOST"):
        raise ValueError("Explicit reviewed trusted-host baseline required")
    config, physical = packet["config"], packet["physical"]
    if (type(physical) is not dict or set(physical) != {"source_root", "sources"}
            or type(physical["sources"]) is not dict or set(physical["sources"]) != set(SOURCE_FILES)):
        raise ValueError("Exact five physical source records required")
    stub_admission(packet["grant"], packet["grant"], config, packet["inventory"],
                   authority="NATIVE_QUALIFICATION")
    # The grant above is authenticated by the independently approved *whole
    # packet* digest, not by pretending that its self-comparison grants access.
    for path in (config["application"], config["cwd"], config["source"], physical["source_root"]):
        if ntpath.splitdrive(exact_path(path))[0].upper() not in ("F:", "G:"):
            raise ValueError("Qualification paths must remain on approved data drives")
    if config["case"] != "human_stop":
        raise ValueError("Only one human_stop case is selected for initial native qualification")
    return packet


class PreparedRole:
    """One independently pollable role, constructed ONLY from its fixed bootstrap.

    No supervisor or sibling object is available. The caller schedules this
    role's steps, or runs its own loop via run(). All API calls remain injected.
    Protocol kinds: 1 identity; 2 ACK/resume; 3 LIVE; 4 EXIT; 5 stop intent/ACK;
    6 durable stop completion; 7 matched LIVE; 8 failure; 9 restart refusal.
    Stop cases are fixed local test actions, not an interactive human-stop UI.
    """

    def __init__(self, encoded, api, clock, persist):
        value = decode_bootstrap(encoded)  # Before any API call or ownership.
        if type(api) not in (StubApi, NativeApi) or any(type(hook) is not FunctionType
                                         for hook in (clock, persist)):
            raise TypeError("SOURCE_ONLY: exact role API and hooks required")
        self.value, self.clock, self.persist = value, clock, persist
        self.owner = owner = RoleHandles(api)
        self.last_tick = value["started_ns"]
        self.failed = self.finished = False
        self.live_tick = self.intent_tick = None
        self.completion = None
        self.sent_exit = self.sent_control = False
        handles = value["handles"]
        for handle in handles:
            owner.own(handle, "inherited")

        def channel(handle):
            return FixedChannel(owner, handle, value["generation"], value["config_sha256"])

        if value["role"] == "controller":
            self.machine = QualificationController(
                owner, handles[0], channel(handles[1]), channel(handles[2]),
                value["application"], value["cwd"], value["source"], value["generation"],
                value["config_sha256"])
        else:
            self.machine = QualificationObserver(
                owner, channel(handles[0]), channel(handles[1]), channel(handles[2]),
                value["application"], value["generation"], value["config_sha256"])

    def now(self):
        tick = self.clock()
        if type(tick) is not int or not self.last_tick <= tick < 2**63:
            raise ValueError("Role monotonic clock failure")
        self.last_tick = tick
        return tick

    def frame(self, channel, kind, now):
        machine = self.machine
        handle = machine.remote if self.value["role"] == "controller" else machine.handle
        channel.send(kind, now, handle, machine.identity.pid, machine.identity.creation_time)

    def bound_frame(self, channel, now, allow_eof=False):
        frame = channel.receive(now, allow_eof=allow_eof)
        if frame is not None:
            machine = self.machine
            handle = machine.remote if self.value["role"] == "controller" else machine.handle
            if frame[2:] != (handle, machine.identity.pid, machine.identity.creation_time):
                raise ValueError("Role frame identity mismatch")
        return frame

    def controller_step(self, now):
        machine, case = self.machine, self.value["case"]
        if machine.process is None:
            machine.prepare(now, self.persist)
            if case == "suspended_stop":
                machine.stop(self.persist)
                self.failed = True
            return
        if machine.resumed_at is None:
            machine.step(now)
            return
        if self.completion is not None:
            return
        if self.live_tick is None:
            frame = self.bound_frame(machine.inbox, now)
            if frame is not None:
                if frame[0] != 3 or frame[1] < machine.resumed_at:
                    raise ValueError("Expected independent post-resume LIVE acknowledgement")
                self.live_tick = now  # Receiver clock, never controller-selected event time.
            return
        if case not in ("human_stop", "stop_persistence_failure", "same_instance_restart_refused"):
            return
        if self.intent_tick is None and now >= self.live_tick + SECOND:
            self.frame(machine.outbox, 5, now)
            self.intent_tick = now
            return
        if self.intent_tick is not None:
            frame = self.bound_frame(machine.inbox, now)
            if frame is None:
                return
            if frame[0] != 5 or frame[1] < self.intent_tick:
                raise ValueError("Expected observer stop-intent acknowledgement")
            durable = machine.stop(self.persist)
            self.completion = 6 if durable else 8
            if case == "same_instance_restart_refused" and durable:
                try:
                    machine.prepare(now, self.persist)
                except ValueError:
                    self.completion = 9
                else:
                    raise ValueError("Same-instance restart bypass")
            self.frame(machine.outbox, self.completion, self.now())

    def observer_step(self, now):
        machine = self.machine
        if machine.handle is None or not machine.resumed:
            machine.step(now)
            if machine.live:
                self.live_tick = now
                self.frame(machine.ackbox, 3, now)
            elif machine.resumed:
                raise ValueError("No post-resume observed LIVE")
            return
        if not self.failed:
            try:
                frame = self.bound_frame(machine.inbox, now, allow_eof=True)
                if frame is not None:
                    kind = frame[0]
                    if kind == 5 and self.intent_tick is None and self.live_tick < now:
                        self.intent_tick = now
                        self.frame(machine.outbox, 5, now)
                        self.frame(machine.ackbox, 5, now)
                    elif kind in (6, 8, 9) and self.intent_tick is not None and self.completion is None:
                        self.completion = kind
                        self.frame(machine.outbox, kind, now)
                    else:
                        raise ValueError("Unexpected observer control frame")
            except (OSError, ValueError):
                self.failed = True
                self.frame(machine.outbox, 8, now)
        # Malformed/closed controller channels cannot suppress actual query
        # evidence, but malformed input permanently prevents a passing verdict.
        state = self.owner.state(machine.handle, machine.identity)
        if state == "EXIT" and not self.sent_exit:
            # Human cases need completion/persistence status as well as intent.
            # On missing completion keep querying until the supervisor deadline.
            if (self.intent_tick is None or self.completion is not None or self.failed):
                self.frame(machine.outbox, 4, now)
                self.sent_exit = True
        elif (state == "LIVE" and self.value["case"] == "no_stop_control"
              and not self.sent_control and now >= self.live_tick + 5 * SECOND):
            self.frame(machine.outbox, 7, now)
            self.sent_control = True

    def steps(self):
        """Cooperative test entry; no cross-role scheduling inside this loop."""
        self.owner.require_non_elevated()
        for _ in range(351):
            now = self.now()
            if now >= self.value["deadline_ns"] + 5 * SECOND:
                break
            if self.value["role"] == "observer":
                self.observer_step(now)
            elif not self.failed:
                self.controller_step(now)
            yield 100_000_000
        self.finished = True

    def run(self, pause):
        """Own-role loop; a future process uses its own clock/wait, not a sibling."""
        if type(pause) is not FunctionType:
            raise TypeError("Exact role pause hook required")
        try:
            for delay in self.steps():
                pause(delay)
        finally:
            self.owner.cleanup()


class PreparedQualification:
    """Strict launch + independent supervisor loop; injected APIs ONLY.

    Unlike the legacy regression scheduler below, this object never constructs,
    calls or reads a controller/observer object. Roles receive only immutable
    bootstrap bytes and three exact inherited handles. Cleanup retains pins and
    process handles on unconfirmed death, forbidding a subsequent case.
    """

    def __init__(self, grant, approved, config, inventory, physical, api_factory, clock,
                 authority="STUB_ONLY"):
        self.digest = stub_admission(grant, approved, config, inventory, authority)
        self.authority = authority
        if (type(physical) is not dict or set(physical) != {"source_root", "sources"}
                or any(type(hook) is not FunctionType for hook in (api_factory, clock))):
            raise ValueError("Mandatory strict pins and exact supervisor hooks required")
        self.grant, self.approved = dict(grant), dict(approved)
        self.config, self.inventory, self.physical = dict(config), inventory, physical
        self.factory, self.clock = api_factory, clock
        self.owner = self.artifacts = None
        self.outer = None
        self.roles, self.jobs = {}, []
        self.evidence = BoundedEvidence()
        self.used = False
        self.last_tick = 0
        self.live_tick = self.intervention = self.intent_receipt = None
        self.live_observed_tick = None
        self.expected = self.completion = None
        self.protocol_valid = True
        self.outcome = "UNKNOWN"
        self.canary_live = self.cleaned = False
        self.cleanup_started = self.abort_started = False
        self.non_elevated = False
        self.stage, self.failure = "SETUP", None
        self.supervisor_in_job = None
        self.immediate_job_flags = None
        self.immediate_job_ui = None
        self.cleanup_operation = None
        self.cleanup_termination_rechecks = []

    def note_failure(self, error):
        """First failure only; no exception text, paths, arguments or type names."""
        if self.failure is not None:
            return
        stages = ("SETUP", "TOKEN_PREFLIGHT", "PIN_ADMISSION", "HOST_JOB",
                  "HOST_JOB_MEMBERSHIP", "HOST_JOB_LIMITS", "HOST_JOB_UI",
                  "HOST_JOB_DEADLINE", "JOBS",
                  "PIPES", "ROLES", "OBSERVE", "CLEANUP", "SERIALIZE", "OUTPUT")
        phases = ("NOT_STARTED", "BINDING", "MANIFEST", "ANCESTORS", "OPEN_DIRECTORY",
                  "OPEN_FILE", "FILE_IDENTITY", "FINAL_PATH", "HASH_FILE", "RECHECK_FILE")
        stage = self.stage if type(self.stage) is str and self.stage in stages else "UNKNOWN"
        phase, index = "NOT_STARTED", 0
        if stage == "PIN_ADMISSION" and self.owner is not None:
            phase, index = self.owner.pin_phase, self.owner.pin_index
        phase = phase if type(phase) is str and phase in phases else "UNKNOWN"
        index = index if type(index) is int and 0 <= index <= 256 else 0
        category = ("PERMISSION" if isinstance(error, PermissionError) else
                    "OS_ERROR" if isinstance(error, OSError) else
                    "VALUE" if isinstance(error, ValueError) else
                    "TYPE" if isinstance(error, TypeError) else
                    "INTERRUPTED" if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit))
                    else "OTHER")
        code, domain = None, "NONE"
        if isinstance(error, OSError):
            for field, label in (("winerror", "WINERROR"), ("errno", "ERRNO")):
                candidate = getattr(error, field, None)
                if type(candidate) is int and 0 <= candidate < 2**32:
                    code, domain = candidate, label
                    break
        self.failure = {"stage": stage, "error_class": category, "code": code,
                        "code_domain": domain, "pin_phase": phase, "pin_index": index,
                        "cleanup_operation": (
                            self.cleanup_operation if stage == "CLEANUP" and
                            self.cleanup_operation in (
                                "TERMINATE_OUTER", "PRE_TERMINATE_WAIT", "TERMINATE_PROCESS",
                                "POST_TERMINATE_WAIT", "WAIT_ALL", "CLOSE_DEAD", "QUERY_EMPTY",
                                "CLOSE_REMAINDER") else None)}

    def now(self):
        tick = self.clock()
        if type(tick) is not int or not self.last_tick <= tick < 2**63:
            raise ValueError("Supervisor monotonic clock failure")
        self.last_tick = tick
        return tick

    def record(self, event, outcome="STUB"):
        if outcome == "STUB" and self.is_native():
            outcome = "OBSERVED"
        self.evidence.record("supervisor", event, self.config["generation"], self.now(), outcome)

    def is_native(self):
        return (self.owner is not None and type(self.owner.api) is NativeApi
                and self.authority == "NATIVE_QUALIFICATION")

    def setup(self):
        c = self.config
        self.started = self.now()
        self.deadline = self.started + 30 * SECOND
        self.owner = sup = RoleHandles(self.factory("supervisor", None))
        sup.requires_accounted_cleanup = True
        if type(sup.api) is NativeApi and self.authority != "NATIVE_QUALIFICATION":
            raise PermissionError("Native API needs separate native authority")
        self.stage = "TOKEN_PREFLIGHT"
        self.non_elevated = sup.require_non_elevated()
        self.stage = "PIN_ADMISSION"
        self.artifacts = pin_physical_launch(
            sup, self.grant, self.approved, c, self.inventory,
            self.physical["source_root"], self.physical["sources"], self.authority)
        self.stage = "HOST_JOB"
        self.supervisor_in_job = sup.membership(sup.api.GetCurrentProcess(), None)
        mode = supervisor_job_mode(c)
        if self.supervisor_in_job != (mode == "REQUIRE_INHERITED_NESTED"):
            self.stage = "HOST_JOB_MEMBERSHIP"
            raise ValueError("Unqualified supervisor job")
        if mode == "REQUIRE_INHERITED_NESTED":
            self.stage = "HOST_JOB_LIMITS"
            self.immediate_job_flags = sup.immediate_job_information(9)
            self.stage = "HOST_JOB_UI"
            self.immediate_job_ui = sup.immediate_job_information(4)
        self.stage = "HOST_JOB_DEADLINE"
        if self.now() >= self.deadline - SECOND:
            raise ValueError("Overdue setup")
        self.stage = "JOBS"
        self.outer = outer = sup.job_limit(3, 640, 2000)
        observer_job = sup.job_limit(1, 128, 2500)
        canary_job = sup.job_limit(1, 128, 500)
        self.jobs = [outer, observer_job, canary_job]
        self.stage = "PIPES"
        query_read, query_write = sup.pipe()
        ack_read, ack_write = sup.pipe()
        report_read, report_write = sup.pipe()
        bootstrap = {**c, "config_sha256": self.digest, "started_ns": self.started,
                     "deadline_ns": self.deadline}
        self.stage = "ROLES"
        for role in ("observer", "canary", "controller"):
            jobs = ((outer, observer_job) if role == "observer" else
                    (canary_job,) if role == "canary" else (outer,))
            inheritance = (((query_read, 0), (ack_write, 0), (report_write, 0))
                           if role == "observer" else () if role == "canary" else
                           ((self.roles["observer"][0], 0x40), (query_write, 0), (ack_read, 0)))
            process, thread, _ = sup.launch(
                role, c["application"], c["cwd"], c["source"], jobs, inheritance,
                bootstrap if role != "canary" else None)
            identity = sup._identity(process, c["generation"], self.digest)
            self.roles[role] = (process, thread, identity)
            if sup.state(process, identity) != "LIVE" or self.now() >= self.deadline - SECOND:
                raise ValueError("Created role identity or setup deadline failure")
        self.reports = FixedChannel(sup, report_read, c["generation"], self.digest)
        for handle in (query_read, query_write, ack_read, ack_write, report_write):
            sup.release(handle)
        for _, thread, _ in self.roles.values():
            if self.now() >= self.deadline - SECOND:
                raise ValueError("Role resume deadline exceeded")
            sup.resume(thread)
        self.record("roles_started")

    def canary_state(self):
        process, _, identity = self.roles["canary"]
        return self.owner.state(process, identity) == "LIVE"

    def accept_frame(self, frame, now):
        kind, tick, handle, pid, creation = frame
        identity = (handle, pid, creation)
        if not self.started <= tick <= now <= self.deadline + 5 * SECOND:
            raise ValueError("Observer report outside admitted case time")
        if kind == 3 and self.live_tick is None and all(identity) and now < self.deadline:
            self.live_tick, self.expected = now, identity  # Supervisor receipt time.
            self.live_observed_tick = tick
            self.record("live_report_received")
            return False
        if identity != self.expected or self.live_tick is None:
            raise ValueError("Unbound observer result")
        if kind == 8:
            self.protocol_valid = False
            self.record("role_failure", "UNKNOWN")
        elif (kind == 5 and self.intent_receipt is None and self.live_tick < now
              and self.config["case"] in ("human_stop", "stop_persistence_failure",
                                          "same_instance_restart_refused")):
            self.intent_receipt = now
            self.intervention = now
            self.record("stop_intent_received")
        elif (kind in (6, 9) and self.intent_receipt is not None and self.completion is None
              and (kind != 9 or self.config["case"] == "same_instance_restart_refused")):
            self.completion = kind
            self.record("stop_completion_received")
        elif kind == 4:
            self.record("observed_exit_report")
            self.canary_live = self.canary_state()
            human = self.config["case"] in (
                "human_stop", "stop_persistence_failure", "same_instance_restart_refused")
            completed = (self.completion == (9 if self.config["case"] ==
                         "same_instance_restart_refused" else 6)) if human else True
            if (self.protocol_valid and completed and self.intervention is not None
                    and self.live_tick < self.intervention <= tick <= now
                    and now <= self.intervention + 4 * SECOND
                    and now < self.started + 60 * SECOND and self.canary_live):
                self.outcome = "STUB_EARLY_PRIMARY_EXIT"
            return True
        elif (kind == 7 and self.config["case"] == "no_stop_control"
              and tick >= self.live_observed_tick + 5 * SECOND and self.intervention is None):
            self.canary_live = self.canary_state()
            if self.protocol_valid and self.canary_live:
                self.outcome = "STUB_MATCHED_LIVE_CONTROL"
            return True
        else:
            raise ValueError("Unexpected observer report order")
        return False

    def intervene(self, now):
        case = self.config["case"]
        if self.live_tick is not None and now >= self.live_tick + SECOND:
            if case == "controller_crash" and self.intervention is None:
                self.owner.terminate(self.roles["controller"][0])
                self.intervention = self.now()
                self.record("controller_crash_dispatched")
            elif case == "observer_loss":
                self.owner.terminate(self.roles["observer"][0])
                self.record("observer_loss", "UNKNOWN")
                return True
            elif case == "supervisor_loss":
                self.record("supervisor_loss", "UNKNOWN")
                return True  # Cleanup models supervisor-table loss, not a receipt.
        if now >= self.deadline - SECOND and self.intervention is None:
            self.owner.terminate(self.roles["controller"][0])
            self.intervention = self.now()
            self.protocol_valid &= self.intervention <= self.deadline
            if case == "human_stop":
                self.protocol_valid = False  # Deadline cleanup never passes the human-stop case.
            self.record("deadline_intervention")
        return self.intervention is not None and now > self.intervention + 4 * SECOND

    def steps(self):
        if self.used:
            raise ValueError("One-shot prepared qualification cannot restart")
        self.used = True
        try:
            self.setup()
            self.stage = "OBSERVE"
            for _ in range(351):
                now = self.now()
                if now > self.deadline + 5 * SECOND:
                    break
                frame = self.reports.receive(now)
                if frame is not None and self.accept_frame(frame, now):
                    break
                if self.intervene(self.now()):
                    break
                yield 100_000_000
        except (OSError, ValueError, PermissionError) as error:
            self.note_failure(error)
            self.outcome = "UNKNOWN"
            self.evidence.record("supervisor", "case_error", self.config["generation"],
                                 self.last_tick, "UNKNOWN")
        # Never yield in finally: close()/GeneratorExit must not start cleanup.
        # The driving run() owns exceptional abort; normal iteration drains it.
        if self.owner is not None:
            yield from self.cleanup_steps()
        else:
            self.cleaned = True  # No API owner or acquired capabilities.
        return self.result()

    def result(self):
        self.stage = "SERIALIZE"
        if not self.cleaned or not self.protocol_valid:
            self.outcome = "UNKNOWN"
        native = self.is_native()
        outcome = self.outcome.removeprefix("STUB_") if native else self.outcome
        return {"schema": "windows-harmless-result.v1",
                "status": "NATIVE_QUALIFICATION_RUN" if native else "STUB_ONLY",
                "generation": self.config["generation"], "config_sha256": self.digest,
                "source_sha256": self.grant["source_sha256"],
                "runtime_sha256": self.grant["runtime_sha256"],
                "supervisor_job_mode": supervisor_job_mode(self.config),
                "supervisor_in_job": self.supervisor_in_job,
                "immediate_job_limit_flags": self.immediate_job_flags,
                "immediate_job_breakaway_ok": (None if self.immediate_job_flags is None
                                               else bool(self.immediate_job_flags & 0x800)),
                "immediate_job_ui_restrictions": self.immediate_job_ui,
                "immediate_job_query": self.owner.immediate_job_query,
                "ancestor_chain_validated": False,
                "case": self.config["case"], "outcome": outcome,
                "launch_pins": (("HELD_NATIVE_OBJECTS" if native else "HELD_STUB_OBJECTS")
                                if self.artifacts else "REFUSED"),
                "restart_safety": "UNQUALIFIED", "owned_cleanup_confirmed": self.cleaned,
                "owned_stub_cleanup": self.cleaned and not native,
                "current_process_non_elevated": self.non_elevated,
                "protocol_valid": self.protocol_valid,
                "failure": self.failure,
                "cleanup_termination_rechecks": self.cleanup_termination_rechecks,
                "case_matched_expected_observation": (
                    self.config["case"] == "human_stop" and self.cleaned and self.protocol_valid
                    and self.outcome == "STUB_EARLY_PRIMARY_EXIT" and self.canary_live),
                "canary_live_before_cleanup": self.canary_live,
                "cleanup_responsibility_retained": not self.cleaned,
                "terminal_cleanup": ("CONFIRMED" if self.cleaned else
                                     "UNCONFIRMED_PROCESS_EXIT_RELEASES_RETAINED_HANDLES"),
                "evidence": self.evidence.finish(), "evidence_bytes": self.evidence.bytes_written}

    def terminate_cleanup_process(self, process, ordinal):
        """One owned cleanup attempt; a code-5 race needs immediate signal proof.

        This proves only current process state, never termination causation.
        Outer-job termination and every other error remain strict failures.
        """
        sup = self.owner
        if (not self.cleanup_started or (process, "process") not in sup.owned
                or type(ordinal) is not int or not 1 <= ordinal <= 3):
            raise ValueError("Cleanup requires exact retained created process")
        self.cleanup_operation = "TERMINATE_PROCESS"
        if sup.api.TerminateProcess(process, 91):
            return
        code = sup.api.last_error()  # Capture before ANY further API call.
        if type(code) is int and code == 5:
            self.cleanup_operation = "POST_TERMINATE_WAIT"
            state = sup.api.WaitForSingleObject(process, 0)
            label = ("SIGNALED" if state == WAIT_OBJECT_0 else
                     "TIMEOUT" if state == WAIT_TIMEOUT else
                     "FAILED" if state == 0xFFFFFFFF else "UNEXPECTED")
            self.cleanup_termination_rechecks.append(
                {"process_ordinal": ordinal, "error_code": 5, "wait_state": label})
            if state == WAIT_OBJECT_0:
                return
        self.cleanup_operation = "TERMINATE_PROCESS"
        raise OSError(code, "ExactCleanupTermination")

    def cleanup_steps(self):
        if self.cleanup_started:
            return
        self.cleanup_started = True
        self.stage = "CLEANUP"
        sup = self.owner
        failed = bool(sup.cleanup_errors)
        # Keep the outer job handle for accounting. Last-close dispatch alone
        # cannot prove target death after the observer has been lost.
        if self.outer is not None and (self.outer, "job") in sup.owned:
            try:
                self.cleanup_operation = "TERMINATE_OUTER"
                sup.terminate_outer(self.outer)
            except (OSError, ValueError) as error:
                self.note_failure(error)
                failed = True
        ordinal = 0
        for process, kind in sup.owned[:]:
            if kind == "process":
                ordinal += 1
                try:
                    self.cleanup_operation = "PRE_TERMINATE_WAIT"
                    state = sup.api.WaitForSingleObject(process, 0)
                    if state == WAIT_TIMEOUT:
                        self.terminate_cleanup_process(process, ordinal)
                    elif state != WAIT_OBJECT_0:
                        self.note_failure(ValueError("Ambiguous cleanup wait"))
                        failed = True
                except (OSError, ValueError) as error:
                    self.note_failure(error)
                    failed = True
        for _ in range(51):
            try:
                self.cleanup_operation = "WAIT_ALL"
                signaled = all(sup.api.WaitForSingleObject(process, 0) == WAIT_OBJECT_0
                               for process, kind in sup.owned if kind == "process")
                if signaled:
                    # Accounting may retain terminated members until process
                    # references close. Preserve job + artifact handles while
                    # releasing only confirmed-dead process/thread references.
                    for handle, kind in sup.owned[:]:
                        if kind in ("process", "thread"):
                            self.cleanup_operation = "CLOSE_DEAD"
                            sup.release(handle)
                    self.cleanup_operation = "QUERY_EMPTY"
                    empty = all(sup.active_processes(job) == 0
                                for job, kind in sup.owned if kind == "job")
                    if empty and not failed:
                        self.record("owned_jobs_empty")
                        # Stop on closure failure before touching remaining pins.
                        for handle, _ in sorted(sup.owned[:], key=lambda entry: entry[1] == "artifact"):
                            self.cleanup_operation = "CLOSE_REMAINDER"
                            sup.release(handle)
                        self.cleaned = not sup.owned and not sup.cleanup_errors
                        break
            except (OSError, ValueError) as error:
                self.note_failure(error)
                failed = True
            if failed or self.now() >= self.deadline + 5 * SECOND:
                break
            yield 100_000_000
        if failed:
            self.protocol_valid = False

    def run(self, pause):
        if type(pause) is not FunctionType:
            raise TypeError("Exact supervisor pause hook required")
        if self.used:
            raise ValueError("One-shot prepared qualification cannot restart")
        steps = self.steps()
        try:
            while True:
                try:
                    delay = next(steps)
                except StopIteration as result:
                    return result.value
                pause(delay)
        except BaseException as error:  # noqa: BLE001 - exact owner survives even interruption
            self.note_failure(error)
            steps.close()  # No yielding finally or destructor-dependent cleanup.
            self.abort_owned_once()
            return self.result()

    def abort_owned_once(self):
        """One non-yielding emergency attempt; never extends the 30+5s window.

        A previous cleanup attempt is never retried or waived. If a zero-time
        check cannot prove empty jobs, keep jobs/pins until explicit process
        exit, which is an unconfirmed loss of evidence, not a cleanup receipt.
        """
        self.outcome, self.protocol_valid = "UNKNOWN", False
        if self.abort_started:
            return
        self.abort_started = True
        if self.owner is None:
            self.cleaned = True
        elif not self.cleanup_started:
            cleanup = self.cleanup_steps()
            try:
                next(cleanup, None)
            except BaseException as error:  # noqa: BLE001 - preserve ownership, no second attempt
                self.note_failure(error)
                self.cleaned = False
            finally:
                cleanup.close()


def run_serial_prepared(cases, pause):
    """Bounded selected batch; never admit another case after unresolved cleanup."""
    if (type(cases) is not tuple or not 1 <= len(cases) <= 10
            or any(type(case) is not PreparedQualification or case.used for case in cases)
            or len({case.config["case"] for case in cases}) != len(cases)
            or type(pause) is not FunctionType):
        raise ValueError("At most ten distinct fresh prepared cases required")
    results = []
    for case in cases:
        result = case.run(pause)
        results.append(result)
        if result["cleanup_responsibility_retained"]:
            break
    return tuple(results)


class StubQualification:
    """Legacy synchronous regression fixture, solely injected process tables.

    The controller/observer state machines prepare a future process split, but
    this scheduler is an in-process STUB. Native bootstrap, artifact locking and
    independent OS scheduling remain unreleased and unqualified.
    """

    def __init__(self, grant, approved, config, inventory, api_factory, clock, advance, persist,
                 physical=None):
        self.digest = stub_admission(grant, approved, config, inventory)
        if any(type(hook) is not FunctionType for hook in (api_factory, clock, advance, persist)):
            raise TypeError("Exact trusted stub hooks required")
        self.config = dict(config)
        self.grant, self.approved, self.inventory = dict(grant), dict(approved), inventory
        self.physical = physical
        self.artifacts = None
        self.factory, self.clock, self.advance, self.persist = api_factory, clock, advance, persist
        self.generation = config["generation"]
        self.evidence = BoundedEvidence()
        self.supervisor = self.controller_owner = self.observer_owner = None
        self.controller = self.observer = None
        self.used = False
        self.last_tick = -1

    def now(self):
        tick = self.clock()
        if type(tick) is not int or not self.last_tick <= tick < 2**63:
            raise ValueError("Trusted monotonic clock failure")
        self.last_tick = tick
        return tick

    def record(self, role, event, outcome="STUB"):
        self.evidence.record(role, event, self.generation, self.now(), outcome)

    def channel(self, owner, handle):
        return FixedChannel(owner, handle, self.generation, self.digest)

    def run(self):
        if self.used:
            raise ValueError("One-shot qualification cannot restart")
        self.used = True
        outcome, canary_live, cleanup = "UNKNOWN", False, False
        try:
            self.setup()
            outcome, canary_live = self.observe()
        except (OSError, ValueError, PermissionError):
            self.evidence.record("supervisor", "case_error", self.generation,
                                 max(self.last_tick, 0), "UNKNOWN")
        finally:
            # This models each owned role's shutdown, not cross-process closing.
            # Native cleanup instead terminates exact retained created roles.
            clean = []
            for owner in (self.controller_owner, self.observer_owner, self.supervisor):
                if owner is not None:
                    clean.append(owner.cleanup())
            cleanup = bool(clean) and all(clean)
        if not cleanup:
            outcome = "UNKNOWN"
        return {"status": "STUB_ONLY", "case": self.config["case"], "outcome": outcome,
                "canary_live_before_cleanup": canary_live, "owned_stub_cleanup": cleanup,
                "restart_safety": "UNQUALIFIED",
                "launch_pins": "HELD_STUB_OBJECTS" if self.artifacts is not None else "SYNTHETIC_ALIASES",
                "same_instance_inhibited": self.controller is not None and self.controller.inhibited,
                "evidence": self.evidence.finish(),
                "evidence_bytes": self.evidence.bytes_written}

    def setup(self):
        c = self.config
        self.started = self.now()  # Independent supervisor deadline BEFORE any role launch.
        self.deadline = self.started + 30 * SECOND
        self.supervisor = sup = RoleHandles(self.factory("supervisor", None))
        if self.physical is not None:
            if type(self.physical) is not dict or set(self.physical) != {"source_root", "sources"}:
                raise ValueError("Malformed physical pin request")
            self.artifacts = pin_physical_launch(
                sup, self.grant, self.approved, c, self.inventory,
                self.physical["source_root"], self.physical["sources"])
        in_job = sup.membership(sup.api.GetCurrentProcess(), None)
        mode = supervisor_job_mode(c)
        if in_job != (mode == "REQUIRE_INHERITED_NESTED"):
            raise ValueError("Pre-existing supervisor job is not qualified; no breakaway")
        if mode == "REQUIRE_INHERITED_NESTED":
            sup.immediate_job_information(9)
            sup.immediate_job_information(4)
        outer = sup.job_limit(3, 640, 2000)
        observer_job = sup.job_limit(1, 128, 2500)  # 25% of outer 20% = 5% system.
        canary_job = sup.job_limit(1, 128, 500)
        query_read, query_write = sup.pipe()
        ack_read, ack_write = sup.pipe()
        report_read, report_write = sup.pipe()
        self.observer_process, observer_thread, inherited_observer = sup.launch(
            "observer", c["application"], c["cwd"], c["source"], (outer, observer_job),
            ((query_read, 0), (ack_write, 0), (report_write, 0)))
        self.canary, canary_thread, _ = sup.launch(
            "canary", c["application"], c["cwd"], c["source"], (canary_job,))
        self.canary_identity = sup._identity(self.canary, self.generation, self.digest)
        self.controller_process, controller_thread, inherited_controller = sup.launch(
            "controller", c["application"], c["cwd"], c["source"], (outer,),
            ((self.observer_process, 0x40), (query_write, 0), (ack_read, 0)))
        self.observer_owner = obs = RoleHandles(self.factory("observer", self.observer_process))
        self.controller_owner = ctrl = RoleHandles(self.factory("controller", self.controller_process))
        for handle in inherited_observer:
            obs.own(handle, "inherited")
        for handle in inherited_controller:
            ctrl.own(handle, "inherited")
        self.observer = QualificationObserver(
            obs, self.channel(obs, inherited_observer[0]), self.channel(obs, inherited_observer[1]),
            self.channel(obs, inherited_observer[2]), c["application"], self.generation, self.digest)
        self.controller = QualificationController(
            ctrl, inherited_controller[0], self.channel(ctrl, inherited_controller[1]),
            self.channel(ctrl, inherited_controller[2]), c["application"], c["cwd"], c["source"],
            self.generation, self.digest)
        self.reports = self.channel(sup, report_read)
        # Originals are not needed by supervisor. Keep only the report reader.
        for handle in (query_read, query_write, ack_read, ack_write, report_write):
            sup.release(handle)
        for thread in (observer_thread, canary_thread, controller_thread):
            sup.resume(thread)
        self.record("supervisor", "roles_started")
        if self.now() >= self.deadline:
            raise ValueError("Role setup exceeded independent deadline")
        self.controller.prepare(self.now(), self.persist)
        if c["case"] == "suspended_stop":
            self.controller.stop(self.persist)
            raise ValueError("Selected stop before resume")

    def observe(self):
        case, sup = self.config["case"], self.supervisor
        live_tick = intervention = None
        expected = None
        controller_active = observer_active = True
        durable = True
        for _ in range(351):  # 100 ms stub schedule, 30 s deadline plus 5 s cleanup window.
            now = self.now()
            if now > self.deadline + 5 * SECOND:
                break
            if observer_active:
                self.observer.step(now)
            if controller_active:
                self.controller.step(now)
            frame = self.reports.receive(now)
            if frame is not None:
                kind, tick, handle, pid, creation = frame
                identity = (handle, pid, creation)
                if kind == 3 and live_tick is None and self.controller.resumed_at is not None:
                    if tick < self.controller.resumed_at or tick >= self.deadline:
                        raise ValueError("Invalid live timing")
                    live_tick, expected = tick, identity
                    self.record("observer", "live_after_resume")
                elif (kind == 4 and expected == identity and live_tick is not None
                      and intervention is not None
                      and live_tick < intervention <= tick <= intervention + 4 * SECOND
                      and tick < self.controller.resumed_at + 60 * SECOND):
                    canary_live = sup.state(self.canary, self.canary_identity) == "LIVE"
                    self.record("observer", "early_primary_exit")
                    if not canary_live or not durable:
                        return "UNKNOWN", canary_live
                    return "STUB_EARLY_PRIMARY_EXIT", True
                else:
                    raise ValueError("Unbound or premature observer result")
            if live_tick is not None and intervention is None:
                if case == "no_stop_control" and now >= live_tick + 5 * SECOND:
                    target_live = self.observer.owner.state(
                        self.observer.handle, self.observer.identity) == "LIVE"
                    canary_live = sup.state(self.canary, self.canary_identity) == "LIVE"
                    return ("STUB_MATCHED_LIVE_CONTROL" if target_live and canary_live else "UNKNOWN",
                            canary_live)
                if case != "no_stop_control" and now >= live_tick + SECOND:
                    if case == "controller_deadline":
                        controller_active = False
                    elif case == "controller_crash":
                        sup.terminate(self.controller_process)
                        self.retire_controller()
                        controller_active, intervention = False, now
                    elif case == "supervisor_loss":
                        # Stub supervisor-table loss closes its sole outer-job
                        # handles; judge and canary can die too. No surviving
                        # independent judge means UNKNOWN, never a stop receipt.
                        for handle, kind in sup.owned[:]:
                            if kind == "job":
                                sup.release(handle)
                        self.retire_controller()
                        if sup.api.WaitForSingleObject(self.observer_process, 0) == WAIT_OBJECT_0:
                            self.observer_owner.owned.clear()
                        self.record("supervisor", "supervisor_lost", "UNKNOWN")
                        return "UNKNOWN", False
                    elif case == "observer_loss":
                        sup.terminate(self.observer_process)
                        if sup.api.WaitForSingleObject(self.observer_process, 0) == WAIT_OBJECT_0:
                            self.observer_owner.owned.clear()
                        self.record("supervisor", "missing_judge", "UNKNOWN")
                        return "UNKNOWN", sup.state(self.canary, self.canary_identity) == "LIVE"
                    else:
                        durable = self.controller.stop(self.persist)
                        intervention = now
                        if case == "same_instance_restart_refused":
                            try:
                                self.controller.prepare(now, self.persist)
                            except ValueError:
                                self.record("controller", "restart_refused", "REFUSED")
                            else:
                                raise ValueError("Restart bypass")
            if now >= self.deadline and intervention is None:
                sup.terminate(self.controller_process)
                self.retire_controller()
                if now != self.deadline:
                    return "UNKNOWN", False
                controller_active, intervention = False, now
                self.record("supervisor", "deadline_intervention")
            if intervention is not None and now > intervention + 4 * SECOND:
                break
            self.advance(100_000_000)
        return "UNKNOWN", sup.state(self.canary, self.canary_identity) == "LIVE"

    def retire_controller(self):
        # A dispatch alone is insufficient. Only confirmed death of this exact
        # created role permits forgetting its no-longer-existing local table.
        if self.supervisor.api.WaitForSingleObject(self.controller_process, 0) == WAIT_OBJECT_0:
            self.controller_owner.owned.clear()
