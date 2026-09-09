"""Source-only Windows x64 ABI and retained-handle adapter, injected stubs ONLY.

The lazy DLL binder is behind unconditional refusal. Mock admission is unchanged.
Callbacks are trusted test code, not a sandbox for arbitrary Python code.
"""

import hashlib
import json
import ntpath
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


def native_backend(*_args, **_kwargs):
    """No flag, environment variable or argument can grant native execution."""
    raise PermissionError("SOURCE_ONLY: native loading and execution are not released")


def _bind_prototypes(library, abi):
    """Set signatures only; tests supply Python functions, never a DLL."""
    for name, (result, args) in abi.signatures.items():
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
        _bind_prototypes(library, self.abi)
        for name in self.abi.signatures:
            setattr(self, name, getattr(library, name))
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
                    "INTENDED", "STUB", "UNKNOWN", "REFUSED")
                or type(generation) is not int or not 1 <= generation < 2**63
                or type(monotonic_ns) is not int or not 0 <= monotonic_ns < 2**63
                or len(self.rows) >= 128):
            raise ValueError("Evidence schema/count limit")
        row = {"role": role, "event": event, "generation": generation,
               "monotonic_ns": monotonic_ns, "outcome": outcome}
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        # Reserve three 4 KiB pipe buffers inside the combined 64 KiB case cap.
        if self.bytes_written + len(encoded) > 65536 - 3 * 4096:
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
                           CpuLimits=CpuLimits, StartupInfo=StartupInfo,
                           StartupInfoEx=StartupInfoEx, ProcessInformation=ProcessInformation,
                           FileInformation=FileInformation,
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
        if type(api) is not StubApi:
            raise TypeError("SOURCE_ONLY: exact injected StubApi required")
        super().__init__(api, lambda *_: None)
        self.owned = []
        self.bound_identities = {}

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

    def cleanup(self):
        for handle, _ in sorted(self.owned[:], key=lambda entry: entry[1] != "job"):
            try:
                self.release(handle)
            except BaseException:  # noqa: BLE001 - attempt every exact close, retain failures
                self.cleanup_errors.append("role_handle")
        return not self.owned and not self.cleanup_errors

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
        return job

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

    def launch(self, role, application, cwd, source, jobs, inheritance=()):
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
                    bootstrap = ",".join(str(handle) for handle in temporary)
                    command = (f'"{application}" -I -S -B "{source}" '
                               f'--mode native-{role} --bootstrap {bootstrap}')
                result = api.CreateProcessW(wide(a, application), wide(a, command), None, None,
                                            int(bool(temporary)), CREATE_FLAGS,
                                            wide(a, f"TEMP={cwd}\0TMP={cwd}\0TMPDIR={cwd}\0"),
                                            wide(a, cwd), a.c.cast(a.c.byref(startup),
                                                                 a.c.POINTER(a.StartupInfo)),
                                            a.c.byref(info))
                self._ok(result, "RoleCreateSuspended")
                process = self.own(info.hProcess, "process")
                thread = self.own(info.hThread, "thread")
                return process, thread, tuple(temporary)
            except BaseException:
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
                        self.cleanup()
                        raise OSError("Temporary inheritance cleanup failed")

    def resume(self, thread):
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
        if type(owner) is not RoleHandles or type(owner.api) is not StubApi:
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
        if self._path(path) in self.handles:
            raise ValueError("Duplicate held artifact path")
        handle = owner.api.CreateFileW(wide(a, path), 0 if directory else 0x80000000,
                                      3 if directory else 1, None, 3, 0x02200000, None)
        owner._ok(handle and handle != 2**64 - 1, "OpenPinnedArtifact")
        owner.own(handle, "artifact")
        info = a.FileInformation()
        owner._ok(owner.api.GetFileInformationByHandle(handle, a.c.byref(info)), "ArtifactIdentity")
        if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
            raise ValueError("Reparse/wrong artifact kind")
        buffer = (a.WORD * 1025)()
        length = owner.api.GetFinalPathNameByHandleW(handle, buffer, 1025, 0)
        if not 0 < length < 1025 or buffer[length] != 0:
            raise ValueError("Unbounded final artifact path")
        final = bytes(buffer)[:length * 2].decode("utf-16-le")
        if final.startswith("\\\\?\\"):
            final = final[4:]
        if self._path(final) != self._path(path):
            raise ValueError("Artifact path substitution")
        self.handles[self._path(path)] = handle
        return handle, info

    def acquire(self, files):
        if self.used or type(files) is not dict or not 1 <= len(files) <= 256:
            raise ValueError("One-shot exact artifact set required")
        bounded_json(files)
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
            for path, expected in files.items():
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
        if (self.sent >= 16 or kind not in (1, 2, 3, 4)
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

    def receive(self, now):
        a, api = self.owner.a, self.owner.api
        available = a.DWORD()
        self.owner._ok(api.PeekNamedPipe(self.handle, None, 0, None,
                                        a.c.byref(available), None), "PeekFrame")
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
        if (kind not in (1, 2, 3, 4) or generation != self.generation or digest != self.digest
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


def stub_admission(grant, approved, config, inventory):
    """Compare with a separately trusted exact approval; NEVER native authority.

    Synthetic application aliases are permitted only here, not artifact locks.
    Recomputed inventory is read-only and reports its explicit native gaps.
    No job/process/pipe function may run until this routine has returned.
    """
    if type(config) is not dict or set(config) != {
            "application", "cwd", "source", "generation", "case"}:
        raise ValueError("Exact fixed probe configuration required")
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
        if value["authority"] != "STUB_ONLY":
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


def pin_physical_launch(owner, grant, approved, config, inventory, source_root, sources):
    """Bind intended launch paths to approved file bytes, then retain file locks.

    Only an injected owner is possible in this revision. No alias fallback:
    application MUST be inventory-root/python.exe and source MUST be the pinned
    probe under source_root. Extra import candidates/system DLLs still require
    an accepted loading baseline; held selected files do not close that gap.
    """
    if type(owner) is not RoleHandles or type(owner.api) is not StubApi:
        raise TypeError("SOURCE_ONLY: exact artifact owner required")
    for value in (config, grant, approved, sources):
        bounded_json(value)
    bounded_json(inventory, 1024 * 1024)
    if (type(grant) is not dict or grant != approved or grant.get("authority") != "STUB_ONLY"
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
    return artifacts


class StubQualification:
    """One connected five-role qualification path, solely injected process tables.

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
        in_job = sup.a.c.c_int32()
        sup._ok(sup.api.IsProcessInJob(sup.api.GetCurrentProcess(), None,
                                       sup.a.c.byref(in_job)), "SupervisorJobCheck")
        if in_job.value:
            raise ValueError("Pre-existing supervisor job is not qualified; no breakaway")
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
                      and intervention is not None and live_tick < intervention <= tick
                      and tick <= intervention + 4 * SECOND
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
