"""Small seccomp user-notification bridge for the sealed-exec boundary.

This module intentionally contains only the Linux primitive and bounded path
inspection.  Policy, cgroup ownership and the enforcement decision remain in
the root supervisor.
"""

from __future__ import annotations

import array
import ctypes
import errno
import os
import socket
from pathlib import Path
from typing import Any

from .execution_policy import inspect_executable, match_identity
from .jsonio import JsonInputError

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows can import the package read-only.
    fcntl = None  # type: ignore[assignment]

LIBC = ctypes.CDLL(None, use_errno=True) if os.name == "posix" else None
SYS_SECCOMP = 317
SYS_PROCESS_VM_READV = 310
SYS_PRCTL = 157
SECCOMP_SET_MODE_FILTER = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER = 8
PR_SET_NO_NEW_PRIVS = 38
AUDIT_ARCH_X86_64 = 0xC000003E
SYS_EXECVE = 59
SYS_EXECVEAT = 322
AT_EMPTY_PATH = 0x1000
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
MAX_PATH_BYTES = 4096

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06
BPF_ALU = 0x04
BPF_OR = 0x40
BPF_X = 0x08
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_USER_NOTIF = 0x7FC00000


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


class SeccompData(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class SeccompNotif(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("pid", ctypes.c_uint32), ("flags", ctypes.c_uint32), ("data", SeccompData)]


class SeccompNotifResp(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("val", ctypes.c_int64), ("error", ctypes.c_int32), ("flags", ctypes.c_uint32)]


def _ioc(direction: int, number: int, size: int) -> int:
    return direction | (size << 16) | (ord("!") << 8) | number


IOC_READ = 2 << 30
IOC_WRITE = 1 << 30
SECCOMP_IOCTL_NOTIF_RECV = _ioc(IOC_READ | IOC_WRITE, 0, ctypes.sizeof(SeccompNotif))
SECCOMP_IOCTL_NOTIF_SEND = _ioc(IOC_READ | IOC_WRITE, 1, ctypes.sizeof(SeccompNotifResp))
SECCOMP_IOCTL_NOTIF_ID_VALID = _ioc(IOC_WRITE, 2, ctypes.sizeof(ctypes.c_uint64))


def _syscall(number: int, *args: Any) -> int:
    if LIBC is None:
        raise OSError(errno.ENOSYS, "Linux syscall bridge is unavailable")
    result = LIBC.syscall(number, *args)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def install_exec_filter() -> int:
    """Install a filter inherited by descendants and return its listener fd."""
    if os.name != "posix":
        raise OSError(errno.ENOSYS, "seccomp is only supported on Linux")
    if _syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(errno.EPERM, "cannot set no-new-privileges")
    instructions = (SockFilter * 8)(
        SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 4),
        # An unexpected architecture fails closed with ENOSYS rather than
        # silently allowing an unmediated exec.
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, AUDIT_ARCH_X86_64),
        SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 2, 0, SYS_EXECVE),
        SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, SYS_EXECVEAT),
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF),
        SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | errno.ENOSYS),
    )
    program = SockFprog(len(instructions), instructions)
    return _syscall(
        SYS_SECCOMP,
        SECCOMP_SET_MODE_FILTER,
        SECCOMP_FILTER_FLAG_NEW_LISTENER,
        ctypes.byref(program),
    )


def send_listener(socket_path: Path, descriptor: int) -> None:
    """Pass the kernel listener to the root supervisor over one run channel."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(8.0)
        connection.connect(str(socket_path))
        payload = array.array("i", [descriptor]).tobytes()
        connection.sendmsg([b"LUMI-EXEC\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, payload)])
        if connection.recv(3) != b"OK\n":
            raise OSError(errno.EPROTO, "execution listener handshake was rejected")


def receive_notification(descriptor: int) -> SeccompNotif:
    if fcntl is None:
        raise OSError(errno.ENOSYS, "seccomp is only supported on Linux")
    value = bytearray(ctypes.sizeof(SeccompNotif))
    fcntl.ioctl(descriptor, SECCOMP_IOCTL_NOTIF_RECV, value, True)
    return SeccompNotif.from_buffer_copy(value)


def notification_id_valid(descriptor: int, notification_id: int) -> bool:
    if fcntl is None:
        raise OSError(errno.ENOSYS, "seccomp is only supported on Linux")
    value = bytearray(ctypes.string_at(ctypes.byref(ctypes.c_uint64(notification_id)), 8))
    try:
        fcntl.ioctl(descriptor, SECCOMP_IOCTL_NOTIF_ID_VALID, value, True)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ESRCH, errno.EINVAL}:
            return False
        raise
    return True


def send_response(descriptor: int, notification_id: int, *, allow: bool) -> None:
    if fcntl is None:
        raise OSError(errno.ENOSYS, "seccomp is only supported on Linux")
    response = SeccompNotifResp(
        notification_id,
        0,
        0 if allow else -errno.EPERM,
        SECCOMP_USER_NOTIF_FLAG_CONTINUE if allow else 0,
    )
    value = bytearray(ctypes.string_at(ctypes.addressof(response), ctypes.sizeof(response)))
    fcntl.ioctl(descriptor, SECCOMP_IOCTL_NOTIF_SEND, value, True)


class _Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def read_process_string(pid: int, address: int) -> str:
    if pid < 1 or address < 1:
        raise JsonInputError("execution notification pointer is invalid")
    buffer = ctypes.create_string_buffer(MAX_PATH_BYTES)
    local = _Iovec(ctypes.cast(buffer, ctypes.c_void_p), MAX_PATH_BYTES)
    remote = _Iovec(ctypes.c_void_p(address), MAX_PATH_BYTES)
    try:
        count = _syscall(
            SYS_PROCESS_VM_READV,
            ctypes.c_int(pid),
            ctypes.byref(local),
            ctypes.c_ulong(1),
            ctypes.byref(remote),
            ctypes.c_ulong(1),
            ctypes.c_ulong(0),
        )
    except OSError as error:
        raise JsonInputError("cannot inspect execution target") from error
    if count < 1:
        raise JsonInputError("execution target path is empty")
    raw = bytes(buffer[:count])
    terminator = raw.find(b"\0")
    if terminator < 0:
        raise JsonInputError("execution target path exceeds bound")
    try:
        return raw[:terminator].decode("utf-8")
    except UnicodeDecodeError as error:
        raise JsonInputError("execution target path is not UTF-8") from error


def target_path(notification: SeccompNotif) -> str:
    if notification.data.nr == SYS_EXECVE:
        return read_process_string(notification.pid, int(notification.data.args[0]))
    if notification.data.nr != SYS_EXECVEAT:
        raise JsonInputError("unsupported execution notification")
    path = read_process_string(notification.pid, int(notification.data.args[1]))
    if not path and int(notification.data.args[4]) & AT_EMPTY_PATH:
        fd = int(ctypes.c_int64(notification.data.args[0]).value)
        if fd < 0:
            raise JsonInputError("execution descriptor is invalid")
        try:
            path = os.readlink(f"/proc/{notification.pid}/fd/{fd}")
        except OSError as error:
            raise JsonInputError("execution descriptor cannot be inspected") from error
    if not path.startswith("/") or Path(os.path.normpath(path)) != Path(path):
        raise JsonInputError("relative execution paths are not supported")
    if path.endswith(" (deleted)") or path.startswith("/memfd:"):
        raise JsonInputError("anonymous or deleted execution targets are not supported")
    return path


def allowed_target(policy: dict[str, Any], notification: SeccompNotif) -> bool:
    try:
        path = target_path(notification)
        identity = inspect_executable(path)
    except (JsonInputError, OSError, ValueError):
        return False
    return match_identity(policy, identity)
