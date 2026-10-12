# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Run a registry tool outside the gate process.

The gate decides. This process does the call. It is forked before the
gate has loaded the policy, opened the decision log, or minted a grant,
then it drops every inherited descriptor except its socket and applies
a landlock ruleset that denies filesystem access. A small seccomp filter
rejects connecting a socket, changing a file mode or owner, signalling
another process, and reading or writing another process. The agent does
not choose the function. The
gate sends a tool name and the argument snapshot.

Linux x86_64 only. If the sandbox cannot be installed, the gate does
not run the tool.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import threading
from collections.abc import Mapping
from typing import Any

# x86_64 syscall numbers. glibc reaches chmod through fchmodat.
_BLOCKED_SYSCALLS = (
    42,  # connect
    62,  # kill
    90,  # chmod
    91,  # fchmod
    92,  # chown
    93,  # fchown
    94,  # lchown
    101,  # ptrace
    129,  # rt_sigqueueinfo
    200,  # tkill
    234,  # tgkill
    260,  # fchownat
    268,  # fchmodat
    310,  # process_vm_readv
    311,  # process_vm_writev
    424,  # pidfd_send_signal
    452,  # fchmodat2
)

_MAX_FRAME = 16 * 1024 * 1024
_HANDSHAKE_SECONDS = 5.0

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_LANDLOCK_CREATE = 444
_LANDLOCK_RESTRICT = 446
_EACCES = 13


class ToolExecutionError(RuntimeError):
    """The executor did not return a tool result. The gate must deny."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class UnencodableResult:
    """A tool result the executor could not encode. The gate already treats that as not JSON."""


class ToolExecutor:
    """One sandbox process for every tool call this gate makes."""

    def __init__(self, pid: int, conn: socket.socket) -> None:
        self._pid = pid
        self._conn = conn
        self._lock = threading.Lock()
        self._closed = False

    @classmethod
    def start(cls, registry: Mapping[str, Any]) -> ToolExecutor:
        if not hasattr(os, "fork"):
            raise ExecutorStartError("tool executor requires fork")
        if os.uname().machine != "x86_64":
            raise ExecutorStartError("tool executor sandbox supports x86_64 only")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                _executor_main(child, dict(registry))
            finally:
                os._exit(0)
        child.close()
        parent.settimeout(_HANDSHAKE_SECONDS)
        try:
            ready = _read_frame(parent)
        except (OSError, ValueError, ToolExecutionError) as exc:
            parent.close()
            _reap(pid)
            raise ExecutorStartError("tool executor did not start") from exc
        parent.settimeout(None)
        if not isinstance(ready, dict) or ready.get("status") != "ready":
            detail = ""
            if isinstance(ready, dict) and isinstance(ready.get("error"), str):
                detail = ready["error"]
            parent.close()
            _reap(pid)
            raise ExecutorStartError(detail or "tool executor did not start")
        return cls(pid, parent)

    def call(self, tool_name: str, args: Mapping[str, Any]) -> Any:
        """Run one registry function. Raises ``ToolExecutionError`` on any failure."""
        with self._lock:
            if self._closed:
                raise ToolExecutionError("error")
            try:
                _write_frame(self._conn, {"tool_name": tool_name, "args": dict(args)})
                reply = _read_frame(self._conn)
            except (OSError, ValueError, ToolExecutionError) as exc:
                self._closed = True
                raise ToolExecutionError("error") from exc
        if not isinstance(reply, dict):
            raise ToolExecutionError("error")
        status = reply.get("status")
        if status == "ok":
            return reply.get("result")
        if status == "unencodable":
            return UnencodableResult()
        if status == "permission":
            raise ToolExecutionError("permission")
        raise ToolExecutionError("error")

    def close(self) -> None:
        # Do not take the call lock. A tool call may be blocked in a read,
        # and shutdown has to unblock that read.
        self._closed = True
        try:
            self._conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._conn.close()
        except OSError:
            pass
        try:
            os.kill(self._pid, 9)
        except OSError:
            pass
        _reap(self._pid)


class ExecutorStartError(RuntimeError):
    """The sandbox process did not become ready. The gate turns this into ``HostError``."""


def _reap(pid: int) -> None:
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        return
    except OSError:
        return


def _executor_main(conn: socket.socket, registry: dict[str, Any]) -> None:
    try:
        _drop_inherited_fds(conn.fileno())
        problem = _sandbox()
        if problem is not None:
            _write_frame(conn, {"status": "failed", "error": problem})
            return
        _write_frame(conn, {"status": "ready"})
        while True:
            message = _read_frame(conn)
            if message is None:
                return
            _write_frame(conn, _run_tool(registry, message))
    except Exception:
        return


def _run_tool(registry: Mapping[str, Any], message: Mapping[str, Any]) -> dict[str, Any]:
    name = message.get("tool_name")
    args = message.get("args")
    fn = registry.get(name) if isinstance(name, str) else None
    if not callable(fn) or not isinstance(args, dict):
        return {"status": "error"}
    try:
        result = fn(args)
    except OSError as exc:
        if exc.errno in {13, 1}:  # EACCES, EPERM
            return {"status": "permission"}
        return {"status": "error"}
    except Exception:
        return {"status": "error"}
    try:
        encoded = json.dumps(result, ensure_ascii=True)
        parsed = json.loads(encoded)
    except (TypeError, ValueError, RecursionError):
        return {"status": "unencodable"}
    return {"status": "ok", "result": parsed}


def _drop_inherited_fds(keep: int) -> None:
    """Point stdio at ``/dev/null`` and close every other descriptor."""
    devnull = os.open("/dev/null", os.O_RDWR)
    try:
        os.dup2(devnull, 0)
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        open_fds = []
        for name in os.listdir("/proc/self/fd"):
            try:
                open_fds.append(int(name))
            except ValueError:
                continue
        for fd in open_fds:
            if fd in {0, 1, 2, keep, devnull}:
                continue
            try:
                os.close(fd)
            except OSError:
                pass
    finally:
        if devnull > 2:
            os.close(devnull)


def _sandbox() -> str | None:
    """Install landlock and the seccomp filter. Return an error string on failure."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        return "could not set no-new-privileges"
    problem = _landlock(libc, ctypes)
    if problem is not None:
        return problem
    return _seccomp(libc, ctypes)


def _landlock(libc: Any, ctypes: Any) -> str | None:
    class Attr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    ruleset = -1
    for bits in (16, 15, 14, 13):
        attr = Attr((1 << bits) - 1)
        ctypes.set_errno(0)
        ruleset = libc.syscall(_LANDLOCK_CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if ruleset >= 0:
            break
    if ruleset < 0:
        return "landlock ruleset was refused"
    try:
        ctypes.set_errno(0)
        if libc.syscall(_LANDLOCK_RESTRICT, ruleset, 0) != 0:
            return "landlock restrict was refused"
    finally:
        os.close(ruleset)
    return None


def _seccomp(libc: Any, ctypes: Any) -> str | None:
    class SockFilter(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_uint16),
            ("jt", ctypes.c_uint8),
            ("jf", ctypes.c_uint8),
            ("k", ctypes.c_uint32),
        ]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    blocked = _BLOCKED_SYSCALLS
    count = len(blocked)
    filters = [SockFilter(0x20, 0, 0, 0)]
    for index, number in enumerate(blocked):
        filters.append(SockFilter(0x15, count - index, 0, number))
    filters.append(SockFilter(0x06, 0, 0, _SECCOMP_RET_ALLOW))
    filters.append(SockFilter(0x06, 0, 0, _SECCOMP_RET_ERRNO | _EACCES))
    table = (SockFilter * len(filters))(*filters)
    program = SockFprog(len(filters), table)
    ctypes.set_errno(0)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        return "seccomp filter was refused"
    return None


def _write_frame(conn: socket.socket, payload: Mapping[str, Any]) -> None:
    body = json.dumps(dict(payload), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(body) > _MAX_FRAME:
        raise ToolExecutionError("error")
    conn.sendall(len(body).to_bytes(4, "big") + body)


def _read_frame(conn: socket.socket) -> dict[str, Any] | None:
    header = _read_exact(conn, 4)
    if header is None:
        return None
    size = int.from_bytes(header, "big")
    if size < 1 or size > _MAX_FRAME:
        raise ToolExecutionError("error")
    body = _read_exact(conn, size)
    if body is None:
        raise ToolExecutionError("error")
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ToolExecutionError("error")
    return parsed


def _read_exact(conn: socket.socket, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            block = conn.recv(size - len(chunks))
        except TimeoutError:
            raise
        if not block:
            if not chunks:
                return None
            raise ToolExecutionError("error")
        chunks.extend(block)
    return bytes(chunks)
