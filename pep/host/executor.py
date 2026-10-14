# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Run a registry tool outside the gate process.

The gate decides. A worker process does the call. A nursery is forked
before the gate has loaded the policy, opened the decision log, or minted
a grant. Each session gets its own worker from that nursery, so one
session cannot stall or kill the executor the others use. The nursery
keeps at most one live worker per connection, capped by the host's
connection limit.

The worker drops every inherited descriptor except its socket, clears
its environment, and caps core dumps, file size, and new processes.
It then applies a landlock ruleset that denies filesystem access. A
seccomp allow list permits the x86_64 calls the worker needs to read,
write, and return. The architecture is checked first: anything that is
not native x86_64 is killed, which stops a 32-bit ``int 0x80`` entry.
An x32-style number (bit 0x40000000) is rejected. ``memfd_create``,
``io_uring``, ``clone3``, ``bpf``, ``userfaultfd``, ``perf_event_open``,
``open_by_handle_at``, ``keyctl``, ``ptrace``, and ``sendto`` are not
on the list. The agent does not choose the function.
The gate sends a tool name and the argument snapshot, and a call that
exceeds its timeout is denied.

Linux x86_64 only. If the sandbox cannot be installed, the gate does
not run the tool.
"""

from __future__ import annotations

import array
import ctypes
import json
import os
import resource
import signal
import socket
import threading
import time
from collections.abc import Mapping
from typing import Any

# x86_64 numbers the worker actually uses after the filter is installed.
# read and write carry the gate protocol. The rest is the memory, signal,
# clock, and exit set CPython needs for one call. Nothing else is allowed.
# sendto (44), sendmsg (46), sendmmsg (307), io_uring_setup (425),
# io_uring_enter (426), and io_uring_register (427) are omitted on purpose.
_X86_64_ALLOWED = (
    0,  # read
    1,  # write
    3,  # close
    9,  # mmap
    10,  # mprotect
    11,  # munmap
    12,  # brk
    13,  # rt_sigaction
    14,  # rt_sigprocmask
    15,  # rt_sigreturn
    25,  # mremap
    28,  # madvise
    39,  # getpid
    60,  # exit
    96,  # gettimeofday
    131,  # sigaltstack
    186,  # gettid
    202,  # futex
    218,  # set_tid_address
    219,  # restart_syscall
    228,  # clock_gettime
    230,  # clock_nanosleep
    231,  # exit_group
    273,  # set_robust_list
    318,  # getrandom
    334,  # rseq
)

# AUDIT_ARCH_X86_64. AArch64 is 0xC00000B7; this process has no AArch64
# numbers, so that architecture is killed with every other one.
_AUDIT_ARCH_X86_64 = 0xC000003E
_X32_SYSCALL_BIT = 0x40000000

_MAX_FRAME = 16 * 1024 * 1024
_HANDSHAKE_SECONDS = 5.0
DEFAULT_CALL_TIMEOUT_SECONDS = 5.0

_PR_SET_PDEATHSIG = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_LANDLOCK_CREATE = 444
_LANDLOCK_RESTRICT = 446
_EPERM = 1
_BPF_LD_ABS_W = 0x20
_BPF_JMP_JEQ = 0x15
_BPF_JMP_JSET = 0x45
_BPF_RET = 0x06


class ToolExecutionError(RuntimeError):
    """The executor did not return a tool result. The gate must deny."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class UnencodableResult:
    """A tool result the executor could not encode. The gate already treats that as not JSON."""


class ExecutorStartError(RuntimeError):
    """The sandbox process did not become ready. The gate turns this into ``HostError``."""


class ExecutorNursery:
    """Workers forked from a process that has not seen the policy, the log, or a grant.

    One worker is handed to one session. A session that has finished, or whose
    call timed out, does not keep that worker. The number of live workers
    never exceeds ``max_workers``.
    """

    def __init__(
        self,
        pid: int,
        conn: socket.socket,
        *,
        call_timeout: float,
        max_workers: int,
    ) -> None:
        self._pid = pid
        self._conn = conn
        self._call_timeout = call_timeout
        self._max_workers = max_workers
        self._lock = threading.Lock()
        self._spawn_lock = threading.Lock()
        self._workers: dict[int, _Worker] = {}
        self._spare: _Worker | None = None
        self._closed = False
        self._aborting = False

    @classmethod
    def start(
        cls,
        registry: Mapping[str, Any],
        *,
        call_timeout: float = DEFAULT_CALL_TIMEOUT_SECONDS,
        max_workers: int = 8,
    ) -> ExecutorNursery:
        if call_timeout <= 0 or max_workers < 1:
            raise ExecutorStartError("tool executor limits must be positive")
        if not hasattr(os, "fork"):
            raise ExecutorStartError("tool executor requires fork")
        if os.uname().machine != "x86_64":
            raise ExecutorStartError("tool executor sandbox supports x86_64 only")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                _set_die_with_parent()
                _zygote_main(child, dict(registry))
            finally:
                os._exit(0)
        child.close()
        parent.settimeout(_HANDSHAKE_SECONDS)
        try:
            ready = _read_frame(parent)
        except (OSError, ValueError, ToolExecutionError) as exc:
            parent.close()
            _kill_and_reap(pid)
            raise ExecutorStartError("tool executor did not start") from exc
        parent.settimeout(None)
        if not isinstance(ready, dict) or ready.get("status") != "ready":
            parent.close()
            _kill_and_reap(pid)
            raise ExecutorStartError("tool executor did not start")
        nursery = cls(pid, parent, call_timeout=call_timeout, max_workers=max_workers)
        try:
            nursery._spare = nursery._spawn_worker()
        except ExecutorStartError:
            nursery.close()
            raise
        return nursery

    def call(self, session_id: int, tool_name: str, args: Mapping[str, Any]) -> Any:
        """Run one registry function for this session. Raises ``ToolExecutionError`` on failure."""
        worker = self._worker_for(session_id)
        try:
            return worker.call(tool_name, args)
        except ToolExecutionError:
            if worker.closed:
                self._discard(session_id, worker)
            raise

    def abort_calls(self) -> None:
        """Stop every worker and refuse new calls, so in-flight calls return now.

        Used on shutdown before the decision log drains. After this no call
        gets a worker: one that had not reached its worker yet is refused, and
        the spare is closed, so no tool call can start and outlast the drain.
        """
        with self._lock:
            self._aborting = True
            workers = list(self._workers.values())
            self._workers.clear()
            spare = self._spare
            self._spare = None
        for worker in workers:
            worker.close()
        if spare is not None:
            spare.close()

    def release(self, session_id: int) -> None:
        """Stop the worker that belonged to a session that has gone away."""
        with self._lock:
            worker = self._workers.pop(session_id, None)
        if worker is not None:
            worker.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            workers = list(self._workers.values())
            spare = self._spare
            self._workers.clear()
            self._spare = None
        for worker in workers:
            worker.close()
        if spare is not None:
            spare.close()
        try:
            self._conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._conn.close()
        except OSError:
            pass
        _kill_and_reap(self._pid)

    def _worker_for(self, session_id: int) -> _Worker:
        with self._lock:
            if self._closed or self._aborting:
                raise ToolExecutionError("error")
            current = self._workers.get(session_id)
            if current is not None and not current.closed:
                return current
            if current is not None:
                current.close()
                self._workers.pop(session_id, None)
            if self._spare is not None and not self._spare.closed:
                worker = self._spare
                self._spare = None
                self._workers[session_id] = worker
                return worker
            if len(self._workers) >= self._max_workers:
                raise ToolExecutionError("limit")
            try:
                worker = self._spawn_worker()
            except ExecutorStartError as exc:
                raise ToolExecutionError("error") from exc
            self._workers[session_id] = worker
            return worker

    def _discard(self, session_id: int, worker: _Worker) -> None:
        with self._lock:
            if self._workers.get(session_id) is worker:
                self._workers.pop(session_id, None)

    def _spawn_worker(self) -> _Worker:
        with self._spawn_lock:
            if self._closed:
                raise ExecutorStartError("tool executor did not start")
            self._conn.settimeout(_HANDSHAKE_SECONDS)
            try:
                _write_frame(self._conn, {"op": "spawn"})
                pid, fd = _recv_fd(self._conn)
            except (OSError, ValueError, ToolExecutionError) as exc:
                raise ExecutorStartError("tool executor did not start") from exc
            finally:
                self._conn.settimeout(None)
        worker_sock = socket.socket(fileno=fd)
        worker_sock.settimeout(_HANDSHAKE_SECONDS)
        try:
            ready = _read_frame(worker_sock)
        except (OSError, ValueError, ToolExecutionError) as exc:
            worker_sock.close()
            _kill(pid)
            raise ExecutorStartError("tool executor did not start") from exc
        worker_sock.settimeout(None)
        if not isinstance(ready, dict) or ready.get("status") != "ready":
            detail = ""
            if isinstance(ready, dict) and isinstance(ready.get("error"), str):
                detail = ready["error"]
            worker_sock.close()
            _kill(pid)
            raise ExecutorStartError(detail or "tool executor did not start")
        return _Worker(pid, worker_sock, self._call_timeout)


class _Worker:
    """One sandboxed process and the socket the gate uses to talk to it."""

    def __init__(self, pid: int, conn: socket.socket, call_timeout: float) -> None:
        self._pid = pid
        self._conn = conn
        self._timeout = call_timeout
        self._lock = threading.Lock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def call(self, tool_name: str, args: Mapping[str, Any]) -> Any:
        with self._lock:
            if self._closed:
                raise ToolExecutionError("error")
            # One deadline for the whole call, not a fresh window per recv:
            # a worker that drips bytes is cut off at call_timeout.
            deadline = time.monotonic() + self._timeout
            self._conn.settimeout(self._timeout)
            try:
                _write_frame(self._conn, {"tool_name": tool_name, "args": dict(args)})
                reply = _read_frame(self._conn, deadline=deadline)
            except TimeoutError as exc:
                self.close()
                raise ToolExecutionError("timeout") from exc
            except (OSError, ValueError, ToolExecutionError) as exc:
                self.close()
                raise ToolExecutionError("error") from exc
        if not isinstance(reply, dict):
            self.close()
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
        _kill(self._pid)


def _kill(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _kill_and_reap(pid: int) -> None:
    _kill(pid)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        return
    except OSError:
        return


def _set_die_with_parent() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(1)
    if os.getppid() == 1:
        os._exit(1)


def _reap_children(_signum: int, _frame: object) -> None:
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            return
        if pid == 0:
            return


def _zygote_main(conn: socket.socket, registry: dict[str, Any]) -> None:
    try:
        os.environ.clear()
        signal.signal(signal.SIGCHLD, _reap_children)
        _drop_inherited_fds(conn.fileno())
        _write_frame(conn, {"status": "ready"})
        while True:
            message = _read_frame(conn)
            if message is None:
                return
            if not isinstance(message, dict) or message.get("op") != "spawn":
                continue
            _spawn_from_zygote(conn, registry)
    except Exception:
        return


def _spawn_from_zygote(gate: socket.socket, registry: dict[str, Any]) -> None:
    gate_end, worker_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            gate.close()
            gate_end.close()
            _set_die_with_parent()
            _executor_main(worker_end, registry)
        finally:
            os._exit(0)
    worker_end.close()
    try:
        _send_fd(gate, gate_end.fileno(), pid)
    finally:
        gate_end.close()


def _executor_main(conn: socket.socket, registry: dict[str, Any]) -> None:
    fd = conn.fileno()
    problem: str | None = None
    try:
        os.environ.clear()
        _drop_inherited_fds(fd)
        _tighten_rlimits()
        problem = _sandbox()
    except Exception:
        problem = "worker limits were refused"
    try:
        if problem is not None:
            _write_fd(fd, {"status": "failed", "error": problem})
            return
        _write_fd(fd, {"status": "ready"})
        while True:
            message = _read_fd(fd)
            if message is None:
                return
            _write_fd(fd, _run_tool(registry, message))
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


def _tighten_rlimits() -> None:
    """Cap the worker. Failures abort startup; the gate does not run the tool."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    cap = 64
    if hard == resource.RLIM_INFINITY or hard > cap:
        hard = cap
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(cap, hard), hard))


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

    filters = _allow_filter(SockFilter)
    table = (SockFilter * len(filters))(*filters)
    program = SockFprog(len(filters), table)
    ctypes.set_errno(0)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        return "seccomp filter was refused"
    return None


def _allow_filter(sock_filter: type) -> list[Any]:
    """Allow ``_X86_64_ALLOWED`` on native x86_64. Kill every other architecture.

    The architecture word is the first check, so an ``int 0x80`` entry
    (AUDIT_ARCH_I386), including i386 ``kill`` and ``ptrace``, is killed
    before the syscall number is considered. A number with the x32 bit
    set is rejected even when the low bits would match an allowed call.
    Anything else returns EPERM. ``clone3`` is not allowed; EPERM or
    ENOSYS from the kernel are both a denial.
    """
    allowed = _X86_64_ALLOWED
    count = len(allowed)
    filters = [
        sock_filter(_BPF_LD_ABS_W, 0, 0, 4),
        sock_filter(_BPF_JMP_JEQ, 1, 0, _AUDIT_ARCH_X86_64),
        sock_filter(_BPF_RET, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        sock_filter(_BPF_LD_ABS_W, 0, 0, 0),
        sock_filter(_BPF_JMP_JSET, count, 0, _X32_SYSCALL_BIT),
    ]
    for index, number in enumerate(allowed):
        filters.append(sock_filter(_BPF_JMP_JEQ, count - index, 0, number))
    filters.append(sock_filter(_BPF_RET, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))
    filters.append(sock_filter(_BPF_RET, 0, 0, _SECCOMP_RET_ALLOW))
    return filters


def _send_fd(sock: socket.socket, fd: int, pid: int) -> None:
    payload = pid.to_bytes(4, "big", signed=False)
    anc = array.array("i", [fd]).tobytes()
    sock.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, anc)])


def _recv_fd(sock: socket.socket) -> tuple[int, int]:
    data = bytearray()
    received: int | None = None
    while len(data) < 4:
        chunk, ancdata, _flags, _addr = sock.recvmsg(4 - len(data), socket.CMSG_SPACE(4))
        if not chunk and not ancdata:
            raise ToolExecutionError("error")
        data.extend(chunk)
        if received is None:
            for level, typ, payload in ancdata:
                if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                    fds = array.array("i")
                    size = fds.itemsize
                    fds.frombytes(payload[: len(payload) - (len(payload) % size)])
                    if len(fds):
                        received = int(fds[0])
                        break
    if received is None:
        raise ToolExecutionError("error")
    return int.from_bytes(data, "big"), received


def _write_frame(conn: socket.socket, payload: Mapping[str, Any]) -> None:
    conn.sendall(_encode_frame(payload))


def _write_fd(fd: int, payload: Mapping[str, Any]) -> None:
    view = memoryview(_encode_frame(payload))
    while view:
        try:
            wrote = os.write(fd, view)
        except InterruptedError:
            continue
        if wrote <= 0:
            raise ToolExecutionError("error")
        view = view[wrote:]


def _encode_frame(payload: Mapping[str, Any]) -> bytes:
    body = json.dumps(dict(payload), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(body) > _MAX_FRAME:
        raise ToolExecutionError("error")
    return len(body).to_bytes(4, "big") + body


def _read_frame(conn: socket.socket, *, deadline: float | None = None) -> dict[str, Any] | None:
    header = _read_exact(conn, 4, deadline=deadline)
    if header is None:
        return None
    size = _frame_size(header)
    body = _read_exact(conn, size, deadline=deadline)
    if body is None:
        raise ToolExecutionError("error")
    return _decode_body(body)


def _read_fd(fd: int) -> dict[str, Any] | None:
    header = _read_exact_fd(fd, 4)
    if header is None:
        return None
    size = _frame_size(header)
    body = _read_exact_fd(fd, size)
    if body is None:
        raise ToolExecutionError("error")
    return _decode_body(body)


def _frame_size(header: bytes) -> int:
    size = int.from_bytes(header, "big")
    if size < 1 or size > _MAX_FRAME:
        raise ToolExecutionError("error")
    return size


def _decode_body(body: bytes) -> dict[str, Any]:
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ToolExecutionError("error")
    return parsed


def _read_exact(conn: socket.socket, size: int, *, deadline: float | None = None) -> bytes | None:
    """Read ``size`` bytes. With ``deadline`` (monotonic), the whole read is bounded by it."""
    chunks = bytearray()
    while len(chunks) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("tool call deadline passed")
            conn.settimeout(remaining)
        try:
            block = conn.recv(size - len(chunks))
        except TimeoutError:
            raise
        except InterruptedError:
            continue
        if not block:
            if not chunks:
                return None
            raise ToolExecutionError("error")
        chunks.extend(block)
    return bytes(chunks)


def _read_exact_fd(fd: int, size: int) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < size:
        try:
            block = os.read(fd, size - len(chunks))
        except InterruptedError:
            continue
        if not block:
            if not chunks:
                return None
            raise ToolExecutionError("error")
        chunks.extend(block)
    return bytes(chunks)
