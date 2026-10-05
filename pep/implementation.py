# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Optional host-side helpers for ADR-0004 implementation digests.

The PEP compares opaque ``sha256:`` digests and never resolves anything
itself. These helpers are one way for a host to compute a digest at mint and
again in its observer. ``evaluate`` does not call them, and they are not a
definition of implementation identity.

``open_executable`` (ADR-0005) also runs what it digested: a sealed in-memory
copy of the resolved program, so nothing is resolved by path after the copy.
"""

from __future__ import annotations

import errno
import hashlib
import marshal
import os
import shutil
import stat
import subprocess
import weakref
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# Linux 6.3+ memfd_create flag; Python does not export it. Without it, a kernel
# with vm.memfd_noexec >= 1 creates the memfd exec-sealed.
_MFD_EXEC = 0x10
_PROC_FD = "/proc/self/fd"


class ImplementationUnavailable(OSError):
    """The artefact cannot be pinned and executed here. There is no path fallback."""


def executable_digest(name: str, path: str | None = None) -> str:
    """Digest of the program ``name`` resolves to: its real path plus its bytes.

    ``path`` is a search path in ``PATH`` format; ``None`` uses the process
    ``PATH``. Symlinks are followed, so retargeting a link changes the digest.
    A name that does not resolve raises ``FileNotFoundError``, which an
    observer turns into a fail-closed mismatch.
    """
    real = _resolve(name, path)
    src = _open_regular(real)
    try:
        return _program_digest(real, src)
    finally:
        os.close(src)


class ResolvedExecutable:
    """A sealed in-memory copy of one resolved program, and the digest of that copy.

    Use one handle per invoke: return ``digest`` from the implementation
    observer and call ``run`` from the tool, so the PEP checks exactly the
    bytes that run. Close it, or use it as a context manager; a handle that is
    never closed is closed when collected. It is not thread-safe: do not close
    it while another thread is running it.
    """

    __slots__ = ("real_path", "digest", "_fd", "_finalizer", "__weakref__")

    def __init__(self, real_path: Path, digest: str, fd: int) -> None:
        self.real_path = real_path
        self.digest = digest
        self._fd = fd
        self._finalizer = weakref.finalize(self, os.close, fd)

    def fileno(self) -> int:
        if self._fd < 0:
            raise ValueError("executable handle is closed")
        return self._fd

    @property
    def exec_path(self) -> str:
        return f"{_PROC_FD}/{self.fileno()}"

    def run(
        self,
        args: Sequence[str] = (),
        *,
        interpreter: str | os.PathLike[str] | ResolvedExecutable | None = None,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[Any]:
        """Run the sealed copy; ``kwargs`` go to ``subprocess.run``.

        ``interpreter`` runs the copy as a script under that interpreter. A
        ``ResolvedExecutable`` interpreter is itself run from its sealed copy.
        ``shell``, ``executable`` and ``preexec_fn`` are refused: each can run
        something other than the copy. Caller ``pass_fds`` are kept.
        """
        for refused in ("shell", "executable", "preexec_fn"):
            if refused in kwargs:
                raise TypeError(f"run() does not accept {refused}=")
        fds = set(kwargs.pop("pass_fds", ()))
        fds.add(self.fileno())
        if interpreter is None:
            argv = [self.exec_path]
        elif isinstance(interpreter, ResolvedExecutable):
            fds.add(interpreter.fileno())
            argv = [interpreter.exec_path, self.exec_path]
        else:
            argv = [os.fspath(interpreter), self.exec_path]
        return subprocess.run([*argv, *args], pass_fds=tuple(sorted(fds)), **kwargs)

    def close(self) -> None:
        if self._fd >= 0:
            self._finalizer()
            self._fd = -1

    def __enter__(self) -> ResolvedExecutable:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_executable(
    name: str,
    path: str | None = None,
    *,
    _before_open: Callable[[Path], None] | None = None,
    _after_copy: Callable[[Path], None] | None = None,
) -> ResolvedExecutable:
    """Copy the program ``name`` resolves to into a sealed memfd and digest the copy.

    The digest uses the ``executable_digest`` formula over the real path and
    the whole sealed file, read back after sealing, so a digest frozen at mint
    matches an unchanged program and anything changed before the seals does
    not. A source that is not a regular file is refused. Linux only: without
    ``os.memfd_create``, sealing or ``/proc/self/fd``, or under a kernel policy
    that refuses an executable memfd, this raises ``ImplementationUnavailable``.
    ``_before_open`` and ``_after_copy`` are test seams.
    """
    if not hasattr(os, "memfd_create") or not os.path.isdir(_PROC_FD):
        raise ImplementationUnavailable("sealed in-memory exec is not available on this platform")
    try:
        import fcntl

        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    except (ImportError, AttributeError) as exc:
        raise ImplementationUnavailable("file sealing is not available on this platform") from exc
    real = _resolve(name, path)
    if _before_open is not None:
        _before_open(real)
    src = _open_regular(real)
    try:
        fd = _create_memfd()
        try:
            _copy(src, fd)
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(src)
    try:
        try:
            os.fchmod(fd, 0o500)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        except OSError as exc:
            raise ImplementationUnavailable(f"cannot seal an executable copy: {exc.strerror}") from exc
        if _after_copy is not None:
            _after_copy(real)
        return ResolvedExecutable(real, _program_digest(real, fd), fd)
    except BaseException:
        os.close(fd)
        raise


def combined_digest(*parts: ResolvedExecutable | str) -> str:
    """One digest over several, in order: script then interpreter, for example.

    Each part is a handle or a ``sha256:`` digest string, so the value frozen
    at mint from ``executable_digest`` results equals the value observed from
    handles.
    """
    if not parts:
        raise ValueError("combined_digest needs at least one part")
    digests = [part.digest if isinstance(part, ResolvedExecutable) else part for part in parts]
    for digest in digests:
        if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("combined_digest parts must be sha256: digests or handles")
    return _digest("\0".join(digests).encode("utf-8"))


def callable_digest(fn: Callable[..., object]) -> str:
    """Digest of an in-process callable: module, qualified name and code object.

    The code object is serialised with ``marshal``, so the digest is stable
    within one interpreter version, not across versions. It includes the
    source file name and first line number, so moving or re-indenting code
    changes the digest (a fail-closed mismatch). Not covered: default
    argument values (``__defaults__``, ``__kwdefaults__``), closure cell
    values, globals, and anything the code imports at call time. A wrapper
    such as one from ``functools.wraps`` digests as the wrapper, not the
    function it wraps. A bound method digests as its function. Callables
    without a Python code object raise ``TypeError``.
    """
    code = getattr(fn, "__code__", None)
    if code is None:
        raise TypeError(f"callable has no Python code object: {fn!r}")
    header = f"{fn.__module__}\0{fn.__qualname__}\0".encode("utf-8")
    return _digest(header + marshal.dumps(code))


def _resolve(name: str, path: str | None) -> Path:
    resolved = shutil.which(name, path=path)
    if resolved is None:
        raise FileNotFoundError(f"executable not found: {name}")
    return Path(resolved).resolve()


def _program_digest(real: Path, fd: int) -> str:
    """The executable_digest formula, streamed from ``fd`` to end of file."""
    h = hashlib.sha256(str(real).encode("utf-8") + b"\0")
    offset = 0
    while chunk := os.pread(fd, 1 << 20, offset):
        h.update(chunk)
        offset += len(chunk)
    return "sha256:" + h.hexdigest()


def _open_regular(real: Path) -> int:
    # O_NONBLOCK so a FIFO on PATH cannot hang the open.
    fd = os.open(real, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ImplementationUnavailable(f"not a regular file: {real}")
    return fd


def _create_memfd() -> int:
    base = os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC
    try:
        return os.memfd_create("pep-exec", base | _MFD_EXEC)
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            # Kernels before 6.3 do not know MFD_EXEC; they never exec-seal.
            try:
                return os.memfd_create("pep-exec", base)
            except OSError as retry:
                raise ImplementationUnavailable(f"memfd_create failed: {retry.strerror}") from retry
        if exc.errno in (errno.EPERM, errno.EACCES):
            raise ImplementationUnavailable("kernel policy refuses an executable memfd") from exc
        raise


def _copy(src: int, dst: int) -> None:
    while chunk := os.read(src, 1 << 20):
        view = memoryview(chunk)
        while view:
            view = view[os.write(dst, view):]


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
