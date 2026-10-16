# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Durable kill / suspend store (JSON file). Survives process restart.

Operator API stays capability language: kill, suspend, resume. This module
is a file-backed mode table, not a product console. Corrupt or unreadable
bytes fail closed to kill. A persisted kill cannot be overwritten by
suspend or resume.

Every write is a read, a merge, and a rename. Two processes can write the
same file: the reference gate rewrites it on suspend and resume, and
``python -m pep.host kill`` writes the kill. Each write holds an exclusive
``flock`` on a lock file next to the halt file (``.<name>.lock``) from the
read to the rename, so a kill that lands first is read by the next writer
and merged as sticky. Without that lock a gate that read "active" before
the kill landed could rename "active" over it.

``write_if`` is the compare-and-write form. It re-reads the file under the
lock and writes only if the file still holds the mode the caller's decision
was based on. The reference gate mirrors suspend and resume with it, so an
operator's suspend or delete that lands after the gate's read is kept.

The late-effect fence (cut epoch for queued or in-flight admissions) lives
on ``PepRuntime``, not in this file. Reloading a killed store denies new
evaluates as ``kill_active``. It does not reconstruct another process's
admissions.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - the reference host is Linux only
    fcntl = None  # type: ignore[assignment]


class HaltMode(StrEnum):
    """Persisted PEP mode. Mirrors ``pep.evaluate.RuntimeMode`` strings."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    KILLED = "killed"


HALT_SCHEMA = "acl-pep-halt-v1"
# How long a write waits for another writer's lock before it fails.
LOCK_WAIT_SECONDS = 5.0
_VALID_MODES = frozenset(m.value for m in HaltMode)


@dataclass(frozen=True, slots=True)
class HaltState:
    mode: HaltMode
    available: bool = True
    updated_at: str | None = None

    def killed(self) -> bool:
        return self.mode is HaltMode.KILLED or not self.available


class HaltStoreError(ValueError):
    """Persist-time failure. Evaluate path treats unread store as kill."""


@dataclass(frozen=True, slots=True)
class HaltStore:
    """JSON halt table. Missing file is active; unreadable file is kill."""

    path: Path
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
        compare=False,
        hash=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))

    def read(self) -> HaltState:
        with self._lock:
            return self._read_unlocked()

    def write(self, state: HaltState) -> HaltState:
        """Merge ``state`` with the file and persist it. A kill on disk stays.

        The read, the merge and the rename run under this object's thread
        lock and an exclusive ``flock`` on the lock file, so another process
        writing the same halt file waits for the rename.
        """
        with self._lock:
            lock_fd = self._acquire_file_lock()
            try:
                current = self._read_unlocked()
                next_state = _merge_sticky_kill(current, state)
                self._write_unlocked(next_state)
                return next_state
            finally:
                _release_file_lock(lock_fd)

    def write_if(self, expected: HaltMode, state: HaltState) -> tuple[HaltState | None, bool]:
        """Compare and write: persist ``state`` only if the file still reads ``expected``.

        The comparison runs under the same thread lock and ``flock`` as
        ``write``, after the lock is taken. Returns the state on disk after
        the call (``None`` when the file is missing) and whether this call
        wrote it. A missing file is never recreated, and a file that is
        killed, unavailable, unreadable, or in another mode is left as it is.
        A caller that mirrors a mode it read earlier uses this, so a change
        that lands between that read and this write is not overwritten.
        """
        with self._lock:
            lock_fd = self._acquire_file_lock()
            try:
                current = self._read_existing_unlocked()
                if current is None:
                    return None, False
                if current.mode is not expected or not current.available:
                    return current, False
                next_state = _merge_sticky_kill(current, state)
                self._write_unlocked(next_state)
                return next_state, True
            finally:
                _release_file_lock(lock_fd)

    @property
    def lock_path(self) -> Path:
        return self.path.parent / f".{self.path.name}.lock"

    def _acquire_file_lock(self) -> int:
        """Open and ``flock`` the lock file. Raises ``HaltStoreError`` if that fails.

        A write that cannot take the lock does not happen, so a caller that
        asked for a kill sees the error rather than a write that might race.
        The wait is bounded (``LOCK_WAIT_SECONDS``): a process that holds the
        lock for ever makes writes fail, it does not hang the caller.
        """
        if fcntl is None:  # pragma: no cover - the reference host is Linux only
            return -1
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = -1
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.lock_path, flags, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise HaltStoreError("halt lock file is not a regular file owned by this user")
            _flock_bounded(fd)
        except HaltStoreError:
            if fd >= 0:
                os.close(fd)
            raise
        except OSError as exc:
            if fd >= 0:
                os.close(fd)
            raise HaltStoreError(f"halt store lock failed: {exc}") from exc
        return fd

    def _read_unlocked(self) -> HaltState:
        path = self.path
        if not path.is_file():
            return HaltState(mode=HaltMode.ACTIVE, available=True)
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            return HaltState(mode=HaltMode.KILLED, available=False)
        return _parse_halt_document(data)

    def _read_existing_unlocked(self) -> HaltState | None:
        """One read of the file. ``None`` only when it does not exist."""
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError):
            return HaltState(mode=HaltMode.KILLED, available=False)
        return parse_halt_text(raw)

    def _write_unlocked(self, state: HaltState) -> None:
        stamp = state.updated_at or _utc_zulu()
        payload = {
            "available": state.available,
            "mode": state.mode.value,
            "schema": HALT_SCHEMA,
            "updated_at": stamp,
        }
        path = self.path
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        # A fixed ``name.tmp`` can be planted. The temp name is unique to this write.
        fd = -1
        tmp_name = ""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
            os.write(fd, (text + "\n").encode("utf-8"))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise HaltStoreError("halt temp file is not a regular file owned by this user")
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp_name, path)
            tmp_name = ""
            _fsync_directory(path.parent)
        except OSError as exc:
            raise HaltStoreError(f"halt store persist failed: {exc}") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass


def _flock_bounded(fd: int) -> None:
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise HaltStoreError("halt store lock is held by another writer") from None
            time.sleep(0.01)


def _release_file_lock(fd: int) -> None:
    if fd < 0:
        return
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        os.close(fd)


def _fsync_directory(parent: Path) -> None:
    """Persist the rename. The temporary file itself is fsynced before it."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    dirfd = os.open(parent, flags)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def parse_halt_text(raw: str) -> HaltState:
    """Parse halt bytes the caller already read. Does not touch the filesystem."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return HaltState(mode=HaltMode.KILLED, available=False)
    return _parse_halt_document(data)


def _parse_halt_document(data: Any) -> HaltState:
    if not isinstance(data, Mapping):
        return HaltState(mode=HaltMode.KILLED, available=False)
    if data.get("schema") != HALT_SCHEMA:
        return HaltState(mode=HaltMode.KILLED, available=False)
    mode_raw = data.get("mode")
    if mode_raw not in _VALID_MODES:
        return HaltState(mode=HaltMode.KILLED, available=False)
    available = data.get("available", True)
    if not isinstance(available, bool):
        return HaltState(mode=HaltMode.KILLED, available=False)
    updated = data.get("updated_at")
    if updated is not None and not isinstance(updated, str):
        return HaltState(mode=HaltMode.KILLED, available=False)
    return HaltState(mode=HaltMode(mode_raw), available=available, updated_at=updated)


def _merge_sticky_kill(current: HaltState, requested: HaltState) -> HaltState:
    """Kill is sticky at the store layer. Resume cannot clear it."""
    stamp = requested.updated_at or _utc_zulu()
    if current.mode is HaltMode.KILLED or requested.mode is HaltMode.KILLED:
        available = current.available and requested.available
        return HaltState(mode=HaltMode.KILLED, available=available, updated_at=stamp)
    available = current.available and requested.available
    if not available:
        return HaltState(mode=requested.mode, available=False, updated_at=stamp)
    return HaltState(mode=requested.mode, available=True, updated_at=stamp)


def _utc_zulu() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
