# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Halt file for the reference host.

A missing, unreadable, or ill-formed file is halted. Writing a kill that
does not land raises ``HaltStoreError``. The in-process ``HaltStore``
still treats a missing file as active; that library default is not a
security boundary (ADR-0007).

The bytes are read once. A second look at a path that disappeared in
between would treat the gap as active, which this reader must not do.
"""

from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path

from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError, parse_halt_text
from pep.host.fsguard import PathGuardError, require_directory

# Why the host will not treat the file as active.
MISSING = "missing"
NOT_A_FILE = "not_a_file"
UNREADABLE = "unreadable"
CORRUPT = "corrupt"
ACTIVE = "active"
SUSPENDED = "suspended"
KILLED = "killed"

_HALT_READ_LIMIT = 1_048_576


def read_fail_closed(path: Path) -> tuple[HaltState, str]:
    """Read a halt file. Any doubt is halted.

    The second value names what was observed: ``missing``, ``not_a_file``,
    ``unreadable``, ``corrupt``, ``active``, ``suspended``, or ``killed``.
    This function does not create the file. It opens the path once and
    classifies those bytes. It does not follow a symlink.
    """
    path = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return _killed(), MISSING
    except OSError as exc:
        return _open_error(exc)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return _killed(), NOT_A_FILE
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > _HALT_READ_LIMIT:
                return _killed(), CORRUPT
            chunks.append(block)
    except OSError:
        return _killed(), UNREADABLE
    finally:
        os.close(fd)
    try:
        raw = b"".join(chunks).decode("utf-8")
    except UnicodeError:
        return _killed(), UNREADABLE
    return _classify(raw)


def init_active(path: Path) -> HaltState:
    """Create an active halt file. Refuses to clear a kill or a bad file."""
    path = Path(path)
    _private_parent(path)
    state, observed = read_fail_closed(path)
    if observed == MISSING:
        written = HaltStore(path).write(HaltState(mode=HaltMode.ACTIVE, available=True))
        if written.mode is not HaltMode.ACTIVE or not written.available:
            raise HaltStoreError("halt file did not become active")
        _restrict(path)
        return written
    if observed == ACTIVE:
        _restrict(path)
        return state
    raise HaltStoreError(
        f"refusing to mark the halt file active ({observed}); a kill is not cleared by rewriting it"
    )


def write_killed(path: Path) -> HaltState:
    """Persist a kill. Raises ``HaltStoreError`` when the write does not land.

    Does not report success if the file is left active. A missing file is
    written as killed so a later reader cannot treat the absence as active.
    """
    path = Path(path)
    _private_parent(path)
    state, observed = read_fail_closed(path)
    if observed in {NOT_A_FILE, UNREADABLE}:
        raise HaltStoreError(f"halt file cannot be written ({observed})")
    if observed == KILLED and state.mode is HaltMode.KILLED:
        _restrict(path)
        return state
    try:
        written = HaltStore(path).write(HaltState(mode=HaltMode.KILLED, available=True))
    except HaltStoreError:
        raise
    except OSError as exc:
        raise HaltStoreError(f"halt store persist failed: {exc}") from exc
    if written.mode is not HaltMode.KILLED:
        raise HaltStoreError("halt file was not left killed")
    _restrict(path)
    confirmed, after = read_fail_closed(path)
    if after != KILLED or confirmed.mode is not HaltMode.KILLED:
        raise HaltStoreError(f"halt file did not read back as killed ({after})")
    return confirmed


def _private_parent(path: Path) -> None:
    try:
        require_directory(path.parent, allow_group_traverse=False)
    except PathGuardError as exc:
        raise HaltStoreError(str(exc)) from exc


def _restrict(path: Path) -> None:
    """Owner-only mode on the open file, not on a path that might be a symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise HaltStoreError("halt file is not a regular file owned by this user")
        os.fchmod(fd, 0o600)
    except OSError as exc:
        raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc
    finally:
        os.close(fd)


def _killed() -> HaltState:
    return HaltState(mode=HaltMode.KILLED, available=False)


def _open_error(exc: OSError) -> tuple[HaltState, str]:
    err = exc.errno
    if err == errno.ENOENT:
        return _killed(), MISSING
    if err in {errno.ELOOP, errno.EISDIR, errno.ENOTDIR}:
        return _killed(), NOT_A_FILE
    return _killed(), UNREADABLE


def _classify(raw: str) -> tuple[HaltState, str]:
    if not raw.strip():
        return _killed(), CORRUPT
    state = parse_halt_text(raw)
    if state.mode is HaltMode.KILLED or not state.available:
        if state.mode is HaltMode.KILLED and not state.available and _looks_corrupt(raw):
            return state, CORRUPT
        return state, KILLED
    if state.mode is HaltMode.SUSPENDED:
        return state, SUSPENDED
    if state.mode is HaltMode.ACTIVE:
        return state, ACTIVE
    return _killed(), CORRUPT


def _looks_corrupt(raw: str) -> bool:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return True
    if not isinstance(data, dict):
        return True
    if data.get("schema") != "acl-pep-halt-v1":
        return True
    if data.get("mode") not in {mode.value for mode in HaltMode}:
        return True
    available = data.get("available", True)
    return not isinstance(available, bool)
