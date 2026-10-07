# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Halt file for the reference host.

A missing, unreadable, or ill-formed file is halted. Writing a kill that
does not land raises ``HaltStoreError``. The in-process ``HaltStore``
still treats a missing file as active; that library default is not a
security boundary (ADR-0007).
"""

from __future__ import annotations

from pathlib import Path

from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError

# Why the host will not treat the file as active.
MISSING = "missing"
NOT_A_FILE = "not_a_file"
UNREADABLE = "unreadable"
CORRUPT = "corrupt"
ACTIVE = "active"
SUSPENDED = "suspended"
KILLED = "killed"


def read_fail_closed(path: Path) -> tuple[HaltState, str]:
    """Read a halt file. Any doubt is halted.

    The second value names what was observed: ``missing``, ``not_a_file``,
    ``unreadable``, ``corrupt``, ``active``, ``suspended``, or ``killed``.
    This function does not create the file.
    """
    path = Path(path)
    try:
        is_file = path.is_file()
    except OSError:
        return HaltState(mode=HaltMode.KILLED, available=False), UNREADABLE
    if not path.exists():
        return HaltState(mode=HaltMode.KILLED, available=False), MISSING
    if not is_file:
        return HaltState(mode=HaltMode.KILLED, available=False), NOT_A_FILE
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return HaltState(mode=HaltMode.KILLED, available=False), UNREADABLE
    try:
        # HaltStore already fails closed on corrupt bytes. It is only asked
        # to read when a regular file was readable, so a missing file cannot
        # be reported as active from here.
        state = HaltStore(path).read()
    except OSError:
        return HaltState(mode=HaltMode.KILLED, available=False), UNREADABLE
    if not raw.strip():
        return HaltState(mode=HaltMode.KILLED, available=False), CORRUPT
    if state.mode is HaltMode.KILLED or not state.available:
        # Corrupt documents come back as killed and unavailable.
        if state.mode is HaltMode.KILLED and not state.available and _looks_corrupt(raw):
            return state, CORRUPT
        return state, KILLED
    if state.mode is HaltMode.SUSPENDED:
        return state, SUSPENDED
    if state.mode is HaltMode.ACTIVE:
        return state, ACTIVE
    return HaltState(mode=HaltMode.KILLED, available=False), CORRUPT


def _looks_corrupt(raw: str) -> bool:
    import json

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return True
    if not isinstance(data, dict):
        return True
    if data.get("schema") != "acl-pep-halt-v1":
        return True
    if data.get("mode") not in {m.value for m in HaltMode}:
        return True
    available = data.get("available", True)
    return not isinstance(available, bool)


def init_active(path: Path) -> HaltState:
    """Create an active halt file. Refuses to clear a kill or a bad file."""
    path = Path(path)
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


def _restrict(path: Path) -> None:
    """Best-effort owner-only mode. A failure here is a failed write."""
    try:
        path.chmod(0o600)
    except OSError as exc:
        raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc
