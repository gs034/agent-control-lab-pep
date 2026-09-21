# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Durable kill / suspend store (JSON file). Survives process restart.

Operator API stays capability language: kill, suspend, resume. This module
is a file-backed mode table, not a product console. Corrupt or unreadable
bytes fail closed to kill. A persisted kill cannot be overwritten by
suspend or resume.

The late-effect fence (cut epoch for queued or in-flight admissions) lives
on ``PepRuntime``, not in this file. Reloading a killed store denies new
evaluates as ``kill_active``. It does not reconstruct another process's
admissions.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping


class HaltMode(StrEnum):
    """Persisted PEP mode. Mirrors ``pep.evaluate.RuntimeMode`` strings."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    KILLED = "killed"


HALT_SCHEMA = "acl-pep-halt-v1"
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
        with self._lock:
            current = self._read_unlocked()
            next_state = _merge_sticky_kill(current, state)
            self._write_unlocked(next_state)
            return next_state

    def _read_unlocked(self) -> HaltState:
        path = self.path
        if not path.is_file():
            return HaltState(mode=HaltMode.ACTIVE, available=True)
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return HaltState(mode=HaltMode.KILLED, available=False)
        return _parse_halt_document(data)

    def _write_unlocked(self, state: HaltState) -> None:
        stamp = state.updated_at or _utc_zulu()
        payload = {
            "available": state.available,
            "mode": state.mode.value,
            "schema": HALT_SCHEMA,
            "updated_at": stamp,
        }
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            tmp.write_text(text + "\n", encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise HaltStoreError(f"halt store persist failed: {exc}") from exc


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
