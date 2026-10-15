# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Append-only decision log for the reference host.

The agent has no command that writes or deletes this file. Records list
checks that ran. They do not carry a boolean that is true by construction
(for example "policy unchanged").

The log is opened with ``O_NOFOLLOW``. The descriptor is checked with
``fstat`` before ``fchmod``. A symlink at the log path is refused, so a
planted link cannot receive the records.

Only the immediate parent directory is checked, not its parents. At
startup the host counts existing lines by reading the file in chunks,
so sequence numbers continue without holding the whole file. One line
longer than ``MAX_LOG_STARTUP_BYTES`` is refused. A file of shorter
lines may be larger than that and the host still starts. The host does
not rotate the log.

Records are bounded. A check that lists names from the request (unknown
keys) lists at most ``MAX_LISTED_KEYS`` of them, each clipped to
``MAX_KEY_CHARS``, plus a count of the rest. One line is at most
``MAX_RECORD_BYTES``: a longer record has its strings clipped, then its
nested fields dropped, and carries a ``truncated`` string saying so. An
agent that sends large requests cannot grow the log faster than the
denial coalescing allows lines, times this bound.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Mapping

from pep.host.fsguard import PathGuardError, require_directory

DECISION_SCHEMA = "acl-pep-host-decision-v1"
# Maximum bytes of one existing line read at startup. Not a maximum
# file size: many shorter lines can add up to more than this.
MAX_LOG_STARTUP_BYTES = 1_048_576
# Maximum bytes of one appended line, newline excluded. Well under the
# startup limit, so a line the host wrote never stops it restarting.
MAX_RECORD_BYTES = 8_192
# A string inside an over-long record is clipped to this many characters.
MAX_FIELD_CHARS = 240
# A check detail lists at most this many request-supplied names, each
# clipped to ``MAX_KEY_CHARS``.
MAX_LISTED_KEYS = 8
MAX_KEY_CHARS = 64
# Kept when an over-long record still does not fit after clipping.
_CORE_KEYS = (
    "decision",
    "reason_code",
    "reason_detail",
    "request_id",
    "schema",
    "seq",
    "session_id",
    "timestamp",
    "tool_name",
)

# Names that would claim a check the host did not perform, or a boolean
# that cannot be false. Rejected at append time.
FORBIDDEN_KEYS = frozenset(
    {
        "agent_prose_used_as_policy",
        "fail_closed",
        "llm_cot_transcript_judge",
        "monitor_coax_accepted",
        "policy_file_unchanged",
        "policy_unchanged",
        "tool_invoke_executed",
    }
)


class DecisionLogError(OSError):
    """The host could not append a decision. Callers must not allow the tool."""


def _count_log_lines(fd: int) -> int:
    """Count non-empty lines without keeping the file in memory.

    A single line longer than ``MAX_LOG_STARTUP_BYTES`` is refused. The
    file itself may be larger.
    """
    count = 0
    tail = b""
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        data = tail + block
        if b"\n" not in data:
            if len(data) > MAX_LOG_STARTUP_BYTES:
                raise DecisionLogError("decision log line exceeds the startup read limit")
            tail = data
            continue
        parts = data.split(b"\n")
        tail = parts.pop()
        if len(tail) > MAX_LOG_STARTUP_BYTES:
            raise DecisionLogError("decision log line exceeds the startup read limit")
        for line in parts:
            count += _line_counts(line)
    if tail:
        count += _line_counts(tail)
    return count


def _line_counts(line: bytes) -> int:
    if len(line) > MAX_LOG_STARTUP_BYTES:
        raise DecisionLogError("decision log line exceeds the startup read limit")
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecisionLogError("decision log is not utf-8") from exc
    return 1 if text.strip() else 0


def describe_keys(keys: Any) -> str:
    """Request-supplied names for a check detail: sorted, at most ``MAX_LISTED_KEYS``, each clipped."""
    names = sorted(str(key) for key in keys)
    shown = [_clip(name, MAX_KEY_CHARS) for name in names[:MAX_LISTED_KEYS]]
    text = ", ".join(shown)
    if len(names) > MAX_LISTED_KEYS:
        text += f" (+{len(names) - MAX_LISTED_KEYS} more)"
    return text


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _clip_strings(value: Any) -> Any:
    if isinstance(value, str):
        return _clip(value, MAX_FIELD_CHARS)
    if isinstance(value, Mapping):
        return {key: _clip_strings(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clip_strings(item) for item in value]
    return value


def _encode(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def bound_record(stored: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Return the record to write and its line, at most ``MAX_RECORD_BYTES``.

    A record that fits is unchanged. Otherwise every string is clipped to
    ``MAX_FIELD_CHARS``; if that is still too long, only top-level scalars
    and each check's name and outcome are kept, and last only ``_CORE_KEYS``. Each step adds a ``truncated``
    string, so a reader can tell the line was shortened and from what size.
    """
    line = _encode(stored)
    if len(line) <= MAX_RECORD_BYTES:
        return stored, line
    original = len(line)
    clipped = _clip_strings(stored)
    clipped["truncated"] = f"record of {original} bytes; strings clipped to {MAX_FIELD_CHARS} characters"
    line = _encode(clipped)
    if len(line) <= MAX_RECORD_BYTES:
        return clipped, line
    flat = {key: value for key, value in clipped.items() if value is None or isinstance(value, (str, int, float))}
    checks = clipped.get("checks")
    if isinstance(checks, list):
        flat["checks"] = [
            {key: item[key] for key in ("name", "outcome") if key in item} for item in checks if isinstance(item, Mapping)
        ]
    flat["truncated"] = f"record of {original} bytes; nested fields dropped, check names and outcomes kept"
    line = _encode(flat)
    if len(line) <= MAX_RECORD_BYTES:
        return flat, line
    core = {key: flat[key] for key in _CORE_KEYS if key in flat}
    core["truncated"] = f"record of {original} bytes; only core fields kept"
    return core, _encode(core)


def reject_unrun_claims(value: Any) -> None:
    """Raise if a record contains a boolean or a forbidden claim name."""
    if isinstance(value, bool):
        raise ValueError("decision record must not carry a boolean claim")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in FORBIDDEN_KEYS:
                raise ValueError(f"decision record must not claim {key}")
            reject_unrun_claims(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            reject_unrun_claims(item)


class DecisionLog:
    """JSON lines opened append-only. Mode 0600. No truncate and no delete."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._prepare_parent(self.path.parent)
        self._lock = threading.Lock()
        self._seq = 0
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise DecisionLogError(f"decision log unreadable: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise DecisionLogError("decision log is not a regular file")
            if info.st_uid != os.getuid():
                raise DecisionLogError("decision log is not owned by this user")
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise DecisionLogError("decision log is not a regular file")
            if info.st_uid != os.getuid():
                raise DecisionLogError("decision log is not owned by this user")
            if stat.S_IMODE(info.st_mode) & 0o777 != 0o600:
                raise DecisionLogError("decision log mode is not 0600")
            os.lseek(fd, 0, os.SEEK_SET)
            read_fd = os.dup(fd)
            try:
                seq = _count_log_lines(read_fd)
            finally:
                os.close(read_fd)
            self._fp = os.fdopen(fd, "a", encoding="utf-8")
            fd = -1
        except Exception:
            if fd >= 0:
                os.close(fd)
            raise
        # Count lines already there so a restarted host does not reuse seq.
        self._seq = seq

    def append(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Append one record. Returns the stored object, including ``seq``."""
        reject_unrun_claims(record)
        with self._lock:
            self._seq += 1
            stored = {key: value for key, value in dict(record).items() if key not in {"schema", "seq"}}
            stored["schema"] = DECISION_SCHEMA
            stored["seq"] = self._seq
            reject_unrun_claims(stored)
            stored, line = bound_record(stored)
            try:
                self._fp.write(line + "\n")
                self._fp.flush()
                os.fsync(self._fp.fileno())
            except OSError as exc:
                self._seq -= 1
                raise DecisionLogError(f"decision log append failed: {exc}") from exc
            return stored

    def read_records(self) -> list[dict[str, Any]]:
        """Operator read of the file the host wrote. Not an agent command."""
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise DecisionLogError(f"decision log unreadable: {exc}") from exc
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            raise DecisionLogError(f"decision log unreadable: {exc}") from exc
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                raise DecisionLogError("decision log line is not an object")
            records.append(parsed)
        return records

    def close(self) -> None:
        with self._lock:
            if self._fp.closed:
                return
            self._fp.close()

    @staticmethod
    def _prepare_parent(parent: Path) -> None:
        try:
            os.lstat(parent)
        except FileNotFoundError:
            os.mkdir(parent, 0o700)
            dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fchmod(dirfd, 0o700)
            finally:
                os.close(dirfd)
        except OSError as exc:
            raise DecisionLogError(f"decision log directory unreadable: {exc}") from exc
        try:
            require_directory(parent, allow_group_traverse=False)
        except PathGuardError as exc:
            raise DecisionLogError(str(exc)) from exc
