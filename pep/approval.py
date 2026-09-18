# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Single-use TTL approval grants (process-local; operator-issued).

Approvals are capability grants, not caller identity and not prose.
They never extend the frozen tool catalog. An approval may authorize
one use of an already-allowlisted tool before its TTL elapses.
Replay, expiry, unknown id, or uncovered tool fail closed.
"""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Mapping

from pep.reasons import ReasonCode

APPROVAL_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_TTL_SECONDS = 86_400
MIN_TTL_SECONDS = 1


class ApprovalError(ValueError):
    """Mint-time failure. Evaluate path uses reason codes, not this type."""


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    tools: tuple[str, ...]
    expires_at: datetime
    single_use: bool = True
    consumed_at: datetime | None = None

    def covers(self, tool_name: str) -> bool:
        return tool_name in self.tools

    def expired(self, now: datetime) -> bool:
        return self.expires_at <= now

    def consumed(self) -> bool:
        return self.consumed_at is not None


class ApprovalStore:
    """In-process single-use TTL approval table.

    Minting is an operator/runtime API. Envelope ``approval_id`` is only a
    reference; the PEP looks up this store. Prose cannot insert a row.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, ApprovalRecord] = {}

    def issue(
        self,
        *,
        tools: tuple[str, ...] | list[str],
        ttl_seconds: int,
        approval_id: str | None = None,
        now: datetime | None = None,
        catalog: Mapping[str, object] | None = None,
    ) -> ApprovalRecord:
        clock = _aware(now)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ApprovalError("ttl_seconds must be a positive integer")
        if ttl_seconds < MIN_TTL_SECONDS or ttl_seconds > MAX_TTL_SECONDS:
            raise ApprovalError(
                f"ttl_seconds must be in [{MIN_TTL_SECONDS}, {MAX_TTL_SECONDS}]"
            )
        tool_tuple = tuple(tools)
        if not tool_tuple or any(not isinstance(t, str) or not t for t in tool_tuple):
            raise ApprovalError("approval must cover at least one tool id")
        if catalog is not None:
            unknown = [t for t in tool_tuple if t not in catalog]
            if unknown:
                raise ApprovalError(
                    f"cannot mint approval for tools outside catalog: {unknown}"
                )
        token = approval_id or f"lab.appr.{uuid.uuid4().hex}"
        if not isinstance(token, str) or not APPROVAL_ID_RE.fullmatch(token):
            raise ApprovalError("approval_id is missing or malformed")
        record = ApprovalRecord(
            approval_id=token,
            tools=tool_tuple,
            expires_at=clock + timedelta(seconds=ttl_seconds),
            single_use=True,
            consumed_at=None,
        )
        with self._lock:
            if token in self._records:
                raise ApprovalError("approval_id already issued")
            self._records[token] = record
        return record

    def lookup(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._records.get(approval_id)

    def try_consume(
        self,
        approval_id: str,
        tool_name: str,
        now: datetime | None = None,
    ) -> ReasonCode | None:
        """Atomically consume a valid grant. ``None`` means the grant was taken.

        Any other return is a fail-closed deny reason. Single-use is enforced
        under the lock so two concurrent allows cannot share one grant.
        """
        clock = _aware(now)
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ReasonCode.APPROVAL_INVALID
            if record.consumed():
                return ReasonCode.APPROVAL_CONSUMED
            if record.expired(clock):
                return ReasonCode.APPROVAL_EXPIRED
            if not record.covers(tool_name):
                return ReasonCode.APPROVAL_INVALID
            if not record.single_use:
                return ReasonCode.APPROVAL_INVALID
            self._records[approval_id] = replace(record, consumed_at=clock)
            return None


def _aware(now: datetime | None) -> datetime:
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ApprovalError("clock must be timezone-aware")
    return clock.astimezone(timezone.utc)
