# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Single-use TTL approval grants (process-local; operator-issued).

Approvals are capability grants, not caller identity and not prose.
They never extend the frozen tool catalog. An approval authorizes one
use of an already-allowlisted invoke (tool_name + canonical args) before
its TTL elapses. Replay, expiry, unknown id, uncovered tool, or a
post-mint args substitution fail closed. An operator may also freeze a
state digest at mint (a host-computed digest of the object the invoke
acts on); consume then requires the host-observed digest to match, so a
substitution of the target between approval and execute is DENY.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping

from pep.canonical import canonical_dumps, sha256_prefixed
from pep.reasons import ReasonCode

APPROVAL_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
STATE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_TTL_SECONDS = 86_400
MIN_TTL_SECONDS = 1


class ApprovalError(ValueError):
    """Mint-time failure. Evaluate path uses reason codes, not this type."""


class ObserverReentry(ApprovalError):
    """A state observer called back into the store that is waiting on it."""


def freeze_invoke_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-round-trip args so mint and consume share one canonical object."""
    if not isinstance(args, Mapping) or isinstance(args, (str, bytes)):
        raise ApprovalError("approval args must be a JSON object")
    try:
        payload = json.loads(canonical_dumps(dict(args)))
    except (TypeError, ValueError) as exc:
        raise ApprovalError(f"approval args not JSON-serializable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ApprovalError("approval args must be a JSON object")
    return payload


def invoke_binding(tool_name: str, args: Mapping[str, Any]) -> dict[str, Any]:
    """Policy-relevant approved invoke. Prose and policy_context are omitted."""
    if not isinstance(tool_name, str) or not tool_name:
        raise ApprovalError("approval binding requires a tool id")
    return {"args": freeze_invoke_args(args), "tool_name": tool_name}


def invoke_binding_digest(tool_name: str, args: Mapping[str, Any]) -> str:
    return sha256_prefixed(invoke_binding(tool_name, args))


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    tools: tuple[str, ...]
    expires_at: datetime
    binding_digest: str
    frozen_args: Mapping[str, Any]
    single_use: bool = True
    consumed_at: datetime | None = None
    state_digest: str | None = None

    def covers(self, tool_name: str) -> bool:
        return tool_name in self.tools

    def matches_binding(self, tool_name: str, args: Mapping[str, Any]) -> bool:
        try:
            digest = invoke_binding_digest(tool_name, args)
        except ApprovalError:
            return False
        return self.covers(tool_name) and self.binding_digest == digest

    def matches_state(self, observed_state_digest: object) -> bool:
        return state_matches(self.state_digest, observed_state_digest)

    def expired(self, now: datetime) -> bool:
        return self.expires_at <= now

    def consumed(self) -> bool:
        return self.consumed_at is not None


@dataclass(frozen=True, slots=True)
class ConsumeResult:
    """Outcome of one consume attempt. ``reason`` is None when the grant was taken."""

    reason: ReasonCode | None
    detail: str | None = None
    # Digest frozen on the consumed grant, so the gate can re-observe at entry.
    frozen_state_digest: str | None = None


class ApprovalStore:
    """In-process single-use TTL approval table.

    Minting is an operator/runtime API. Envelope ``approval_id`` is only a
    reference; the PEP looks up this store. Prose cannot insert a row.
    Each grant freezes one invoke binding (tool_name + canonical args).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, ApprovalRecord] = {}
        # Set on the thread that is running a state observer inside consume().
        # The lock is not reentrant; a callback into the store would wedge, so
        # it is refused with a receipt instead.
        self._observing = threading.local()

    def _refuse_reentry(self) -> None:
        if getattr(self._observing, "active", False):
            raise ObserverReentry("state observer re-entered the approval store")

    def issue(
        self,
        *,
        tools: tuple[str, ...] | list[str],
        ttl_seconds: int,
        args: Mapping[str, Any],
        approval_id: str | None = None,
        now: datetime | None = None,
        catalog: Mapping[str, object] | None = None,
        state_digest: str | None = None,
    ) -> ApprovalRecord:
        clock = _aware(now)
        frozen_state = normalize_state_digest(state_digest)
        if state_digest is not None and frozen_state is None:
            raise ApprovalError("state_digest must be sha256: plus 64 hex characters")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ApprovalError("ttl_seconds must be a positive integer")
        if ttl_seconds < MIN_TTL_SECONDS or ttl_seconds > MAX_TTL_SECONDS:
            raise ApprovalError(
                f"ttl_seconds must be in [{MIN_TTL_SECONDS}, {MAX_TTL_SECONDS}]"
            )
        tool_tuple = tuple(tools)
        if not tool_tuple or any(not isinstance(t, str) or not t for t in tool_tuple):
            raise ApprovalError("approval must cover at least one tool id")
        if len(tool_tuple) != 1:
            raise ApprovalError("approval binds exactly one tool invoke")
        if catalog is not None:
            unknown = [t for t in tool_tuple if t not in catalog]
            if unknown:
                raise ApprovalError(
                    f"cannot mint approval for tools outside catalog: {unknown}"
                )
        binding = invoke_binding(tool_tuple[0], args)
        token = approval_id or f"lab.appr.{uuid.uuid4().hex}"
        if not isinstance(token, str) or not APPROVAL_ID_RE.fullmatch(token):
            raise ApprovalError("approval_id is missing or malformed")
        record = ApprovalRecord(
            approval_id=token,
            tools=tool_tuple,
            expires_at=clock + timedelta(seconds=ttl_seconds),
            binding_digest=sha256_prefixed(binding),
            frozen_args=MappingProxyType(binding["args"]),
            single_use=True,
            consumed_at=None,
            state_digest=frozen_state,
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
        *,
        args: Mapping[str, Any],
        state_digest: str | None = None,
        observe: Callable[[], object] | None = None,
    ) -> ReasonCode | None:
        """Atomically consume a valid grant. ``None`` means the grant was taken."""
        return self.consume(
            approval_id, tool_name, now, args=args, state_digest=state_digest, observe=observe
        ).reason

    def consume(
        self,
        approval_id: str,
        tool_name: str,
        now: datetime | None = None,
        *,
        args: Mapping[str, Any],
        state_digest: str | None = None,
        observe: Callable[[], object] | None = None,
    ) -> ConsumeResult:
        """Atomically consume a valid grant, with the state observation inside.

        Any non-None reason is a fail-closed deny. Single-use is enforced under
        the lock so two concurrent allows cannot share one grant. A tool or args
        mismatch against the frozen binding does not consume.

        When the grant froze a state digest, the observation is taken here:
        ``observe`` (the host's read of the target) runs only after the grant
        has passed existence, single-use, expiry and binding checks, and its
        return replaces ``state_digest``. A raising or non-digest observer, or
        a missing or different digest, is ``APPROVAL_STATE_MISMATCH`` and does
        not consume. Grants without a frozen digest never call ``observe``.
        """
        clock = _aware(now)
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                return ConsumeResult(ReasonCode.APPROVAL_INVALID)
            if record.consumed():
                return ConsumeResult(ReasonCode.APPROVAL_CONSUMED)
            if record.expired(clock):
                return ConsumeResult(ReasonCode.APPROVAL_EXPIRED)
            if not record.matches_binding(tool_name, args):
                return ConsumeResult(ReasonCode.APPROVAL_BINDING_MISMATCH)
            if record.state_digest is not None:
                observed: object = state_digest
                source = "envelope state digest"
                if observe is not None:
                    source = "state observer"
                    try:
                        observed = observe()
                    except Exception:
                        return ConsumeResult(ReasonCode.APPROVAL_STATE_MISMATCH, "state observer failed")
                if not record.matches_state(observed):
                    return ConsumeResult(ReasonCode.APPROVAL_STATE_MISMATCH, f"{source} mismatch")
            if not record.single_use:
                return ConsumeResult(ReasonCode.APPROVAL_INVALID)
            self._records[approval_id] = replace(record, consumed_at=clock)
            return ConsumeResult(None, frozen_state_digest=record.state_digest)


def state_matches(frozen: str | None, observed: Any) -> bool:
    """True when no digest was frozen, or the observation normalises to it."""
    return frozen is None or normalize_state_digest(observed) == frozen


def normalize_state_digest(value: Any) -> str | None:
    """Lower-cased ``sha256:<64 hex>`` or None when absent or malformed."""
    if not isinstance(value, str):
        return None
    candidate = value.lower()
    return candidate if STATE_DIGEST_RE.fullmatch(candidate) else None


def _aware(now: datetime | None) -> datetime:
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ApprovalError("clock must be timezone-aware")
    return clock.astimezone(timezone.utc)
