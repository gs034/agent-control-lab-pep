# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Host/runtime PEP evaluate path.

Trust domain
------------
This module *is* the Policy Enforcement Point. Agents, optional monitors,
and any HITL UI are callers on the other side of ``evaluate()``. In-process
import is allowed; the function boundary is the trust boundary. There is
no LLM, CoT, or transcript judge on this path — policy is a frozen
allowlist plus capability tokens and single-use TTL approvals bound
to a frozen invoke (tool_name + canonical args).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal, Mapping

from pep.approval import ApprovalRecord, ApprovalStore
from pep.canonical import sha256_prefixed
from pep.envelope import EnvelopeError, InvokeEnvelope, parse_envelope
from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError
from pep.policy import DEMO_POLICY, POLICY_VERSION, PolicyStore, args_match_schema, parse_expiry
from pep.reasons import ADMISSION_CONSUMED_DETAIL, LATE_EFFECT_FENCE_DETAIL, ReasonCode
from pep.receipt import Receipt, issue_receipt


class RuntimeMode(StrEnum):
    """Process-local PEP mode. Kill is irreversible; suspend may resume."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    KILLED = "killed"


@dataclass(frozen=True, slots=True)
class Decision:
    receipt: Receipt
    # Not part of the frozen receipt. Set on an ALLOW that consumed a grant
    # with a frozen state digest, so the gate can re-observe at tool entry.
    frozen_state_digest: str | None = None

    @property
    def verdict(self) -> Literal["ALLOW", "DENY"]:
        return self.receipt.decision

    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return self.receipt.to_dict()


class PepRuntime:
    """Host/runtime PEP. Kill, suspend, and unavailability fail closed to DENY.

    ``halt_store`` is an optional JSON file so kill / suspend / unavailable
    survive process restart. Process-local mode remains the default.

    ``kill()`` also engages an in-process late-effect fence: a monotonic cut
    epoch. Admissions taken before the cut must not enter a tool after it.
    The epoch is process-local. It is not a field in ``HaltStore``.
    """

    def __init__(
        self,
        policy: PolicyStore | None = None,
        *,
        kill_active: bool = False,
        available: bool = True,
        approvals: ApprovalStore | None = None,
        halt_store: HaltStore | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._fence_epoch = 0
        self._fence_engaged = False
        self._next_admission_id = 0
        self._spent_admissions: set[int] = set()
        self._policy = policy if policy is not None else DEMO_POLICY
        self._halt_store = halt_store
        self._approvals = approvals if approvals is not None else ApprovalStore()
        persisted = halt_store.read() if halt_store is not None else HaltState(HaltMode.ACTIVE)
        self.available = bool(available) and persisted.available
        if kill_active or persisted.mode is HaltMode.KILLED:
            self._mode = RuntimeMode.KILLED
            self._engage_fence_unlocked()
        elif persisted.mode is HaltMode.SUSPENDED:
            self._mode = RuntimeMode.SUSPENDED
        else:
            self._mode = RuntimeMode.ACTIVE
        self._persist_halt()

    @property
    def policy(self) -> PolicyStore:
        return self._policy

    @property
    def approvals(self) -> ApprovalStore:
        return self._approvals

    @property
    def halt_store(self) -> HaltStore | None:
        return self._halt_store

    @property
    def mode(self) -> RuntimeMode:
        with self._lock:
            return self._mode

    @property
    def fence_epoch(self) -> int:
        """Cut generation. ``kill()`` bumps this once when the fence engages."""
        with self._lock:
            return self._fence_epoch

    @property
    def fence_engaged(self) -> bool:
        """True after a kill cut. Resume cannot clear it."""
        with self._lock:
            return self._fence_engaged

    @property
    def kill_active(self) -> bool:
        with self._lock:
            return self._mode is RuntimeMode.KILLED

    @kill_active.setter
    def kill_active(self, value: bool) -> None:
        if value:
            self.kill()

    @property
    def suspend_active(self) -> bool:
        with self._lock:
            return self._mode is RuntimeMode.SUSPENDED

    def kill(self) -> None:
        """Irreversible halt plus in-process late-effect fence.

        New evaluates deny as ``kill_active``. An admission that completes
        after this cut denies as ``late_effect_fence`` and does not enter
        the tool. ``resume`` cannot clear either.
        """
        with self._lock:
            self._engage_fence_unlocked()
            self._mode = RuntimeMode.KILLED
            self._persist_halt()

    def _engage_fence_unlocked(self) -> None:
        if self._fence_engaged:
            return
        self._fence_engaged = True
        self._fence_epoch += 1

    def _observe(self) -> tuple[RuntimeMode, bool, int]:
        with self._lock:
            return self._mode, self.available, self._fence_epoch

    def mint_admission_id(self) -> int:
        """One-shot id for an in-process admission. Not an allow."""
        with self._lock:
            self._next_admission_id += 1
            return self._next_admission_id

    def _entry_block_unlocked(self, admitted_epoch: int) -> ReasonCode | None:
        if self._fence_engaged and admitted_epoch != self._fence_epoch:
            return ReasonCode.LATE_EFFECT_FENCE
        if (not self.available) or self._mode is RuntimeMode.KILLED:
            return ReasonCode.KILL_ACTIVE
        if self._mode is RuntimeMode.SUSPENDED:
            return ReasonCode.SUSPEND_ACTIVE
        return None

    def completion_block(self, admitted_epoch: int) -> ReasonCode | None:
        """Non-binding observation. Tool entry uses ``claim_entry`` instead.

        A stale epoch after the kill cut is ``late_effect_fence`` (cut+fence),
        not merely ``kill_active``. This read releases the lock; it is not a
        permit to call a tool.
        """
        with self._lock:
            return self._entry_block_unlocked(admitted_epoch)

    def _claim_entry_unlocked(self, admission_id: int, admitted_epoch: int) -> ReasonCode | None:
        """Spend the ticket or refuse. Caller holds ``self._lock``."""
        if admission_id in self._spent_admissions:
            return ReasonCode.ADMISSION_CONSUMED
        blocked = self._entry_block_unlocked(admitted_epoch)
        if blocked is not None:
            # Suspend is reversible, so the ticket stays open across resume.
            # Kill, unavailability, and a stale cut epoch spend it.
            if blocked is not ReasonCode.SUSPEND_ACTIVE:
                self._spent_admissions.add(admission_id)
            return blocked
        self._spent_admissions.add(admission_id)
        return None

    def claim_entry(
        self,
        admission_id: int,
        admitted_epoch: int,
        *,
        _before_commit: Callable[[], None] | None = None,
    ) -> ReasonCode | None:
        """Issue a one-shot entry permit, or a fail-closed deny reason.

        Under the runtime lock this either records the admission as entered
        or refuses it. ``None`` means the permit was stored before the lock
        was released; the caller may then invoke the tool. ``kill()`` takes
        the same lock and will not issue a new permit after the cut.

        ``_before_commit``, when passed, runs only after an observation that
        the fence was open, and only with the lock released. The permit is
        decided again under the lock after it returns. Production callers
        omit it. Once the caller has entered ``tool()``, kill does not
        preempt that call.
        """
        if _before_commit is None:
            with self._lock:
                return self._claim_entry_unlocked(admission_id, admitted_epoch)
        with self._lock:
            if (
                admission_id in self._spent_admissions
                or self._entry_block_unlocked(admitted_epoch) is not None
            ):
                return self._claim_entry_unlocked(admission_id, admitted_epoch)
        _before_commit()
        with self._lock:
            return self._claim_entry_unlocked(admission_id, admitted_epoch)

    def activate_kill(self) -> None:
        self.kill()

    def suspend(self) -> None:
        """Reversible halt. No-op when already killed (kill wins)."""
        with self._lock:
            if self._mode is RuntimeMode.KILLED:
                return
            self._mode = RuntimeMode.SUSPENDED
            self._persist_halt()

    def resume(self) -> None:
        """Clear suspend only. A killed PEP stays killed."""
        with self._lock:
            if self._mode is RuntimeMode.SUSPENDED:
                self._mode = RuntimeMode.ACTIVE
                self._persist_halt()

    def mark_unavailable(self) -> None:
        with self._lock:
            self.available = False
            self._persist_halt()

    def _persist_halt(self) -> None:
        store = self._halt_store
        if store is None:
            return
        requested = HaltState(
            mode=_mode_to_halt(self._mode),
            available=self.available,
        )
        try:
            written = store.write(requested)
        except HaltStoreError:
            # Persist failed. Stay fail-closed in this process (already killed
            # or suspended in memory). Next process may miss the write.
            return
        self._mode = _halt_to_mode(written.mode)
        self.available = written.available
        if self._mode is RuntimeMode.KILLED:
            # Sticky kill learned from the store is the same cut: fence
            # admissions already taken in this process.
            self._engage_fence_unlocked()

    def issue_approval(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        ttl_seconds: int,
        approval_id: str | None = None,
        now: datetime | None = None,
        state_digest: str | None = None,
    ) -> ApprovalRecord:
        """Mint a single-use TTL approval bound to one allowlisted invoke.

        ``state_digest`` optionally freezes a host-computed digest of the state
        the invoke acts on; consume then requires the host-observed digest to
        match.
        """
        return self._approvals.issue(
            tools=(tool_name,),
            args=args,
            ttl_seconds=ttl_seconds,
            approval_id=approval_id,
            now=now,
            catalog=self._policy.allowed_tools(),
            state_digest=state_digest,
        )

    def evaluate(
        self,
        envelope: Any,
        *,
        now: datetime | None = None,
        state_observer: Callable[[], object] | None = None,
        _before_allow: Callable[[], None] | None = None,
    ) -> Decision:
        """Evaluate one structured envelope.

        ``state_observer`` is the host's read of the current digest of the
        state the invoke acts on. When the referenced approval froze a state
        digest, ``ApprovalStore.consume`` calls it under the store lock after
        the grant has passed its other checks, and its return is the
        observation; the envelope's ``state_digest`` is used only when no
        observer is given. A raising or non-digest observer is a mismatch.
        """
        try:
            clock = _aware_clock(now)
        except (TypeError, ValueError):
            policy = self._policy
            return _deny(
                ReasonCode.ENVELOPE_INVALID,
                "evaluate clock must be timezone-aware; fail-closed deny",
                _envelope_hash(envelope),
                policy.version if policy.document else POLICY_VERSION,
                policy.bytes_unchanged(),
            )
        policy = self._policy
        unchanged = policy.bytes_unchanged()
        env_hash = _envelope_hash(envelope)
        version = policy.version if policy.document else POLICY_VERSION

        observed_mode, observed_available, admitted_epoch = self._observe()
        if (not observed_available) or observed_mode is RuntimeMode.KILLED:
            return _deny(
                ReasonCode.KILL_ACTIVE,
                _KILL_DETAIL,
                env_hash,
                version,
                unchanged,
            )
        if observed_mode is RuntimeMode.SUSPENDED:
            return _deny(
                ReasonCode.SUSPEND_ACTIVE,
                _SUSPEND_DETAIL,
                env_hash,
                version,
                unchanged,
            )

        try:
            parsed = parse_envelope(envelope)
        except EnvelopeError as exc:
            return _deny(exc.reason, exc.detail, env_hash, version, policy.bytes_unchanged())
        except (TypeError, ValueError) as exc:
            return _deny(
                ReasonCode.ENVELOPE_INVALID,
                f"parse failure: {exc}",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        env_hash = parsed.digest()

        if parsed.has_untrusted_prose():
            return _deny(
                ReasonCode.AGENT_PROSE_REJECTED,
                "untrusted agent prose rejected; not consulted as policy",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        if not policy.raw_bytes or not policy.document:
            return _deny(
                ReasonCode.POLICY_MISS,
                "no policy loaded; fail-closed deny",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        allowed_tools = policy.allowed_tools()
        token = parsed.capability_token
        approval = parsed.approval_id

        if parsed.tool_name not in allowed_tools:
            if token is None and approval is None:
                return _deny(
                    ReasonCode.TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY,
                    (
                        f"Host/runtime PEP denied invoke: tool_name {parsed.tool_name} "
                        "is outside allowlist; capability_token and approval_id absent. "
                        "Agent free-text was ignored as policy input."
                    ),
                    env_hash,
                    version,
                    policy.bytes_unchanged(),
                )
            return _deny(
                ReasonCode.UNKNOWN_TOOL,
                f"tool not in policy catalog: {parsed.tool_name}",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        spec = allowed_tools[parsed.tool_name]
        if not hasattr(spec, "get"):
            return _deny(
                ReasonCode.POLICY_MISS,
                "tool spec unreadable; fail-closed deny",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        required_cap = spec.get("required_capability")
        if token:
            denied = _capability_deny(policy, parsed, token, required_cap, clock)
            if denied is not None:
                reason, detail = denied
                return _deny(reason, detail, env_hash, version, policy.bytes_unchanged())
        elif approval is None:
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability token missing",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        schema = spec.get("args_schema")
        if not hasattr(schema, "get"):
            return _deny(
                ReasonCode.POLICY_MISS,
                "args schema missing; fail-closed",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )
        if not args_match_schema(parsed.args, schema):
            return _deny(
                ReasonCode.POLICY_MISS,
                "args failed policy schema",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        frozen_state: str | None = None
        if approval is not None:
            consumed = self._approvals.consume(
                approval,
                parsed.tool_name,
                now=clock,
                args=parsed.args,
                state_digest=parsed.state_digest,
                observe=state_observer,
            )
            frozen_state = consumed.frozen_state_digest
            if consumed.reason is not None:
                detail = f"single-use TTL approval rejected: {consumed.reason}"
                if consumed.detail:
                    detail = f"{detail}; {consumed.detail}"
                return _deny(
                    consumed.reason,
                    detail,
                    env_hash,
                    version,
                    policy.bytes_unchanged(),
                )

        return self._finalize_allow(
            admitted_epoch,
            envelope_hash=env_hash,
            policy_version=version,
            policy_file_unchanged=policy.bytes_unchanged(),
            frozen_state_digest=frozen_state,
            _before_allow=_before_allow,
        )

    def _finalize_allow(
        self,
        admitted_epoch: int,
        *,
        envelope_hash: str,
        policy_version: str,
        policy_file_unchanged: bool,
        frozen_state_digest: str | None = None,
        _before_allow: Callable[[], None] | None = None,
    ) -> Decision:
        """Publish ALLOW only if the cut is still open, under the runtime lock.

        The fence re-check and the ALLOW ``Decision`` are one critical section.
        ``kill()`` cannot land between them. ``_before_allow`` yields only after
        an observation that the cut was open, with the lock released; the
        decision is taken again under the lock after it returns. An ALLOW
        object is not a tool-entry permit; ``claim_entry`` still gates that.
        """
        if _before_allow is not None:
            with self._lock:
                still_open = self._entry_block_unlocked(admitted_epoch) is None
            if still_open:
                _before_allow()
        with self._lock:
            blocked = self._entry_block_unlocked(admitted_epoch)
            if blocked is not None:
                return _deny(
                    blocked,
                    _reason_detail(blocked),
                    envelope_hash,
                    policy_version,
                    policy_file_unchanged,
                )
            return Decision(
                issue_receipt(
                    decision="ALLOW",
                    reason_code=ReasonCode.ALLOWED,
                    reason_detail="structured envelope matched static allowlist",
                    envelope_hash=envelope_hash,
                    policy_version=policy_version,
                    policy_file_unchanged=policy_file_unchanged,
                ),
                frozen_state_digest=frozen_state_digest,
            )


def _capability_deny(
    policy: PolicyStore,
    parsed: InvokeEnvelope,
    token: str,
    required_cap: Any,
    clock: datetime,
) -> tuple[ReasonCode, str] | None:
    cap = policy.capability(token)
    if cap is None:
        return ReasonCode.CAPABILITY_MISSING, "capability token unknown"
    expires_at = cap.get("expires_at")
    if not isinstance(expires_at, str):
        return ReasonCode.CAPABILITY_MISSING, "capability record missing expires_at; fail-closed"
    try:
        expiry = parse_expiry(expires_at)
    except (TypeError, ValueError):
        return ReasonCode.CAPABILITY_MISSING, "capability expiry unparseable; fail-closed"
    if expiry <= clock:
        return ReasonCode.CAPABILITY_MISSING, "capability token expired"
    cap_tools = cap.get("tools", [])
    if parsed.tool_name not in cap_tools:
        return ReasonCode.CAPABILITY_MISSING, "capability token does not cover tool"
    if required_cap and token != required_cap:
        return ReasonCode.POLICY_MISS, "capability token does not match tool policy"
    return None


def _mode_to_halt(mode: RuntimeMode) -> HaltMode:
    if mode is RuntimeMode.KILLED:
        return HaltMode.KILLED
    if mode is RuntimeMode.SUSPENDED:
        return HaltMode.SUSPENDED
    return HaltMode.ACTIVE


def _halt_to_mode(mode: HaltMode) -> RuntimeMode:
    if mode is HaltMode.KILLED:
        return RuntimeMode.KILLED
    if mode is HaltMode.SUSPENDED:
        return RuntimeMode.SUSPENDED
    return RuntimeMode.ACTIVE


_DEFAULT_RUNTIME = PepRuntime()


def resolve_runtime(runtime: PepRuntime | None) -> PepRuntime:
    """Return ``runtime`` or the process-default PEP. One object, so kill fences it."""
    return runtime if runtime is not None else _DEFAULT_RUNTIME


def evaluate(
    envelope: Any,
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
    state_observer: Callable[[], object] | None = None,
    _before_allow: Callable[[], None] | None = None,
) -> Decision:
    """Evaluate a structured envelope. Always returns a Decision; never invokes."""
    pep = resolve_runtime(runtime)
    return pep.evaluate(
        envelope, now=now, state_observer=state_observer, _before_allow=_before_allow
    )


def supersede(decision: Decision, reason: ReasonCode) -> Decision:
    """Fail-closed replacement for an admission. Same frozen receipt schema."""
    receipt = decision.receipt
    return _deny(
        reason,
        _reason_detail(reason),
        receipt.envelope_hash,
        receipt.policy_version,
        receipt.policy_file_unchanged,
    )


_KILL_DETAIL = "PEP kill active or PEP unavailable; fail-closed deny, no invoke"
_STATE_REOBSERVE_DETAIL = (
    "state re-observed at tool entry differs from the approved digest; "
    "fail-closed deny, no tool entry (grant already spent)"
)
_SUSPEND_DETAIL = "PEP suspend active; fail-closed deny, no invoke"


def _reason_detail(reason: ReasonCode) -> str:
    if reason is ReasonCode.APPROVAL_STATE_MISMATCH:
        return _STATE_REOBSERVE_DETAIL
    if reason is ReasonCode.LATE_EFFECT_FENCE:
        return LATE_EFFECT_FENCE_DETAIL
    if reason is ReasonCode.ADMISSION_CONSUMED:
        return ADMISSION_CONSUMED_DETAIL
    if reason is ReasonCode.SUSPEND_ACTIVE:
        return _SUSPEND_DETAIL
    return _KILL_DETAIL


def _deny(
    reason: ReasonCode,
    detail: str,
    envelope_hash: str,
    policy_version: str,
    unchanged: bool,
) -> Decision:
    return Decision(
        issue_receipt(
            decision="DENY",
            reason_code=reason,
            reason_detail=detail,
            envelope_hash=envelope_hash,
            policy_version=policy_version,
            policy_file_unchanged=unchanged,
        )
    )


def _envelope_hash(envelope: Any) -> str:
    if isinstance(envelope, InvokeEnvelope):
        return envelope.digest()
    if isinstance(envelope, Mapping):
        try:
            return sha256_prefixed(dict(envelope))
        except (TypeError, ValueError):
            return "sha256:"
    return "sha256:"


def _aware_clock(now: datetime | None) -> datetime:
    clock = now if now is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ValueError("evaluate clock must be timezone-aware")
    return clock.astimezone(timezone.utc)
