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

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal, Mapping

from pep.approval import ApprovalRecord, ApprovalStore
from pep.canonical import sha256_prefixed
from pep.envelope import EnvelopeError, InvokeEnvelope, parse_envelope
from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError
from pep.policy import DEMO_POLICY, POLICY_VERSION, PolicyStore, args_match_schema, parse_expiry
from pep.reasons import ReasonCode
from pep.receipt import Receipt, issue_receipt


class RuntimeMode(StrEnum):
    """Process-local PEP mode. Kill is irreversible; suspend may resume."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    KILLED = "killed"


@dataclass(frozen=True, slots=True)
class Decision:
    receipt: Receipt

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
        self._policy = policy if policy is not None else DEMO_POLICY
        self._halt_store = halt_store
        self._approvals = approvals if approvals is not None else ApprovalStore()
        persisted = halt_store.read() if halt_store is not None else HaltState(HaltMode.ACTIVE)
        self.available = bool(available) and persisted.available
        if kill_active or persisted.mode is HaltMode.KILLED:
            self._mode = RuntimeMode.KILLED
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
        return self._mode

    @property
    def kill_active(self) -> bool:
        return self._mode is RuntimeMode.KILLED

    @kill_active.setter
    def kill_active(self, value: bool) -> None:
        if value:
            self.kill()

    @property
    def suspend_active(self) -> bool:
        return self._mode is RuntimeMode.SUSPENDED

    def kill(self) -> None:
        """Irreversible halt. ``resume`` cannot clear a kill."""
        self._mode = RuntimeMode.KILLED
        self._persist_halt()

    def activate_kill(self) -> None:
        self.kill()

    def suspend(self) -> None:
        """Reversible halt. No-op when already killed (kill wins)."""
        if self._mode is RuntimeMode.KILLED:
            return
        self._mode = RuntimeMode.SUSPENDED
        self._persist_halt()

    def resume(self) -> None:
        """Clear suspend only. A killed PEP stays killed."""
        if self._mode is RuntimeMode.SUSPENDED:
            self._mode = RuntimeMode.ACTIVE
            self._persist_halt()

    def mark_unavailable(self) -> None:
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

    def issue_approval(
        self,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        ttl_seconds: int,
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Mint a single-use TTL approval bound to one allowlisted invoke."""
        return self._approvals.issue(
            tools=(tool_name,),
            args=args,
            ttl_seconds=ttl_seconds,
            approval_id=approval_id,
            now=now,
            catalog=self._policy.allowed_tools(),
        )

    def evaluate(self, envelope: Any, *, now: datetime | None = None) -> Decision:
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

        if (not self.available) or self._mode is RuntimeMode.KILLED:
            return _deny(
                ReasonCode.KILL_ACTIVE,
                "PEP kill active or PEP unavailable; fail-closed deny, no invoke",
                env_hash,
                version,
                unchanged,
            )
        if self._mode is RuntimeMode.SUSPENDED:
            return _deny(
                ReasonCode.SUSPEND_ACTIVE,
                "PEP suspend active; fail-closed deny, no invoke",
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

        if approval is not None:
            consume_reason = self._approvals.try_consume(
                approval, parsed.tool_name, now=clock, args=parsed.args
            )
            if consume_reason is not None:
                return _deny(
                    consume_reason,
                    f"single-use TTL approval rejected: {consume_reason}",
                    env_hash,
                    version,
                    policy.bytes_unchanged(),
                )

        receipt = issue_receipt(
            decision="ALLOW",
            reason_code=ReasonCode.ALLOWED,
            reason_detail="structured envelope matched static allowlist",
            envelope_hash=env_hash,
            policy_version=version,
            policy_file_unchanged=policy.bytes_unchanged(),
        )
        return Decision(receipt)


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


def evaluate(
    envelope: Any,
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
) -> Decision:
    """Evaluate a structured envelope. Always returns a Decision; never invokes."""
    pep = runtime if runtime is not None else _DEFAULT_RUNTIME
    return pep.evaluate(envelope, now=now)


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
