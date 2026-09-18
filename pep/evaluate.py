# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Host/runtime PEP evaluate path.

Trust domain
------------
This module *is* the Policy Enforcement Point. Agents, optional monitors,
and any HITL UI are callers on the other side of ``evaluate()``. In-process
import is allowed; the function boundary is the trust boundary. There is
no LLM, CoT, or transcript judge on this path — policy is a frozen
allowlist plus capability tokens.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from pep.canonical import sha256_prefixed
from pep.envelope import EnvelopeError, InvokeEnvelope, parse_envelope
from pep.policy import DEMO_POLICY, POLICY_VERSION, PolicyStore, args_match_schema, parse_expiry
from pep.reasons import ReasonCode
from pep.receipt import Receipt, issue_receipt


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
    """Process-local PEP. Kill / unavailability fail closed to DENY."""

    def __init__(
        self,
        policy: PolicyStore | None = None,
        *,
        kill_active: bool = False,
        available: bool = True,
    ) -> None:
        self._policy = policy if policy is not None else DEMO_POLICY
        self.kill_active = kill_active
        self.available = available

    @property
    def policy(self) -> PolicyStore:
        return self._policy

    def activate_kill(self) -> None:
        self.kill_active = True

    def mark_unavailable(self) -> None:
        self.available = False

    def evaluate(self, envelope: Any) -> Decision:
        policy = self._policy
        unchanged = policy.bytes_unchanged()
        env_hash = _envelope_hash(envelope)
        version = policy.version if policy.document else POLICY_VERSION

        if (not self.available) or self.kill_active:
            return _deny(
                ReasonCode.KILL_ACTIVE,
                "PEP kill active or PEP unavailable; fail-closed deny, no invoke",
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
        if not token:
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability token missing",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        cap = policy.capability(token)
        if cap is None:
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability token unknown",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        expires_at = cap.get("expires_at")
        if not isinstance(expires_at, str):
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability record missing expires_at; fail-closed",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )
        try:
            expiry = parse_expiry(expires_at)
        except (TypeError, ValueError):
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability expiry unparseable; fail-closed",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )
        if expiry <= datetime.now(timezone.utc):
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability token expired",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        cap_tools = cap.get("tools", [])
        if parsed.tool_name not in cap_tools:
            return _deny(
                ReasonCode.CAPABILITY_MISSING,
                "capability token does not cover tool",
                env_hash,
                version,
                policy.bytes_unchanged(),
            )

        if required_cap and token != required_cap:
            return _deny(
                ReasonCode.POLICY_MISS,
                "capability token does not match tool policy",
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

        receipt = issue_receipt(
            decision="ALLOW",
            reason_code=ReasonCode.ALLOWED,
            reason_detail="structured envelope matched static allowlist",
            envelope_hash=env_hash,
            policy_version=version,
            policy_file_unchanged=policy.bytes_unchanged(),
        )
        return Decision(receipt)


_DEFAULT_RUNTIME = PepRuntime()


def evaluate(envelope: Any, runtime: PepRuntime | None = None) -> Decision:
    """Evaluate a structured envelope. Always returns a Decision; never invokes."""
    pep = runtime if runtime is not None else _DEFAULT_RUNTIME
    return pep.evaluate(envelope)


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
