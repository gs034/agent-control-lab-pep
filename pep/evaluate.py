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
from typing import Any, Literal

from pep.envelope import EnvelopeError, InvokeEnvelope, parse_envelope
from pep.policy import DEMO_POLICY, PolicyStore, args_match_schema, parse_expiry
from pep.reasons import ReasonCode
from pep.receipt import Receipt, issue_receipt


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Literal["ALLOW", "DENY"]
    receipt: Receipt

    def allowed(self) -> bool:
        return self.verdict == "ALLOW"

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "receipt": self.receipt.to_dict()}


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
        digest = policy.digest
        unchanged = policy.bytes_unchanged()

        if (not self.available) or self.kill_active:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.KILL_ACTIVE,),
                detail="PEP kill active or PEP unavailable; fail-closed deny, no invoke",
                policy_digest=digest,
                policy_bytes_unchanged=unchanged,
                envelope_digest=_try_envelope_digest(envelope),
            )
            return Decision("DENY", receipt)

        try:
            parsed = parse_envelope(envelope)
        except EnvelopeError as exc:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(exc.reason,),
                detail=exc.detail,
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=_try_envelope_digest(envelope),
            )
            return Decision("DENY", receipt)
        except (TypeError, ValueError) as exc:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.ENVELOPE_INVALID,),
                detail=f"parse failure: {exc}",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=None,
            )
            return Decision("DENY", receipt)

        if parsed.has_untrusted_prose():
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.AGENT_PROSE_REJECTED,),
                detail="untrusted agent prose rejected; not consulted as policy",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        if not policy.raw_bytes or not policy.document:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail="no policy loaded; fail-closed deny",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        allowed_tools = policy.allowed_tools()
        if parsed.tool_name not in allowed_tools:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.UNKNOWN_TOOL,),
                detail=f"tool not in policy catalog: {parsed.tool_name}",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        spec = allowed_tools[parsed.tool_name]
        if not isinstance(spec, dict) and not hasattr(spec, "get"):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail="tool spec unreadable; fail-closed deny",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        callers = policy.allowed_callers()
        if callers and parsed.caller_identity not in callers:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail=f"caller not in policy allowlist: {parsed.caller_identity}",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        required_cap = spec.get("required_capability")
        token = parsed.capability_token
        if not token:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability token missing",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        cap = policy.capability(token)
        if cap is None:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability token unknown",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        expires_at = cap.get("expires_at")
        if not isinstance(expires_at, str):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability record missing expires_at; fail-closed",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)
        try:
            expiry = parse_expiry(expires_at)
        except (TypeError, ValueError):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability expiry unparseable; fail-closed",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)
        if expiry <= datetime.now(timezone.utc):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability token expired",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        cap_tools = cap.get("tools", [])
        if parsed.tool_name not in cap_tools:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.CAPABILITY_MISSING,),
                detail="capability token does not cover tool",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        if required_cap and token != required_cap:
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail="capability token does not match tool policy",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        schema = spec.get("args_schema")
        if not isinstance(schema, dict) and not hasattr(schema, "get"):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail="args schema missing; fail-closed",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)
        if not args_match_schema(parsed.args, schema):
            receipt = issue_receipt(
                verdict="DENY",
                reason_codes=(ReasonCode.POLICY_MISS,),
                detail="args failed policy schema",
                policy_digest=digest,
                policy_bytes_unchanged=policy.bytes_unchanged(),
                envelope_digest=parsed.digest(),
            )
            return Decision("DENY", receipt)

        receipt = issue_receipt(
            verdict="ALLOW",
            reason_codes=(ReasonCode.ALLOWED,),
            detail="structured envelope matched static allowlist",
            policy_digest=digest,
            policy_bytes_unchanged=policy.bytes_unchanged(),
            envelope_digest=parsed.digest(),
        )
        return Decision("ALLOW", receipt)


_DEFAULT_RUNTIME = PepRuntime()


def evaluate(envelope: Any, runtime: PepRuntime | None = None) -> Decision:
    """Evaluate a structured envelope. Always returns a Decision; never invokes."""
    pep = runtime if runtime is not None else _DEFAULT_RUNTIME
    return pep.evaluate(envelope)


def _try_envelope_digest(envelope: Any) -> str | None:
    if isinstance(envelope, InvokeEnvelope):
        return envelope.digest()
    if isinstance(envelope, dict):
        try:
            import hashlib

            from pep.canonical import canonical_bytes

            return hashlib.sha256(canonical_bytes(envelope)).hexdigest()
        except (TypeError, ValueError):
            return None
    return None
