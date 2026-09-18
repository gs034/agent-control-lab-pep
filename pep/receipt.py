# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Attested deny/allow receipts. No model scores, no HITL fields."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from pep.canonical import canonical_bytes
from pep.reasons import ReasonCode

PEP_ID = "agent-control-lab.pep.reference.v0"
TRUST_DOMAIN = "pep"
# Demo HMAC only. A production PEP would keep this key off-box.
DEMO_ATTESTATION_KEY = b"agent-control-lab.pep.demo-attestation-not-for-production"


@dataclass(frozen=True, slots=True)
class Receipt:
    verdict: Literal["ALLOW", "DENY"]
    reason_codes: tuple[str, ...]
    detail: str
    policy_digest: str
    policy_bytes_unchanged: bool
    prose_consulted_as_policy: Literal[False]
    envelope_digest: str | None
    evaluated_at: str
    pep_id: str
    trust_domain: str
    no_model_call: Literal[True]
    attestation_alg: str
    attestation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "detail": self.detail,
            "policy_digest": self.policy_digest,
            "policy_bytes_unchanged": self.policy_bytes_unchanged,
            "prose_consulted_as_policy": False,
            "envelope_digest": self.envelope_digest,
            "evaluated_at": self.evaluated_at,
            "pep_id": self.pep_id,
            "trust_domain": self.trust_domain,
            "no_model_call": True,
            "attestation_alg": self.attestation_alg,
            "attestation": self.attestation,
        }


def issue_receipt(
    *,
    verdict: Literal["ALLOW", "DENY"],
    reason_codes: Sequence[ReasonCode | str],
    detail: str,
    policy_digest: str,
    policy_bytes_unchanged: bool,
    envelope_digest: str | None,
    attestation_key: bytes = DEMO_ATTESTATION_KEY,
    now: datetime | None = None,
) -> Receipt:
    evaluated_at = (now or datetime.now(timezone.utc)).isoformat()
    codes = tuple(str(c) for c in reason_codes)
    body: dict[str, Any] = {
        "verdict": verdict,
        "reason_codes": list(codes),
        "detail": detail,
        "policy_digest": policy_digest,
        "policy_bytes_unchanged": policy_bytes_unchanged,
        "prose_consulted_as_policy": False,
        "envelope_digest": envelope_digest,
        "evaluated_at": evaluated_at,
        "pep_id": PEP_ID,
        "trust_domain": TRUST_DOMAIN,
        "no_model_call": True,
    }
    mac = hmac.new(attestation_key, canonical_bytes(body), hashlib.sha256).hexdigest()
    return Receipt(
        verdict=verdict,
        reason_codes=codes,
        detail=detail,
        policy_digest=policy_digest,
        policy_bytes_unchanged=policy_bytes_unchanged,
        prose_consulted_as_policy=False,
        envelope_digest=envelope_digest,
        evaluated_at=evaluated_at,
        pep_id=PEP_ID,
        trust_domain=TRUST_DOMAIN,
        no_model_call=True,
        attestation_alg="HMAC-SHA256",
        attestation=mac,
    )


def verify_receipt(receipt: Receipt, attestation_key: bytes = DEMO_ATTESTATION_KEY) -> bool:
    body = {k: v for k, v in receipt.to_dict().items() if k not in {"attestation", "attestation_alg"}}
    expected = hmac.new(attestation_key, canonical_bytes(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, receipt.attestation)


def receipt_from_mapping(data: Mapping[str, Any]) -> Receipt:
    return Receipt(
        verdict=data["verdict"],  # type: ignore[arg-type]
        reason_codes=tuple(data["reason_codes"]),
        detail=str(data["detail"]),
        policy_digest=str(data["policy_digest"]),
        policy_bytes_unchanged=bool(data["policy_bytes_unchanged"]),
        prose_consulted_as_policy=False,
        envelope_digest=data.get("envelope_digest"),
        evaluated_at=str(data["evaluated_at"]),
        pep_id=str(data["pep_id"]),
        trust_domain=str(data["trust_domain"]),
        no_model_call=True,
        attestation_alg=str(data["attestation_alg"]),
        attestation=str(data["attestation"]),
    )
