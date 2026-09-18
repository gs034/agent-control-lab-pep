# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Deny/allow receipts matching eval/expected_deny_receipt.example.json.

The public receipt object is a frozen schema (v1). Additive fields require a
new schema version and an ADR. ``issue_receipt`` validates before return.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from pep.policy import POLICY_VERSION
from pep.reasons import ReasonCode

PEP_ID = "acl-pep-stub-host-runtime-001"
BRAND = "Agent Control Lab"
LICENCE = "Apache-2.0"
EVAL_REF = "ACL_PEP_Eval_Row_2609_19587_class_2026-09-18"
JUDGE_PATH = "host_runtime_deterministic"

# Frozen public receipt (v1). Do not add or remove keys without a schema bump.
RECEIPT_SCHEMA_VERSION = "1"
FROZEN_RECEIPT_KEYS = frozenset(
    {
        "brand",
        "decision",
        "envelope_hash",
        "eval_ref",
        "fail_closed",
        "judge",
        "licence",
        "negative_controls_observed",
        "pep_id",
        "policy_version",
        "reason_code",
        "reason_detail",
        "receipt_type",
        "timestamp",
        "trust_domain",
    }
)
FROZEN_JUDGE_KEYS = frozenset(
    {
        "agent_prose_used_as_policy",
        "llm_cot_transcript_judge",
        "path",
    }
)
FROZEN_NEGATIVE_KEYS = frozenset(
    {
        "monitor_coax_accepted",
        "policy_file_unchanged",
        "tool_invoke_executed",
    }
)
FROZEN_TRUST_KEYS = frozenset(
    {
        "model_monitor_mcp",
        "pep",
    }
)


class ReceiptSchemaError(ValueError):
    """Public receipt drifted from the frozen v1 schema."""


@dataclass(frozen=True, slots=True)
class Receipt:
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    reason_detail: str
    envelope_hash: str
    timestamp: str
    policy_version: str
    policy_file_unchanged: bool
    tool_invoke_executed: bool = False

    @property
    def pep_id(self) -> str:
        return PEP_ID

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "brand": BRAND,
            "decision": self.decision,
            "envelope_hash": self.envelope_hash,
            "eval_ref": EVAL_REF,
            "fail_closed": True,
            "judge": {
                "agent_prose_used_as_policy": False,
                "llm_cot_transcript_judge": False,
                "path": JUDGE_PATH,
            },
            "licence": LICENCE,
            "negative_controls_observed": {
                "monitor_coax_accepted": False,
                "policy_file_unchanged": self.policy_file_unchanged,
                "tool_invoke_executed": self.tool_invoke_executed,
            },
            "pep_id": PEP_ID,
            "policy_version": self.policy_version,
            "reason_code": self.reason_code,
            "reason_detail": self.reason_detail,
            "receipt_type": "pep_deny" if self.decision == "DENY" else "pep_allow",
            "timestamp": self.timestamp,
            "trust_domain": {
                "model_monitor_mcp": "untrusted_relative_to_pep",
                "pep": "host-runtime-separate",
            },
        }
        validate_receipt(payload)
        return payload


def issue_receipt(
    *,
    decision: Literal["ALLOW", "DENY"],
    reason_code: ReasonCode | str,
    reason_detail: str,
    envelope_hash: str,
    policy_version: str = POLICY_VERSION,
    policy_file_unchanged: bool,
    tool_invoke_executed: bool = False,
    now: datetime | None = None,
) -> Receipt:
    stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt = Receipt(
        decision=decision,
        reason_code=str(reason_code),
        reason_detail=reason_detail,
        envelope_hash=envelope_hash,
        timestamp=timestamp,
        policy_version=policy_version,
        policy_file_unchanged=policy_file_unchanged,
        tool_invoke_executed=tool_invoke_executed,
    )
    validate_receipt(receipt.to_dict())
    return receipt


def validate_receipt(payload: Mapping[str, Any]) -> None:
    """Fail closed if the public receipt is not frozen v1."""
    if not isinstance(payload, Mapping):
        raise ReceiptSchemaError("receipt must be a JSON object")
    keys = frozenset(payload.keys())
    if keys != FROZEN_RECEIPT_KEYS:
        missing = sorted(FROZEN_RECEIPT_KEYS - keys)
        extra = sorted(keys - FROZEN_RECEIPT_KEYS)
        raise ReceiptSchemaError(f"receipt keys drifted (missing={missing} extra={extra})")
    if payload.get("brand") != BRAND:
        raise ReceiptSchemaError("brand must be Agent Control Lab")
    if payload.get("licence") != LICENCE:
        raise ReceiptSchemaError("licence must be Apache-2.0")
    if payload.get("pep_id") != PEP_ID:
        raise ReceiptSchemaError("pep_id drifted")
    if payload.get("fail_closed") is not True:
        raise ReceiptSchemaError("fail_closed must be true")
    decision = payload.get("decision")
    if decision not in ("ALLOW", "DENY"):
        raise ReceiptSchemaError("decision must be ALLOW or DENY")
    receipt_type = payload.get("receipt_type")
    expected_type = "pep_deny" if decision == "DENY" else "pep_allow"
    if receipt_type != expected_type:
        raise ReceiptSchemaError("receipt_type must match decision")
    if not isinstance(payload.get("reason_code"), str) or not payload["reason_code"]:
        raise ReceiptSchemaError("reason_code must be a non-empty string")
    if not isinstance(payload.get("reason_detail"), str) or not payload["reason_detail"]:
        raise ReceiptSchemaError("reason_detail must be a non-empty string")
    if not isinstance(payload.get("policy_version"), str) or not payload["policy_version"]:
        raise ReceiptSchemaError("policy_version must be a non-empty string")
    digest = payload.get("envelope_hash")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ReceiptSchemaError("envelope_hash must be sha256-prefixed")
    stamp = payload.get("timestamp")
    if not isinstance(stamp, str) or len(stamp) < 20 or not stamp.endswith("Z"):
        raise ReceiptSchemaError("timestamp must be UTC Zulu")
    if not isinstance(payload.get("eval_ref"), str) or not payload["eval_ref"]:
        raise ReceiptSchemaError("eval_ref must be a non-empty string")

    judge = payload.get("judge")
    if not isinstance(judge, Mapping) or frozenset(judge.keys()) != FROZEN_JUDGE_KEYS:
        raise ReceiptSchemaError("judge object drifted from frozen v1")
    if judge.get("path") != JUDGE_PATH:
        raise ReceiptSchemaError("judge.path must be host_runtime_deterministic")
    if judge.get("llm_cot_transcript_judge") is not False:
        raise ReceiptSchemaError("llm_cot_transcript_judge must be false")
    if judge.get("agent_prose_used_as_policy") is not False:
        raise ReceiptSchemaError("agent_prose_used_as_policy must be false")

    neg = payload.get("negative_controls_observed")
    if not isinstance(neg, Mapping) or frozenset(neg.keys()) != FROZEN_NEGATIVE_KEYS:
        raise ReceiptSchemaError("negative_controls_observed drifted from frozen v1")
    if neg.get("monitor_coax_accepted") is not False:
        raise ReceiptSchemaError("monitor_coax_accepted must be false")
    if not isinstance(neg.get("policy_file_unchanged"), bool):
        raise ReceiptSchemaError("policy_file_unchanged must be a boolean")
    if not isinstance(neg.get("tool_invoke_executed"), bool):
        raise ReceiptSchemaError("tool_invoke_executed must be a boolean")

    trust = payload.get("trust_domain")
    if not isinstance(trust, Mapping) or frozenset(trust.keys()) != FROZEN_TRUST_KEYS:
        raise ReceiptSchemaError("trust_domain drifted from frozen v1")
    if trust.get("model_monitor_mcp") != "untrusted_relative_to_pep":
        raise ReceiptSchemaError("trust_domain.model_monitor_mcp drifted")
    if trust.get("pep") != "host-runtime-separate":
        raise ReceiptSchemaError("trust_domain.pep drifted")


def expected_shape_keys(expected: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(expected.keys())
