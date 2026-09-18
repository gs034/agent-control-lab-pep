# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Deny/allow receipts matching eval/expected_deny_receipt.example.json."""

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
        return {
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
    return Receipt(
        decision=decision,
        reason_code=str(reason_code),
        reason_detail=reason_detail,
        envelope_hash=envelope_hash,
        timestamp=timestamp,
        policy_version=policy_version,
        policy_file_unchanged=policy_file_unchanged,
        tool_invoke_executed=tool_invoke_executed,
    )


def expected_shape_keys(expected: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(expected.keys())
