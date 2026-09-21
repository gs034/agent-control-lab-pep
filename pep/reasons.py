# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Stable deny/allow reason codes for attested receipts."""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    """Machine-stable codes. New codes are additive; do not reuse strings."""

    ALLOWED = "allowed"
    UNKNOWN_TOOL = "unknown_tool"
    CAPABILITY_MISSING = "capability_missing"
    AGENT_PROSE_REJECTED = "agent_prose_rejected"
    POLICY_MISS = "policy_miss"
    KILL_ACTIVE = "kill_active"
    # Admitted before kill, completed after the cut. Distinct from KILL_ACTIVE.
    LATE_EFFECT_FENCE = "late_effect_fence"
    # Second complete_invoke on an admission whose entry permit was already taken.
    ADMISSION_CONSUMED = "admission_consumed"
    SUSPEND_ACTIVE = "suspend_active"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_CONSUMED = "approval_consumed"
    APPROVAL_BINDING_MISMATCH = "approval_binding_mismatch"
    ENVELOPE_INVALID = "envelope_invalid"
    # Exact Deep Research receipt code for the official eval row.
    TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY = "TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY"


# Composite receipt signal for LATE_EFFECT_FENCE. Frozen v1 has no extra field;
# cut+fence is carried in reason_detail so the deny is not only kill_active.
LATE_EFFECT_FENCE_DETAIL = (
    "kill cut+fence engaged; in-flight or queued invoke fail-closed deny, no tool entry"
)
ADMISSION_CONSUMED_DETAIL = (
    "admission ticket already consumed; fail-closed deny, no second tool entry"
)
