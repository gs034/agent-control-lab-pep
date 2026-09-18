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
    ENVELOPE_INVALID = "envelope_invalid"
