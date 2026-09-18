# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Envelope parse failures deny with envelope_invalid."""

from __future__ import annotations

from pep.evaluate import evaluate
from pep.reasons import ReasonCode


def test_null_envelope():
    decision = evaluate(None)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID


def test_non_object_envelope():
    decision = evaluate(["lab.echo"])
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID


def test_bad_json_bytes():
    decision = evaluate(b"{not-json")
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID


def test_args_must_be_object():
    decision = evaluate(
        {
            "tool_name": "lab.echo",
            "args": ["hello"],
            "capability_token": "lab.cap.echo.demo",
            "caller_identity": "lab.demo.agent",
            "request_id": "test-args",
        }
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID


def test_unknown_field_is_invalid_not_policy():
    decision = evaluate(
        {
            "tool_name": "lab.echo",
            "args": {"message": "hello"},
            "capability_token": "lab.cap.echo.demo",
            "caller_identity": "lab.demo.agent",
            "request_id": "test-extra",
            "typo_field": 1,
        }
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID


def test_malformed_tool_name():
    decision = evaluate(
        {
            "tool_name": "Lab.Echo",
            "args": {"message": "hello"},
            "capability_token": "lab.cap.echo.demo",
            "caller_identity": "lab.demo.agent",
            "request_id": "test-case",
        }
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID
