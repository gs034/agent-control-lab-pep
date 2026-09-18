# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Structured deny path: unknown tool, policy miss, capability, allow."""

from __future__ import annotations

from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY, PolicyStore
from pep.reasons import ReasonCode
from pep.receipt import verify_receipt


def _base(**overrides):
    env = {
        "tool_name": "lab.echo",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-deny-path",
    }
    env.update(overrides)
    return env


def test_unknown_tool_denies_and_does_not_invoke():
    called = {"n": 0}

    def boom():
        called["n"] += 1
        return "nope"

    decision, result = gated_invoke(_base(tool_name="shell.exec"), boom)
    assert decision.verdict == "DENY"
    assert ReasonCode.UNKNOWN_TOOL in decision.receipt.reason_codes
    assert result is None
    assert called["n"] == 0
    assert decision.receipt.no_model_call is True
    assert decision.receipt.trust_domain == "pep"
    assert verify_receipt(decision.receipt)


def test_policy_miss_wrong_caller():
    decision = evaluate(_base(caller_identity="lab.other.agent"))
    assert decision.verdict == "DENY"
    assert ReasonCode.POLICY_MISS in decision.receipt.reason_codes


def test_policy_miss_bad_args():
    decision = evaluate(_base(args={"message": "hello", "extra": True}))
    assert decision.verdict == "DENY"
    assert ReasonCode.POLICY_MISS in decision.receipt.reason_codes


def test_policy_miss_empty_store():
    runtime = PepRuntime(policy=PolicyStore.empty())
    decision = evaluate(_base(), runtime=runtime)
    assert decision.verdict == "DENY"
    assert ReasonCode.POLICY_MISS in decision.receipt.reason_codes


def test_capability_missing():
    decision = evaluate(_base(capability_token=None))
    assert decision.verdict == "DENY"
    assert ReasonCode.CAPABILITY_MISSING in decision.receipt.reason_codes


def test_capability_expired():
    decision = evaluate(_base(capability_token="lab.cap.echo.expired"))
    assert decision.verdict == "DENY"
    assert ReasonCode.CAPABILITY_MISSING in decision.receipt.reason_codes


def test_capability_unknown():
    decision = evaluate(_base(capability_token="lab.cap.not.issued"))
    assert decision.verdict == "DENY"
    assert ReasonCode.CAPABILITY_MISSING in decision.receipt.reason_codes


def test_allow_structured_echo_invokes():
    called = {"n": 0}

    def echo():
        called["n"] += 1
        return "ok"

    decision, result = gated_invoke(_base(), echo)
    assert decision.verdict == "ALLOW"
    assert ReasonCode.ALLOWED in decision.receipt.reason_codes
    assert result == "ok"
    assert called["n"] == 1
    assert decision.receipt.policy_digest == DEMO_POLICY.digest
    assert decision.receipt.policy_bytes_unchanged is True
    assert decision.receipt.prose_consulted_as_policy is False
