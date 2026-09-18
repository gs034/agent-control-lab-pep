# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Structured deny path: unknown tool, policy miss, capability, allow."""

from __future__ import annotations

from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY, POLICY_VERSION, PolicyStore
from pep.reasons import ReasonCode


def _base(**overrides):
    env = {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-deny-path",
    }
    env.update(overrides)
    return env


def test_unknown_tool_with_token_is_unknown_tool():
    called = {"n": 0}

    def boom():
        called["n"] += 1
        return "nope"

    decision, result = gated_invoke(_base(tool_name="shell.exec"), boom)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.UNKNOWN_TOOL
    assert result is None
    assert called["n"] == 0
    assert decision.to_dict()["judge"]["llm_cot_transcript_judge"] is False
    assert decision.to_dict()["trust_domain"]["pep"] == "host-runtime-separate"
    assert decision.to_dict()["pep_id"] == "acl-pep-stub-host-runtime-001"


def test_unknown_tool_without_capability_uses_dr_reason():
    decision = evaluate(_base(tool_name="shell.exec", capability_token=None))
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY


def test_caller_is_not_allow_authority():
    decision = evaluate(_base(caller_identity="lab.other.agent"))
    assert decision.verdict == "ALLOW"


def test_policy_miss_bad_args():
    decision = evaluate(_base(args={"message": "hello", "extra": True}))
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.POLICY_MISS


def test_policy_miss_empty_store():
    runtime = PepRuntime(policy=PolicyStore.empty())
    decision = evaluate(_base(), runtime=runtime)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.POLICY_MISS


def test_capability_missing():
    decision = evaluate(_base(capability_token=None))
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING


def test_capability_expired():
    decision = evaluate(_base(capability_token="lab.cap.echo.expired"))
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING


def test_capability_unknown():
    decision = evaluate(_base(capability_token="lab.cap.not.issued"))
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING


def test_allow_structured_echo_invokes():
    called = {"n": 0}

    def echo():
        called["n"] += 1
        return "ok"

    decision, result = gated_invoke(_base(), echo)
    assert decision.verdict == "ALLOW"
    assert decision.receipt.reason_code == ReasonCode.ALLOWED
    assert result == "ok"
    assert called["n"] == 1
    assert decision.receipt.policy_version == POLICY_VERSION
    assert decision.receipt.policy_file_unchanged is True
    assert decision.to_dict()["judge"]["agent_prose_used_as_policy"] is False
    assert DEMO_POLICY.bytes_unchanged()
