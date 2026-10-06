# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Kill switch and PEP-unavailable fail closed to DENY; never invoke."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

# ADR-0003: the principal the test host attests; a listed holder of lab.cap.echo.demo.
HOST = "lab.demo.agent"


def _valid():
    return {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-fail-closed",
    }


def test_kill_active_denies_allowlisted_invoke():
    runtime = PepRuntime(policy=DEMO_POLICY, kill_active=True)
    called = {"n": 0}

    def boom():
        called["n"] += 1
        return "nope"

    decision, result = gated_invoke(_valid(), boom, runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert result is None
    assert called["n"] == 0


def test_pep_unavailable_is_kill_active():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.mark_unavailable()
    decision = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert decision.receipt.policy_file_unchanged is True


def test_activate_kill_after_construct():
    runtime = PepRuntime()
    runtime.activate_kill()
    decision = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def _killed() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY, kill_active=True)


def _unavailable() -> PepRuntime:
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.mark_unavailable()
    return runtime


@pytest.mark.parametrize("halted", [_killed, _unavailable], ids=["killed", "unavailable"])
@pytest.mark.parametrize(
    ("override", "principal"),
    [
        ({"capability_token": "lab.cap.not.issued"}, HOST),
        ({}, "lab.other.agent"),
        ({"tool_name": "not.in.catalog"}, HOST),
    ],
    ids=["bad-token", "non-holder", "unknown-tool"],
)
def test_kill_is_the_reason_before_any_other_deny(halted, override, principal):
    # Audit 2026-10-06-gate-set2 M08: the first kill check in evaluate is the
    # only one before the policy and approval checks. Without it a halted PEP
    # still reports other reasons, and spends a grant before the later check.
    decision = evaluate({**_valid(), **override}, runtime=halted(), principal=principal)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_kill_denies_without_spending_an_approval():
    runtime = PepRuntime(policy=DEMO_POLICY)
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(
        tool_name="echo.ping", args={"message": "hello"}, ttl_seconds=60, principal=HOST, now=now
    )
    runtime.activate_kill()
    envelope = {**_valid(), "capability_token": None, "approval_id": grant.approval_id}
    decision = evaluate(envelope, runtime=runtime, principal=HOST, now=now)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert runtime.approvals.lookup(grant.approval_id).consumed() is False


def test_suspend_denies_and_resume_restores_allow():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.suspend()
    assert runtime.suspend_active is True
    denied = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert denied.verdict == "DENY"
    assert denied.receipt.reason_code == ReasonCode.SUSPEND_ACTIVE
    runtime.resume()
    allowed = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert allowed.verdict == "ALLOW"
    assert allowed.receipt.reason_code == ReasonCode.ALLOWED


def test_resume_cannot_clear_kill():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.kill()
    runtime.resume()
    decision = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert runtime.kill_active is True


def test_kill_wins_over_later_suspend():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.kill()
    runtime.suspend()
    decision = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert runtime.mode.value == "killed"


def test_suspend_then_kill_stays_killed():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.suspend()
    runtime.kill()
    runtime.resume()
    decision = evaluate(_valid(), runtime=runtime, principal=HOST)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
