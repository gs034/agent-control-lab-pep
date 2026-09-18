# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Single-use TTL approval path: mint, consume, replay, expiry, catalog bound."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from pep.approval import ApprovalError, ApprovalStore
from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode


def _base(**overrides):
    env = {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": None,
        "caller_identity": "lab.demo.agent",
        "request_id": "test-approval",
    }
    env.update(overrides)
    return env


def _runtime() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY)


def test_issue_approval_allows_allowlisted_tool_without_standing_capability():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=60, now=now)
    called = {"n": 0}

    def echo():
        called["n"] += 1
        return "ok"

    decision, result = gated_invoke(
        _base(approval_id=grant.approval_id),
        echo,
        runtime=runtime,
        now=now,
    )
    assert decision.verdict == "ALLOW"
    assert result == "ok"
    assert called["n"] == 1
    stored = runtime.approvals.lookup(grant.approval_id)
    assert stored is not None and stored.consumed()


def test_approval_is_single_use_replay_denies():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=60, now=now)
    first = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    second = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    assert first.verdict == "ALLOW"
    assert second.verdict == "DENY"
    assert second.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED
    assert second.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False


def test_expired_approval_denies():
    runtime = _runtime()
    issued = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=30, now=issued)
    later = issued + timedelta(seconds=31)
    decision = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=later)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_EXPIRED


def test_unknown_approval_denies():
    runtime = _runtime()
    decision = evaluate(_base(approval_id="lab.appr.not-issued"), runtime=runtime)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_INVALID


def test_approval_does_not_extend_catalog():
    runtime = _runtime()
    with pytest.raises(ApprovalError):
        runtime.issue_approval(tool_name="shell.exec", ttl_seconds=60)
    decision = evaluate(
        _base(tool_name="shell.exec", approval_id="lab.appr.forged"),
        runtime=runtime,
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.UNKNOWN_TOOL


def test_approval_wrong_tool_denies_even_if_id_exists():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    store = ApprovalStore()
    store.issue(tools=("echo.ping",), ttl_seconds=60, approval_id="lab.appr.echo-only", now=now)
    runtime = PepRuntime(policy=DEMO_POLICY, approvals=store)
    # echo.ping is the only catalog tool; uncovered means a presented id that
    # does not list this tool — mint a grant then evaluate a different allowlisted
    # name is impossible on the stub catalog, so assert consume reason directly.
    reason = store.try_consume("lab.appr.echo-only", "lab.other.tool", now=now)
    assert reason == ReasonCode.APPROVAL_INVALID
    assert store.lookup("lab.appr.echo-only") is not None
    assert not store.lookup("lab.appr.echo-only").consumed()


def test_stale_approval_denies_even_when_standing_capability_is_valid():
    runtime = _runtime()
    decision = evaluate(
        _base(
            capability_token="lab.cap.echo.demo",
            approval_id="lab.appr.spoofed",
        ),
        runtime=runtime,
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_INVALID


def test_valid_capability_and_valid_approval_allows_and_consumes():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=60, now=now)
    decision = evaluate(
        _base(
            capability_token="lab.cap.echo.demo",
            approval_id=grant.approval_id,
        ),
        runtime=runtime,
        now=now,
    )
    assert decision.verdict == "ALLOW"
    assert runtime.approvals.lookup(grant.approval_id).consumed()


def test_invalid_capability_does_not_consume_valid_approval():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=60, now=now)
    decision = evaluate(
        _base(
            capability_token="lab.cap.not.issued",
            approval_id=grant.approval_id,
        ),
        runtime=runtime,
        now=now,
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_concurrent_consume_is_single_use():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = runtime.issue_approval(tool_name="echo.ping", ttl_seconds=60, now=now)

    def once() -> str:
        return evaluate(
            _base(approval_id=grant.approval_id, request_id="test-approval-race"),
            runtime=runtime,
            now=now,
        ).verdict

    with ThreadPoolExecutor(max_workers=8) as pool:
        verdicts = list(pool.map(lambda _: once(), range(8)))
    assert verdicts.count("ALLOW") == 1
    assert verdicts.count("DENY") == 7


def test_mint_rejects_zero_ttl_and_duplicate_id():
    store = ApprovalStore()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ApprovalError):
        store.issue(tools=("echo.ping",), ttl_seconds=0, now=now, catalog=DEMO_POLICY.allowed_tools())
    store.issue(
        tools=("echo.ping",),
        ttl_seconds=10,
        approval_id="lab.appr.dup",
        now=now,
        catalog=DEMO_POLICY.allowed_tools(),
    )
    with pytest.raises(ApprovalError):
        store.issue(
            tools=("echo.ping",),
            ttl_seconds=10,
            approval_id="lab.appr.dup",
            now=now,
            catalog=DEMO_POLICY.allowed_tools(),
        )
