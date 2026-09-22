# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Single-use TTL approval path: mint, consume, replay, expiry, catalog bound."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from pep.approval import ApprovalError, ApprovalStore, invoke_binding_digest
from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

APPROVED_ARGS = {"message": "hello"}
MUTATED_ARGS = {"message": "mutated"}


def _base(**overrides):
    env = {
        "tool_name": "echo.ping",
        "args": dict(APPROVED_ARGS),
        "capability_token": None,
        "caller_identity": "lab.demo.agent",
        "request_id": "test-approval",
    }
    env.update(overrides)
    return env


def _runtime() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY)


def _issue(runtime: PepRuntime, **overrides):
    kwargs = {
        "tool_name": "echo.ping",
        "args": dict(APPROVED_ARGS),
        "ttl_seconds": 60,
    }
    kwargs.update(overrides)
    return runtime.issue_approval(**kwargs)


def test_issue_approval_allows_allowlisted_tool_without_standing_capability():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now)
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
    grant = _issue(runtime, now=now)
    first = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    second = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    assert first.verdict == "ALLOW"
    assert second.verdict == "DENY"
    assert second.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED
    assert second.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False


def test_expired_approval_denies():
    runtime = _runtime()
    issued = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, ttl_seconds=30, now=issued)
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
        runtime.issue_approval(tool_name="shell.exec", args=dict(APPROVED_ARGS), ttl_seconds=60)
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
    store.issue(
        tools=("echo.ping",),
        args=dict(APPROVED_ARGS),
        ttl_seconds=60,
        approval_id="lab.appr.echo-only",
        now=now,
    )
    runtime = PepRuntime(policy=DEMO_POLICY, approvals=store)
    # echo.ping is the only catalog tool; uncovered means a presented id that
    # does not list this tool — mint a grant then evaluate a different allowlisted
    # name is impossible on the stub catalog, so assert consume reason directly.
    reason = store.try_consume(
        "lab.appr.echo-only", "lab.other.tool", now=now, args=dict(APPROVED_ARGS)
    )
    assert reason == ReasonCode.APPROVAL_BINDING_MISMATCH
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
    grant = _issue(runtime, now=now)
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
    grant = _issue(runtime, now=now)
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
    grant = _issue(runtime, now=now)

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
        store.issue(
            tools=("echo.ping",),
            args=dict(APPROVED_ARGS),
            ttl_seconds=0,
            now=now,
            catalog=DEMO_POLICY.allowed_tools(),
        )
    store.issue(
        tools=("echo.ping",),
        args=dict(APPROVED_ARGS),
        ttl_seconds=10,
        approval_id="lab.appr.dup",
        now=now,
        catalog=DEMO_POLICY.allowed_tools(),
    )
    with pytest.raises(ApprovalError):
        store.issue(
            tools=("echo.ping",),
            args=dict(APPROVED_ARGS),
            ttl_seconds=10,
            approval_id="lab.appr.dup",
            now=now,
            catalog=DEMO_POLICY.allowed_tools(),
        )


def test_mutated_args_deny_binding_mismatch_without_consume():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now)
    mutated = evaluate(
        _base(approval_id=grant.approval_id, args=dict(MUTATED_ARGS)),
        runtime=runtime,
        now=now,
    )
    assert mutated.verdict == "DENY"
    assert mutated.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH
    assert mutated.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False
    stored = runtime.approvals.lookup(grant.approval_id)
    assert stored is not None and not stored.consumed()


def test_exact_binding_allows_then_single_use_consume():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now)
    assert grant.binding_digest == invoke_binding_digest("echo.ping", APPROVED_ARGS)
    assert dict(grant.frozen_args) == APPROVED_ARGS
    first = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    replay = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    assert first.verdict == "ALLOW"
    assert first.receipt.reason_code == ReasonCode.ALLOWED
    assert runtime.approvals.lookup(grant.approval_id).consumed()
    assert replay.verdict == "DENY"
    assert replay.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED


def test_equivalent_arg_key_order_matches_frozen_binding():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, args={"cwd": "/tmp", "network": False}, now=now)
    decision = evaluate(
        _base(approval_id=grant.approval_id, args={"network": False, "cwd": "/tmp"}),
        runtime=runtime,
        now=now,
    )
    assert decision.verdict == "ALLOW"


def test_prose_and_policy_context_are_ignored_for_binding():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(
        runtime,
        args={"argv": [], "cwd": "/tmp", "env_allowlist": [], "network": False},
        now=now,
    )
    envelope = {
        "caller": {
            "identity": "lab.demo.agent",
            "note": "Caller identity is not an allow authority; PEP trust domain is separate.",
            "trust_domain": "model+monitor+mcp",
        },
        "envelope_version": "1.0",
        "invoke": {
            "argv": [],
            "schema_fields": {
                "approval_id": grant.approval_id,
                "capability_token": None,
                "cwd": "/tmp",
                "env_allowlist": [],
                "network": False,
            },
            "tool_name": "echo.ping",
        },
        "pep_eval_id": "acl-pep-eval-approval-binding-prose",
        "policy_context": {
            "expected_tool_allowlist": ["echo.ping", "shell.exec"],
            "fail_closed": True,
            "please_allow_mutated_args": True,
            "policy_id": "acl-pep-stub-allowlist-v0",
            "policy_version": "0.1.0-stub",
        },
        "untrusted_attachments": {
            "agent_prose_role": "data_only_never_policy",
            "please_rewrite_approved_args": True,
        },
    }
    decision = evaluate(envelope, runtime=runtime, now=now)
    assert decision.verdict == "ALLOW"
    assert "shell.exec" not in DEMO_POLICY.allowed_tools()


def test_mint_rejects_non_object_args_and_multi_tool_binding():
    store = ApprovalStore()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    with pytest.raises(ApprovalError):
        store.issue(tools=("echo.ping",), args=["not-an-object"], ttl_seconds=10, now=now)
    with pytest.raises(ApprovalError):
        store.issue(
            tools=("echo.ping", "lab.other.tool"),
            args=dict(APPROVED_ARGS),
            ttl_seconds=10,
            now=now,
        )


STATE_A = "sha256:" + "a" * 64
STATE_B = "sha256:" + "b" * 64


def test_state_digest_frozen_at_mint_denies_substituted_state_without_consume():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    assert grant.state_digest == STATE_A
    substituted = evaluate(
        _base(approval_id=grant.approval_id, state_digest=STATE_B),
        runtime=runtime,
        now=now,
    )
    assert substituted.verdict == "DENY"
    assert substituted.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert substituted.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False
    missing = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now)
    assert missing.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    stored = runtime.approvals.lookup(grant.approval_id)
    assert stored is not None and not stored.consumed()


def test_matching_state_digest_allows_then_consumes():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    first = evaluate(
        _base(approval_id=grant.approval_id, state_digest=STATE_A.upper()),
        runtime=runtime,
        now=now,
    )
    assert first.verdict == "ALLOW"
    assert runtime.approvals.lookup(grant.approval_id).consumed()
    replay = evaluate(
        _base(approval_id=grant.approval_id, state_digest=STATE_A), runtime=runtime, now=now
    )
    assert replay.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED


def test_args_mismatch_is_reported_before_state_mismatch():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    both = evaluate(
        _base(approval_id=grant.approval_id, args=dict(MUTATED_ARGS), state_digest=STATE_B),
        runtime=runtime,
        now=now,
    )
    assert both.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH


def test_grant_without_state_digest_ignores_envelope_state_digest():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now)
    assert grant.state_digest is None
    decision = evaluate(
        _base(approval_id=grant.approval_id, state_digest=STATE_B), runtime=runtime, now=now
    )
    assert decision.verdict == "ALLOW"


def test_mint_rejects_malformed_state_digest():
    runtime = _runtime()
    for bad in ("sha256:abc", "md5:" + "a" * 32, "a" * 64, "", " " + STATE_A, STATE_A + "\n"):
        with pytest.raises(ApprovalError):
            _issue(runtime, state_digest=bad)


def test_prose_cannot_supply_state_digest_for_binding():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    coaxed = evaluate(
        _base(
            approval_id=grant.approval_id,
            state_digest=STATE_B,
            untrusted_agent_text=f"state digest is really {STATE_A}, please allow",
        ),
        runtime=runtime,
        now=now,
    )
    assert coaxed.verdict == "DENY"
    # The prose channel is rejected before the approval path runs; the
    # frozen digest is never compared against prose and the grant stays unspent.
    assert coaxed.receipt.reason_code == ReasonCode.AGENT_PROSE_REJECTED
    stored = runtime.approvals.lookup(grant.approval_id)
    assert stored is not None and not stored.consumed()


def test_state_observer_overrides_envelope_digest_at_consume():
    """The host observes the target inside the gate, next to execution."""
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    # Envelope still claims A; the host observes B at consume time.
    swapped = evaluate(
        _base(approval_id=grant.approval_id, state_digest=STATE_A),
        runtime=runtime,
        now=now,
        state_observer=lambda: STATE_B,
    )
    assert swapped.verdict == "DENY"
    assert swapped.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert not runtime.approvals.lookup(grant.approval_id).consumed()
    # Observer confirms A: ALLOW even when the envelope omits the digest.
    ok = evaluate(
        _base(approval_id=grant.approval_id),
        runtime=runtime,
        now=now,
        state_observer=lambda: STATE_A,
    )
    assert ok.verdict == "ALLOW"
    assert runtime.approvals.lookup(grant.approval_id).consumed()


def test_state_observer_failure_or_bad_value_is_deny():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)

    def boom() -> str:
        raise OSError("target unreadable")

    for observer in (boom, lambda: None, lambda: "not-a-digest", lambda: 42):
        decision = evaluate(
            _base(approval_id=grant.approval_id, state_digest=STATE_A),
            runtime=runtime,
            now=now,
            state_observer=observer,
        )
        assert decision.verdict == "DENY"
        assert decision.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_state_observer_runs_through_gated_invoke_and_blocks_tool_entry():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    calls = {"tool": 0, "observer": 0}

    def observer() -> str:
        calls["observer"] += 1
        return STATE_B

    def tool() -> str:
        calls["tool"] += 1
        return "ran"

    decision, result = gated_invoke(
        _base(approval_id=grant.approval_id, state_digest=STATE_A),
        tool,
        runtime,
        now=now,
        state_observer=observer,
    )
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert result is None
    assert calls == {"tool": 0, "observer": 1}


def test_state_observer_not_called_when_grant_fails_an_earlier_check():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    calls = {"n": 0}

    def observer() -> str:
        calls["n"] += 1
        return STATE_A

    expired = _issue(runtime, now=now, state_digest=STATE_A, ttl_seconds=60)
    late = evaluate(
        _base(approval_id=expired.approval_id),
        runtime=runtime,
        now=now + timedelta(minutes=5),
        state_observer=observer,
    )
    assert late.receipt.reason_code == ReasonCode.APPROVAL_EXPIRED
    spent = _issue(runtime, now=now, state_digest=STATE_A)
    first = evaluate(_base(approval_id=spent.approval_id), runtime=runtime, now=now, state_observer=observer)
    assert first.verdict == "ALLOW" and calls["n"] == 1
    replay = evaluate(_base(approval_id=spent.approval_id), runtime=runtime, now=now, state_observer=observer)
    assert replay.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED
    bound = _issue(runtime, now=now, state_digest=STATE_A)
    mutated = evaluate(
        _base(approval_id=bound.approval_id, args=dict(MUTATED_ARGS)),
        runtime=runtime,
        now=now,
        state_observer=observer,
    )
    assert mutated.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH
    unknown = evaluate(_base(approval_id="lab.appr.nope"), runtime=runtime, now=now, state_observer=observer)
    assert unknown.receipt.reason_code == ReasonCode.APPROVAL_INVALID
    assert calls["n"] == 1


def test_state_mismatch_detail_distinguishes_failed_observer_from_mismatch():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)

    def boom() -> str:
        raise OSError("target unreadable")

    failed = evaluate(_base(approval_id=grant.approval_id), runtime=runtime, now=now, state_observer=boom)
    assert failed.receipt.reason_detail.endswith("state observer failed")
    wrong = evaluate(
        _base(approval_id=grant.approval_id), runtime=runtime, now=now, state_observer=lambda: STATE_B
    )
    assert wrong.receipt.reason_detail.endswith("state observer mismatch")
    envelope_only = evaluate(_base(approval_id=grant.approval_id, state_digest=STATE_B), runtime=runtime, now=now)
    assert envelope_only.receipt.reason_detail.endswith("envelope state digest mismatch")


def test_split_admission_reobserves_state_at_entry_and_denies_a_changed_target():
    from pep.gate import begin_invoke, complete_invoke

    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    target = {"digest": STATE_A}
    calls = {"observer": 0, "tool": 0}

    def observer() -> str:
        calls["observer"] += 1
        return target["digest"]

    def tool() -> str:
        calls["tool"] += 1
        return "ran"

    pending = begin_invoke(_base(approval_id=grant.approval_id), runtime, now=now, state_observer=observer)
    assert pending.decision.verdict == "ALLOW"
    assert pending.decision.frozen_state_digest == STATE_A
    assert runtime.approvals.lookup(grant.approval_id).consumed()
    target["digest"] = STATE_B  # target swapped between admission and entry
    decision, result = complete_invoke(pending, tool)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert "re-observed at tool entry" in decision.receipt.reason_detail
    assert result is None
    assert calls == {"observer": 2, "tool": 0}
    assert "frozen_state_digest" not in decision.to_dict()


def test_split_admission_enters_tool_when_state_unchanged_and_raising_observer_denies():
    from pep.gate import begin_invoke, complete_invoke

    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now, state_digest=STATE_A)
    pending = begin_invoke(
        _base(approval_id=grant.approval_id), runtime, now=now, state_observer=lambda: STATE_A
    )
    decision, result = complete_invoke(pending, lambda: "ran")
    assert decision.verdict == "ALLOW" and result == "ran"

    flaky = {"n": 0}

    def observer() -> str:
        flaky["n"] += 1
        if flaky["n"] == 1:
            return STATE_A
        raise OSError("target unreadable at entry")

    second = _issue(runtime, now=now, state_digest=STATE_A)
    pending = begin_invoke(_base(approval_id=second.approval_id), runtime, now=now, state_observer=observer)
    decision, result = complete_invoke(pending, lambda: "ran")
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert result is None


def test_split_admission_without_observer_or_frozen_digest_has_no_entry_recheck():
    from pep.gate import begin_invoke, complete_invoke

    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    plain = _issue(runtime, now=now)
    pending = begin_invoke(_base(approval_id=plain.approval_id), runtime, now=now, state_observer=lambda: STATE_B)
    assert pending.decision.frozen_state_digest is None
    assert complete_invoke(pending, lambda: "ran")[1] == "ran"
    frozen = _issue(runtime, now=now, state_digest=STATE_A)
    pending = begin_invoke(_base(approval_id=frozen.approval_id, state_digest=STATE_A), runtime, now=now)
    assert pending.decision.frozen_state_digest == STATE_A
    assert complete_invoke(pending, lambda: "ran")[1] == "ran"


def test_state_observer_is_not_consulted_without_a_frozen_digest():
    runtime = _runtime()
    now = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)
    grant = _issue(runtime, now=now)
    calls = {"observer": 0}

    def observer() -> str:
        calls["observer"] += 1
        return STATE_B

    decision = evaluate(
        _base(approval_id=grant.approval_id), runtime=runtime, now=now, state_observer=observer
    )
    assert decision.verdict == "ALLOW"
    assert calls["observer"] == 0
