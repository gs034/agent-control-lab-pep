# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0002: single-use approvals bound to a host-attested principal.

Each test is one row of the ADR-0002 acceptance table. The principal is passed
by the host as a function argument, never read from the envelope; the
envelope identity is only a consistency check. Every principal failure is
``approval_principal_mismatch``, does not consume, and names no identity.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from pep.approval import ApprovalError
from pep.evaluate import PepRuntime, evaluate
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
ARGS = {"message": "hello"}
OWNER = "lab.demo.agent"
OTHER = "lab.other.agent"
DIGEST = "sha256:" + "a" * 64


def _envelope(approval_id: str, *, identity: str = OWNER, args=None) -> dict:
    return {
        "tool_name": "echo.ping",
        "args": dict(ARGS if args is None else args),
        "capability_token": None,
        "caller_identity": identity,
        "request_id": "test-principal-binding",
        "approval_id": approval_id,
    }


def _lab_envelope(approval_id: str, *, identity: str = OWNER) -> dict:
    return {
        "caller": {"identity": identity},
        "envelope_version": "1.0",
        "invoke": {
            "tool_name": "echo.ping",
            "argv": [],
            "schema_fields": {"approval_id": approval_id, "capability_token": None},
        },
        "pep_eval_id": "acl-pep-principal-binding-lab",
    }


def _runtime() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY)


def _grant(runtime: PepRuntime, **overrides):
    kwargs = {
        "tool_name": "echo.ping",
        "args": dict(ARGS),
        "ttl_seconds": 60,
        "now": NOW,
        "principal": OWNER,
    }
    kwargs.update(overrides)
    return runtime.issue_approval(**kwargs)


def _consumed(runtime: PepRuntime, approval_id: str) -> bool:
    return runtime.approvals.lookup(approval_id).consumed()


def _assert_mismatch(decision) -> None:
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_PRINCIPAL_MISMATCH
    detail = decision.receipt.reason_detail
    assert OWNER not in detail and OTHER not in detail


def test_mint_records_principal():
    grant = _grant(_runtime())
    assert grant.principal == OWNER


@pytest.mark.parametrize("bad", ["", "Lab.Upper", "has space", "x" * 200, 7])
def test_mint_rejects_malformed_principal(bad):
    with pytest.raises(ApprovalError):
        _grant(_runtime(), principal=bad)


def test_owner_principal_exact_invoke_allows():
    runtime = _runtime()
    grant = _grant(runtime)
    calls: list[str] = []
    decision, result = gated_invoke(
        _envelope(grant.approval_id),
        lambda: calls.append("entered") or "ok",
        runtime=runtime,
        now=NOW,
        principal=OWNER,
    )
    assert decision.verdict == "ALLOW"
    assert result == "ok" and calls == ["entered"]
    assert _consumed(runtime, grant.approval_id)


def test_delegation_to_a_second_principal_denies_and_does_not_consume():
    runtime = _runtime()
    grant = _grant(runtime)
    calls: list[str] = []
    delegated, result = gated_invoke(
        _envelope(grant.approval_id, identity=OTHER),
        lambda: calls.append("entered"),
        runtime=runtime,
        now=NOW,
        principal=OTHER,
    )
    _assert_mismatch(delegated)
    assert result is None and calls == []
    assert not _consumed(runtime, grant.approval_id)

    owner = evaluate(_envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER)
    assert owner.verdict == "ALLOW"


def test_copied_identity_string_without_host_attestation_denies():
    """A delegate that copies the owner's identity into the envelope still fails."""
    runtime = _runtime()
    grant = _grant(runtime)
    copied = evaluate(_envelope(grant.approval_id, identity=OWNER), runtime=runtime, now=NOW)
    _assert_mismatch(copied)
    assert copied.receipt.reason_detail.endswith("no attested principal")
    assert not _consumed(runtime, grant.approval_id)


def test_envelope_identity_disagreeing_with_host_denies():
    runtime = _runtime()
    grant = _grant(runtime)
    decision = evaluate(
        _envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OWNER
    )
    _assert_mismatch(decision)
    assert not _consumed(runtime, grant.approval_id)


@pytest.mark.parametrize("bad", ["Lab.Upper", "has space", ""])
def test_malformed_host_principal_is_envelope_invalid_and_touches_no_grant(bad):
    runtime = _runtime()
    grant = _grant(runtime)
    decision = evaluate(_envelope(grant.approval_id), runtime=runtime, now=NOW, principal=bad)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID
    assert not _consumed(runtime, grant.approval_id)


def test_unknown_approval_id_stays_approval_invalid():
    decision = evaluate(_envelope("lab.appr.unknown"), runtime=_runtime(), now=NOW)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_INVALID


def test_wrong_principal_learns_nothing_about_grant_state():
    """Spent, expired and args-mismatched grants all look the same to a wrong caller."""
    runtime = _runtime()
    spent = _grant(runtime)
    assert evaluate(_envelope(spent.approval_id), runtime=runtime, now=NOW, principal=OWNER).allowed()
    expiring = _grant(runtime, ttl_seconds=1)
    other_args = _grant(runtime, args={"message": "other"})

    probes = [
        evaluate(_envelope(spent.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER),
        evaluate(
            _envelope(expiring.approval_id, identity=OTHER),
            runtime=runtime,
            now=NOW + timedelta(minutes=5),
            principal=OTHER,
        ),
        evaluate(_envelope(other_args.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER),
        evaluate(_envelope(spent.approval_id), runtime=runtime, now=NOW),
    ]
    for probe in probes:
        _assert_mismatch(probe)
    assert len({p.receipt.reason_detail for p in probes[:3]}) == 1
    assert not _consumed(runtime, expiring.approval_id)
    assert not _consumed(runtime, other_args.approval_id)

    # The owner sees the real state, so the probes above hid something real.
    owner_late = evaluate(
        _envelope(expiring.approval_id), runtime=runtime, now=NOW + timedelta(minutes=5), principal=OWNER
    )
    assert owner_late.receipt.reason_code == ReasonCode.APPROVAL_EXPIRED
    owner_args = evaluate(_envelope(other_args.approval_id), runtime=runtime, now=NOW, principal=OWNER)
    assert owner_args.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH
    owner_spent = evaluate(_envelope(spent.approval_id), runtime=runtime, now=NOW, principal=OWNER)
    assert owner_spent.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED


def test_wrong_principal_and_envelope_disagreement_share_one_detail():
    runtime = _runtime()
    grant = _grant(runtime)
    wrong = evaluate(_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER)
    disagree = evaluate(
        _envelope(grant.approval_id, identity="lab.zzz"), runtime=runtime, now=NOW, principal=OWNER
    )
    _assert_mismatch(wrong)
    _assert_mismatch(disagree)
    assert wrong.receipt.reason_detail == disagree.receipt.reason_detail


def test_owner_expiry_consume_and_replay_codes_are_unchanged():
    runtime = _runtime()
    expiring = _grant(runtime, ttl_seconds=30)
    late = evaluate(
        _envelope(expiring.approval_id), runtime=runtime, now=NOW + timedelta(seconds=30), principal=OWNER
    )
    assert late.receipt.reason_code == ReasonCode.APPROVAL_EXPIRED

    grant = _grant(runtime)
    assert evaluate(_envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER).allowed()
    replay = evaluate(
        _envelope(grant.approval_id), runtime=runtime, now=NOW + timedelta(seconds=1), principal=OWNER
    )
    assert replay.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED


def test_owner_binding_mismatch_is_unchanged_and_does_not_consume():
    runtime = _runtime()
    grant = _grant(runtime)
    swapped = evaluate(
        _envelope(grant.approval_id, args={"message": "swapped"}), runtime=runtime, now=NOW, principal=OWNER
    )
    assert swapped.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH
    assert not _consumed(runtime, grant.approval_id)


def test_wrong_principal_never_triggers_a_host_state_read():
    runtime = _runtime()
    grant = _grant(runtime, state_digest=DIGEST)
    reads: list[int] = []

    def observe() -> str:
        reads.append(1)
        return DIGEST

    wrong = evaluate(
        _envelope(grant.approval_id, identity=OTHER),
        runtime=runtime,
        now=NOW,
        principal=OTHER,
        state_observer=observe,
    )
    _assert_mismatch(wrong)
    assert reads == []

    changed = evaluate(
        _envelope(grant.approval_id),
        runtime=runtime,
        now=NOW,
        principal=OWNER,
        state_observer=lambda: "sha256:" + "b" * 64,
    )
    assert changed.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert not _consumed(runtime, grant.approval_id)

    owner = evaluate(
        _envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER, state_observer=observe
    )
    assert owner.verdict == "ALLOW"
    assert reads == [1]


def test_wrong_principal_before_and_after_the_owner_both_mismatch():
    """Both orders, forced: the principal check precedes the consumed check."""
    runtime = _runtime()
    grant = _grant(runtime)
    before = evaluate(_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER)
    _assert_mismatch(before)
    assert evaluate(_envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER).allowed()
    after = evaluate(_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER)
    _assert_mismatch(after)


def test_concurrent_owner_calls_consume_exactly_once():
    """Owner calls race one grant. A slow state observer runs inside consume,
    after the single-use check, so a consume without the store lock would let
    a second owner call through while the first is still observing."""
    runtime = _runtime()
    grant = _grant(runtime, state_digest=DIGEST)

    def slow_observe() -> str:
        time.sleep(0.02)
        return DIGEST

    barrier = threading.Barrier(4)
    results: list[object] = []
    lock = threading.Lock()

    def run(name: str) -> None:
        barrier.wait()
        decision = evaluate(
            _envelope(grant.approval_id, identity=name),
            runtime=runtime,
            now=NOW,
            principal=name,
            state_observer=slow_observe,
        )
        with lock:
            results.append((name, decision))

    names = [OWNER, OWNER, OWNER, OTHER]
    threads = [threading.Thread(target=run, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    allowed = [name for name, d in results if d.verdict == "ALLOW"]
    assert allowed == [OWNER]
    owner_denies = [d.receipt.reason_code for name, d in results if name == OWNER and d.verdict == "DENY"]
    assert owner_denies == [ReasonCode.APPROVAL_CONSUMED, ReasonCode.APPROVAL_CONSUMED]
    for name, decision in results:
        if name == OTHER:
            _assert_mismatch(decision)


def test_lab_shape_envelope_is_bound_the_same_way():
    runtime = _runtime()
    grant = _grant(runtime, args={"argv": []})
    for decision in (
        evaluate(_lab_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER),
        evaluate(_lab_envelope(grant.approval_id), runtime=runtime, now=NOW),
        evaluate(_lab_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OWNER),
    ):
        _assert_mismatch(decision)
    assert not _consumed(runtime, grant.approval_id)
    owner = evaluate(_lab_envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER)
    assert owner.verdict == "ALLOW"


def test_begin_then_complete_with_wrong_principal_never_enters_the_tool():
    runtime = _runtime()
    grant = _grant(runtime)
    calls: list[str] = []
    pending = begin_invoke(_envelope(grant.approval_id, identity=OTHER), runtime=runtime, now=NOW, principal=OTHER)
    decision, result = complete_invoke(pending, lambda: calls.append("entered"))
    _assert_mismatch(decision)
    assert result is None and calls == []
    assert not _consumed(runtime, grant.approval_id)


def test_owner_grant_spent_when_state_changes_before_entry_is_the_documented_residual():
    """ADR-0002 residual: an owner ALLOW whose target changes before entry is
    DENY with the grant already spent. Only a wrong caller is kept from spending it."""
    runtime = _runtime()
    grant = _grant(runtime, state_digest=DIGEST)
    reads = iter([DIGEST, "sha256:" + "b" * 64])
    pending = begin_invoke(
        _envelope(grant.approval_id), runtime=runtime, now=NOW, principal=OWNER, state_observer=lambda: next(reads)
    )
    assert pending.decision.verdict == "ALLOW"
    calls: list[str] = []
    decision, result = complete_invoke(pending, lambda: calls.append("entered"))
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_STATE_MISMATCH
    assert result is None and calls == []
    assert _consumed(runtime, grant.approval_id)


def test_mint_without_principal_raises():
    """ADR-0002 phase 2: there is no unbound mode."""
    with pytest.raises(ApprovalError):
        _grant(_runtime(), principal=None)
    with pytest.raises(ApprovalError):
        _runtime().approvals.issue(tools=("echo.ping",), args=dict(ARGS), ttl_seconds=60, now=NOW)


def test_try_consume_passes_principal_through():
    runtime = _runtime()
    grant = _grant(runtime)
    store = runtime.approvals
    assert (
        store.try_consume(
            grant.approval_id, "echo.ping", NOW, args=ARGS, principal=OTHER, envelope_identity=OTHER
        )
        == ReasonCode.APPROVAL_PRINCIPAL_MISMATCH
    )
    assert (
        store.try_consume(grant.approval_id, "echo.ping", NOW, args=ARGS, principal=OWNER)
        == ReasonCode.APPROVAL_PRINCIPAL_MISMATCH
    )
    assert (
        store.try_consume(
            grant.approval_id, "echo.ping", NOW, args=ARGS, principal=OWNER, envelope_identity=OWNER
        )
        is None
    )
