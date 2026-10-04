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
from datetime import datetime, timedelta, timezone

import pytest

from pep.approval import ApprovalError
from pep.evaluate import PepRuntime, evaluate
from pep.gate import gated_invoke
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


def test_two_principals_racing_one_grant_only_the_owner_consumes():
    for _ in range(50):
        runtime = _runtime()
        grant = _grant(runtime)
        barrier = threading.Barrier(2)
        results: dict[str, object] = {}

        def run(name: str) -> None:
            barrier.wait()
            results[name] = evaluate(
                _envelope(grant.approval_id, identity=name), runtime=runtime, now=NOW, principal=name
            )

        threads = [threading.Thread(target=run, args=(name,)) for name in (OWNER, OTHER)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert results[OWNER].verdict == "ALLOW"
        _assert_mismatch(results[OTHER])
        assert _consumed(runtime, grant.approval_id)


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
        store.try_consume(
            grant.approval_id, "echo.ping", NOW, args=ARGS, principal=OWNER, envelope_identity=OWNER
        )
        is None
    )
