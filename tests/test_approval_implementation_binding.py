# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0004: single-use approvals bound to the implementation resolved at mint.

Each test is a row of the ADR-0004 acceptance table. The PEP compares opaque
host-computed digests; these tests compute them from a resolved program path
plus its bytes, the way a host would. Tests named ``*_residual`` record an
ALLOW the binding does not stop.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest

from pep.approval import ApprovalError
from pep.evaluate import PepRuntime, evaluate
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.implementation import executable_digest
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
HOST = "lab.demo.agent"
OTHER = "lab.other.agent"
MISMATCH = ReasonCode.APPROVAL_IMPLEMENTATION_MISMATCH
ENTRY_DETAIL = (
    "implementation re-observed at tool entry differs from the approved digest; "
    "fail-closed deny, no tool entry (grant already spent)"
)

posix_only = pytest.mark.skipif(os.name == "nt", reason="shutil.which resolution here relies on POSIX exec bits")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _Observer:
    """Counts calls so tests can assert when the PEP did not consult the host."""

    def __init__(self, produce):
        self.produce = produce
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.produce()


def _envelope(args, approval_id=None, identity=HOST, **extra):
    env = {
        "tool_name": "echo.ping",
        "args": dict(args),
        "capability_token": None,
        "caller_identity": identity,
        "request_id": "test-approval-implementation",
        "approval_id": approval_id,
    }
    env.update(extra)
    return env


def _runtime() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY)


def _issue(runtime, args, **overrides):
    kwargs = {"tool_name": "echo.ping", "args": dict(args), "ttl_seconds": 60, "now": NOW, "principal": HOST}
    kwargs.update(overrides)
    return runtime.issue_approval(**kwargs)


@pytest.fixture
def programs(tmp_path, monkeypatch):
    """Two executables named ``labtool``; ``order`` puts one first on PATH."""
    dirs = {}
    for label in ("program-a", "program-b"):
        bin_dir = tmp_path / label
        bin_dir.mkdir()
        script = bin_dir / "labtool"
        script.write_text(f"print({label!r})\n", encoding="utf-8")
        script.chmod(0o755)
        dirs[label] = bin_dir

    def order(first: str) -> None:
        second = "program-b" if first == "program-a" else "program-a"
        monkeypatch.setenv("PATH", os.pathsep.join([str(dirs[first]), str(dirs[second])]))

    order("program-a")
    return order


def _run_labtool() -> str:
    resolved = shutil.which("labtool")
    assert resolved is not None
    done = subprocess.run([sys.executable, resolved], capture_output=True, text=True, check=True)
    return done.stdout.strip()


ARGS = {"message": "hello"}


@posix_only
def test_path_reorder_after_mint_denies_at_consume_without_spending(programs):
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=executable_digest("labtool"))
    programs("program-b")
    calls: list[str] = []

    decision, result = gated_invoke(
        _envelope(ARGS, grant.approval_id),
        lambda: calls.append("entered"),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: executable_digest("labtool"),
    )

    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail.endswith("; implementation mismatch")
    assert result is None and calls == []
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


@posix_only
def test_unchanged_implementation_allows_and_runs_the_approved_program(programs):
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=executable_digest("labtool"))
    observer = _Observer(lambda: executable_digest("labtool"))

    decision, result = gated_invoke(
        _envelope(ARGS, grant.approval_id),
        _run_labtool,
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=observer,
    )

    assert decision.verdict == "ALLOW"
    assert result == "program-a"
    assert observer.calls == 2  # once at consume, once at entry
    assert runtime.approvals.lookup(grant.approval_id).consumed()


@posix_only
def test_change_between_admission_and_entry_denies_at_entry_with_grant_spent(programs):
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=executable_digest("labtool"))
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: executable_digest("labtool"),
    )
    assert pending.decision.verdict == "ALLOW"
    programs("program-b")
    calls: list[str] = []

    decision, result = complete_invoke(pending, lambda: calls.append("entered"))

    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail == ENTRY_DETAIL
    assert result is None and calls == []
    assert runtime.approvals.lookup(grant.approval_id).consumed()


FROZEN = _digest(b"implementation at mint")
CHANGED = _digest(b"implementation now")


@pytest.mark.parametrize(
    ("observer", "detail"),
    [
        (None, "no implementation observer"),
        (lambda: (_ for _ in ()).throw(RuntimeError("resolver down")), "implementation observer failed"),
        (lambda: "not-a-digest", "implementation observer failed"),
        (lambda: None, "implementation observer failed"),
        (lambda: CHANGED, "implementation mismatch"),
    ],
    ids=["no-observer", "raises", "non-digest", "none", "different"],
)
def test_consume_failures_deny_without_spending(observer, detail):
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)

    decision = evaluate(
        _envelope(ARGS, grant.approval_id),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=observer,
    )

    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail.endswith(f"; {detail}")
    assert FROZEN not in decision.receipt.reason_detail and CHANGED not in decision.receipt.reason_detail
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_observer_calling_back_into_the_store_is_refused_not_deadlocked():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)

    def reenter():
        runtime.approvals.lookup(grant.approval_id)
        return FROZEN

    out: list = []
    worker = threading.Thread(
        target=lambda: out.append(
            evaluate(
                _envelope(ARGS, grant.approval_id),
                runtime=runtime,
                now=NOW,
                principal=HOST,
                implementation_observer=reenter,
            )
        ),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "observer re-entry deadlocked the approval store"
    (decision,) = out

    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail.endswith("; implementation observer re-entered store")
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_earlier_exits_return_their_own_code_and_never_call_the_observer():
    runtime = _runtime()
    observer = _Observer(lambda: FROZEN)

    def run(envelope, principal=HOST, now=NOW):
        return evaluate(envelope, runtime=runtime, now=now, principal=principal, implementation_observer=observer)

    unknown = run(_envelope(ARGS, "lab.appr.not-issued"))
    assert unknown.receipt.reason_code == ReasonCode.APPROVAL_INVALID

    wrong = _issue(runtime, ARGS, implementation_digest=FROZEN)
    other = run(_envelope(ARGS, wrong.approval_id, identity=OTHER), principal=OTHER)
    assert other.receipt.reason_code == ReasonCode.APPROVAL_PRINCIPAL_MISMATCH

    expiring = _issue(runtime, ARGS, implementation_digest=FROZEN, ttl_seconds=1)
    expired = run(_envelope(ARGS, expiring.approval_id), now=NOW + timedelta(seconds=5))
    assert expired.receipt.reason_code == ReasonCode.APPROVAL_EXPIRED

    bound = _issue(runtime, ARGS, implementation_digest=FROZEN)
    swapped_args = run(_envelope({"message": "other"}, bound.approval_id))
    assert swapped_args.receipt.reason_code == ReasonCode.APPROVAL_BINDING_MISMATCH

    assert observer.calls == 0
    for grant in (wrong, expiring, bound):
        assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_replay_of_a_consumed_bound_grant_is_approval_consumed():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    first = evaluate(
        _envelope(ARGS, grant.approval_id), runtime=runtime, now=NOW, principal=HOST, implementation_observer=lambda: FROZEN
    )
    assert first.verdict == "ALLOW"
    observer = _Observer(lambda: CHANGED)

    replay = evaluate(
        _envelope(ARGS, grant.approval_id), runtime=runtime, now=NOW, principal=HOST, implementation_observer=observer
    )

    assert replay.receipt.reason_code == ReasonCode.APPROVAL_CONSUMED
    assert observer.calls == 0


def test_unbound_grant_never_calls_the_observer():
    runtime = _runtime()
    grant = _issue(runtime, ARGS)
    observer = _Observer(lambda: CHANGED)
    calls: list[str] = []

    decision, _ = gated_invoke(
        _envelope(ARGS, grant.approval_id),
        lambda: calls.append("entered"),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=observer,
    )

    assert decision.verdict == "ALLOW"
    assert calls == ["entered"]
    assert observer.calls == 0


@pytest.mark.parametrize(
    "observed",
    [lambda: (_ for _ in ()).throw(RuntimeError("resolver down")), lambda: "not-a-digest"],
    ids=["raises", "non-digest"],
)
def test_entry_observer_failure_denies_with_grant_spent(observed):
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    answers = iter([lambda: FROZEN, observed])
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: next(answers)(),
    )
    assert pending.decision.verdict == "ALLOW"
    calls: list[str] = []

    decision, result = complete_invoke(pending, lambda: calls.append("entered"))

    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail == ENTRY_DETAIL
    assert result is None and calls == []
    assert runtime.approvals.lookup(grant.approval_id).consumed()


def test_admission_without_an_entry_observer_fails_closed():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id), runtime=runtime, now=NOW, principal=HOST, implementation_observer=lambda: FROZEN
    )
    stripped = dataclasses.replace(pending, implementation_observer=None)
    calls: list[str] = []

    decision, result = complete_invoke(stripped, lambda: calls.append("entered"))

    assert decision.receipt.reason_code == MISMATCH
    assert decision.receipt.reason_detail == ENTRY_DETAIL
    assert result is None and calls == []
    assert runtime.approvals.lookup(grant.approval_id).consumed()


def test_second_complete_is_admission_consumed_without_calling_the_observer():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    answers = iter([FROZEN, FROZEN, CHANGED])
    observer = _Observer(lambda: next(answers))
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id), runtime=runtime, now=NOW, principal=HOST, implementation_observer=observer
    )
    first, ran = complete_invoke(pending, lambda: "entered")
    assert first.verdict == "ALLOW" and ran == "entered"
    assert observer.calls == 2

    second, again = complete_invoke(pending, lambda: "entered again")

    assert second.receipt.reason_code == ReasonCode.ADMISSION_CONSUMED
    assert again is None
    assert observer.calls == 2


def test_implementation_is_checked_before_state_at_entry():
    runtime = _runtime()
    state_at_mint = _digest(b"target at mint")
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN, state_digest=state_at_mint)
    implementation = iter([FROZEN, CHANGED])
    state = iter([state_at_mint, _digest(b"target now")])
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: next(implementation),
        state_observer=lambda: next(state),
    )
    assert pending.decision.verdict == "ALLOW"

    decision, result = complete_invoke(pending, lambda: "entered")

    assert decision.receipt.reason_code == MISMATCH
    assert result is None


def test_kill_between_admission_and_entry_is_the_fence_and_skips_the_entry_observer():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    observer = _Observer(lambda: FROZEN)
    pending = begin_invoke(
        _envelope(ARGS, grant.approval_id), runtime=runtime, now=NOW, principal=HOST, implementation_observer=observer
    )
    assert pending.decision.verdict == "ALLOW"
    assert observer.calls == 1
    runtime.kill()

    decision, result = complete_invoke(pending, lambda: "entered")

    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert result is None
    assert observer.calls == 1


def test_two_threads_consuming_one_bound_grant_get_one_allow():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    barrier = threading.Barrier(2, timeout=5)
    verdicts: list[str] = []

    def worker():
        barrier.wait()
        decision = evaluate(
            _envelope(ARGS, grant.approval_id),
            runtime=runtime,
            now=NOW,
            principal=HOST,
            implementation_observer=lambda: FROZEN,
        )
        verdicts.append(decision.receipt.reason_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not any(thread.is_alive() for thread in threads)

    assert sorted(verdicts) == sorted([ReasonCode.ALLOWED, ReasonCode.APPROVAL_CONSUMED])


@pytest.mark.parametrize("bad", ["sha256:short", "md5:" + "0" * 32, "", 7])
def test_malformed_implementation_digest_is_refused_at_mint(bad):
    with pytest.raises(ApprovalError):
        _issue(_runtime(), ARGS, implementation_digest=bad)


def _lab_envelope(approval_id, **schema_extra):
    schema_fields = {"approval_id": approval_id, "capability_token": None}
    schema_fields.update(schema_extra)
    return {
        "caller": {"identity": HOST},
        "envelope_version": "1.0",
        "invoke": {"tool_name": "echo.ping", "argv": [], "schema_fields": schema_fields},
        "pep_eval_id": "acl-pep-implementation-lab-shape",
    }


def test_lab_envelope_top_level_implementation_digest_is_envelope_invalid():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)
    envelope = {**_lab_envelope(grant.approval_id), "implementation_digest": FROZEN}

    decision = evaluate(envelope, runtime=runtime, now=NOW, principal=HOST)

    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_lab_envelope_schema_field_unknown_key_is_envelope_invalid():
    """Unknown ``schema_fields`` keys are rejected, not dropped and not read."""
    runtime = _runtime()
    grant = _issue(runtime, {"argv": []}, implementation_digest=FROZEN)

    decision = evaluate(
        _lab_envelope(grant.approval_id, implementation_digest=FROZEN), runtime=runtime, now=NOW, principal=HOST
    )

    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID
    assert "implementation_digest" in decision.receipt.reason_detail
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_envelope_cannot_carry_an_implementation_digest():
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=FROZEN)

    decision = evaluate(
        _envelope(ARGS, grant.approval_id, implementation_digest=FROZEN), runtime=runtime, now=NOW, principal=HOST
    )

    assert decision.receipt.reason_code == ReasonCode.ENVELOPE_INVALID
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


@posix_only
def test_swap_after_the_entry_check_is_residual(programs):
    """ADR-0004 check-to-exec race: the tool resolves again after the PEP's check.

    The entry re-observation matches, then the PATH changes inside the tool
    before it resolves ``labtool``, so the other program runs. Only a host that
    executes the artefact it digested, from the same open file descriptor,
    closes this window.
    """
    runtime = _runtime()
    grant = _issue(runtime, ARGS, implementation_digest=executable_digest("labtool"))

    def tool() -> str:
        programs("program-b")
        return _run_labtool()

    decision, result = gated_invoke(
        _envelope(ARGS, grant.approval_id),
        tool,
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: executable_digest("labtool"),
    )

    assert decision.verdict == "ALLOW"
    assert result == "program-b"
