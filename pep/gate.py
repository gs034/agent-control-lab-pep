# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Invoke gate: DENY means the tool function is never called.

``begin_invoke`` admits a structured envelope (no tool entry). ``complete_invoke``
enters the tool only after ``PepRuntime.claim_entry`` records a one-shot permit
under the runtime lock. ``kill()`` cuts the runtime and refuses new permits, so
a queued or callback completion after the cut is DENY ``late_effect_fence``.
A second complete on the same admission is DENY ``admission_consumed``.

Once ``tool()`` has been called, kill does not preempt that call.
``gated_invoke`` is begin then complete with no yield in between.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar

from pep.approval import state_matches
from pep.evaluate import Decision, PepRuntime, evaluate, resolve_runtime, supersede
from pep.reasons import ReasonCode

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PendingInvoke:
    """In-process admission bound to one cut epoch and one ticket id.

    Holding this object does not authorize tool entry. ``complete_invoke``
    claims a one-shot permit. Callers that invoke a tool without this gate
    are outside the PEP trust domain.
    """

    decision: Decision
    admitted_epoch: int
    runtime: PepRuntime
    admission_id: int
    state_observer: Callable[[], object] | None = None


def begin_invoke(
    envelope: object,
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
    state_observer: Callable[[], object] | None = None,
) -> PendingInvoke:
    """Admit one invoke. Does not call a tool.

    The returned epoch is the cut generation observed before evaluation.
    A later ``kill()`` makes ``complete_invoke`` fail closed. ``state_observer``
    is passed to ``evaluate`` and kept on the admission so ``complete_invoke``
    can re-observe the target at tool entry.
    """
    pep = resolve_runtime(runtime)
    admission_id = pep.mint_admission_id()
    admitted_epoch = pep.fence_epoch
    decision = evaluate(envelope, runtime=pep, now=now, state_observer=state_observer)
    return PendingInvoke(
        decision=decision,
        admitted_epoch=admitted_epoch,
        runtime=pep,
        admission_id=admission_id,
        state_observer=state_observer,
    )


def complete_invoke(
    pending: PendingInvoke,
    tool: Callable[..., T],
    *,
    _before_commit: Callable[[], None] | None = None,
) -> tuple[Decision, T | None]:
    """Enter ``tool`` only with a one-shot permit recorded before the call.

    The permit and the fence check are one locked transition on the runtime.
    After ``kill()``, a pre-cut admission returns DENY ``late_effect_fence``
    (cut+fence) and does not call ``tool``. A second complete returns DENY
    ``admission_consumed``. A decision that is already DENY is returned
    unchanged, so a fresh post-kill evaluate stays ``kill_active``.

    When the admission consumed a grant with a frozen state digest and an
    observer was given, the target is re-observed here, after a fence read and
    before the permit is claimed; a change is DENY ``approval_state_mismatch``
    with the grant already spent. A cut seen by the fence read denies first and
    skips the observer. ``_before_commit`` is a yield before that locked transition (tests use it
    to cut in the old check-then-call gap). It is not a permit. The runtime
    re-checks under the lock after it returns. Once ``tool()`` has started,
    this gate does not preempt it.
    """
    decision = pending.decision
    if not decision.allowed():
        return decision, None
    # Fence first: no host read after the cut, and kill keeps precedence over a
    # state mismatch. claim_entry re-decides under the lock below.
    cut = pending.runtime.entry_blocked(pending.admitted_epoch)
    if cut is not None:
        return supersede(decision, cut), None
    if not _state_still_matches(pending):
        # The grant was consumed at admission; a changed target at entry is a
        # fail-closed deny with the grant spent, like a suspend after consume.
        return supersede(decision, ReasonCode.APPROVAL_STATE_MISMATCH), None
    blocked = pending.runtime.claim_entry(
        pending.admission_id,
        pending.admitted_epoch,
        _before_commit=_before_commit,
    )
    if blocked is not None:
        return supersede(decision, blocked), None
    # One-shot ticket was spent in claim_entry before this call. Replay denies.
    return decision, tool()


def _state_still_matches(pending: PendingInvoke) -> bool:
    """Re-observe the target at entry when the admission consumed a frozen digest.

    Without an observer there is nothing to re-read and the admission-time
    check stands. A raising observer is a mismatch.
    """
    frozen = pending.decision.frozen_state_digest
    if frozen is None or pending.state_observer is None:
        return True
    try:
        observed = pending.state_observer()
    except Exception:
        return False
    return state_matches(frozen, observed)


def gated_invoke(
    envelope: object,
    tool: Callable[..., T],
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
    state_observer: Callable[[], object] | None = None,
) -> tuple[Decision, T | None]:
    """Run ``tool`` only after ``evaluate`` returns ALLOW and the fence is open.

    On DENY the callable is not entered. Callers that bypass this helper
    are outside the PEP trust domain. ``state_observer`` is passed through
    to ``evaluate``.
    """
    pending = begin_invoke(envelope, runtime=runtime, now=now, state_observer=state_observer)
    return complete_invoke(pending, tool)
