# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Invoke gate: DENY means the tool function is never called.

``begin_invoke`` admits a structured envelope (no tool entry). ``complete_invoke``
enters the tool only if that admission is still open. ``kill()`` cuts the
runtime and engages a late-effect fence, so a queued or callback completion
after the cut is DENY ``late_effect_fence`` and does not enter the tool.
``gated_invoke`` is begin then complete with no yield in between.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar

from pep.evaluate import Decision, PepRuntime, evaluate, resolve_runtime, supersede

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PendingInvoke:
    """In-process admission bound to the cut epoch at ``begin_invoke``.

    Holding this object does not authorize tool entry. ``complete_invoke``
    re-checks the fence. Callers that invoke a tool without this gate are
    outside the PEP trust domain.
    """

    decision: Decision
    admitted_epoch: int
    runtime: PepRuntime


def begin_invoke(
    envelope: object,
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
) -> PendingInvoke:
    """Admit one invoke. Does not call a tool.

    The returned epoch is the cut generation observed before evaluation.
    A later ``kill()`` makes ``complete_invoke`` fail closed.
    """
    pep = resolve_runtime(runtime)
    admitted_epoch = pep.fence_epoch
    decision = evaluate(envelope, runtime=pep, now=now)
    return PendingInvoke(decision=decision, admitted_epoch=admitted_epoch, runtime=pep)


def complete_invoke(pending: PendingInvoke, tool: Callable[..., T]) -> tuple[Decision, T | None]:
    """Enter ``tool`` only if the admission is still open.

    After ``kill()``, a pre-cut admission returns DENY ``late_effect_fence``
    (cut+fence) and does not call ``tool``. A decision that is already DENY
    is returned unchanged, so a fresh post-kill evaluate stays ``kill_active``.
    """
    decision = pending.decision
    if not decision.allowed():
        return decision, None
    blocked = pending.runtime.completion_block(pending.admitted_epoch)
    if blocked is not None:
        return supersede(decision, blocked), None
    return decision, tool()


def gated_invoke(
    envelope: object,
    tool: Callable[..., T],
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
) -> tuple[Decision, T | None]:
    """Run ``tool`` only after ``evaluate`` returns ALLOW and the fence is open.

    On DENY the callable is not entered. Callers that bypass this helper
    are outside the PEP trust domain.
    """
    pending = begin_invoke(envelope, runtime=runtime, now=now)
    return complete_invoke(pending, tool)
