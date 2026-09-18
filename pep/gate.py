# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Invoke gate: DENY means the tool function is never called."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from datetime import datetime

from pep.evaluate import Decision, PepRuntime, evaluate

T = TypeVar("T")


def gated_invoke(
    envelope: Any,
    tool: Callable[..., T],
    runtime: PepRuntime | None = None,
    *,
    now: datetime | None = None,
) -> tuple[Decision, T | None]:
    """Run ``tool`` only after ``evaluate`` returns ALLOW.

    On DENY the callable is not entered. Callers that bypass this helper
    are outside the PEP trust domain.
    """
    decision = evaluate(envelope, runtime=runtime, now=now)
    if not decision.allowed():
        return decision, None
    return decision, tool()
