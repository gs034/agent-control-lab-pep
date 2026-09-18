# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent Control Lab reference host/runtime PEP (Policy Enforcement Point).

This package is the PEP trust domain. It is not an agent, not a monitor,
and not an LLM/CoT/transcript judge. There are no model calls on the
evaluate path.
"""

from pep.envelope import InvokeEnvelope
from pep.evaluate import Decision, PepRuntime, evaluate
from pep.gate import gated_invoke
from pep.reasons import ReasonCode
from pep.receipt import Receipt
from pep.row import evaluate_official_row

__all__ = [
    "Decision",
    "InvokeEnvelope",
    "PepRuntime",
    "ReasonCode",
    "Receipt",
    "evaluate",
    "evaluate_official_row",
    "gated_invoke",
]

__version__ = "0.1.0"
