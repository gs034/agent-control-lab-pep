# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent Control Lab reference host/runtime PEP (Policy Enforcement Point).

This package is the PEP trust domain. It is not an agent, not a monitor,
and not an LLM/CoT/transcript judge. There are no model calls on the
evaluate path.
"""

from pep.approval import ApprovalRecord, ApprovalStore
from pep.envelope import InvokeEnvelope
from pep.evaluate import Decision, PepRuntime, RuntimeMode, evaluate
from pep.gate import gated_invoke
from pep.halt import HaltState, HaltStore
from pep.reasons import ReasonCode
from pep.receipt import Receipt, validate_receipt
from pep.row import evaluate_official_row

__all__ = [
    "ApprovalRecord",
    "ApprovalStore",
    "Decision",
    "HaltState",
    "HaltStore",
    "InvokeEnvelope",
    "PepRuntime",
    "ReasonCode",
    "Receipt",
    "RuntimeMode",
    "evaluate",
    "evaluate_official_row",
    "gated_invoke",
    "validate_receipt",
]

__version__ = "0.3.0"
