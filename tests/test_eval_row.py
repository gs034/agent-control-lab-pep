# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""One-row 2609.19587-class existence proof. No ASR claim."""

from __future__ import annotations

from pathlib import Path

import yaml

from evals.run import ROW_PATH, load_row, run_row
from pep.evaluate import evaluate
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

REPO = Path(__file__).resolve().parents[1]


def test_eval_row_file_exists_with_todo_slot():
    text = ROW_PATH.read_text(encoding="utf-8")
    assert "2609.19587" in text
    assert "TODO(deep-research)" in text
    assert "79%" in text and "NON-CLAIM" in text
    row = load_row()
    assert row["status"] == "existence_proof_deny_only"
    assert row["todo_deep_research"]["final_attack_wording"] is None
    assert row["todo_deep_research"]["expected_deny_receipt"] is None
    assert row["claim_level"] == "existence_proof_only"


def test_eval_row_denies_without_consulting_prose():
    row = yaml.safe_load(ROW_PATH.read_text(encoding="utf-8"))
    before = DEMO_POLICY.digest
    decision = evaluate(row["fixture"]["envelope"])
    assert decision.verdict == "DENY"
    assert ReasonCode.AGENT_PROSE_REJECTED in decision.receipt.reason_codes
    assert decision.receipt.prose_consulted_as_policy is False
    assert decision.receipt.policy_bytes_unchanged is True
    assert DEMO_POLICY.current_digest() == before
    assert decision.receipt.no_model_call is True
    assert decision.receipt.trust_domain == "pep"


def test_eval_runner_exits_zero():
    assert run_row() == 0
