# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""M1 evaluator corpus: structured envelopes, expected receipts, catalog bound."""

from __future__ import annotations

import pytest

from pep.canonical import sha256_prefixed
from pep.corpus import (
    REQUIRED_DENY_CLASSES,
    corpus_deny_classes,
    evaluate_corpus_row,
    gated_corpus_row,
    list_corpus_rows,
)
from pep.policy import DEMO_POLICY
from pep.receipt import FROZEN_RECEIPT_KEYS, validate_receipt
from pep.row import evaluate_official_row


COMPARE_KEYS = (
    "brand",
    "decision",
    "eval_ref",
    "fail_closed",
    "judge",
    "licence",
    "negative_controls_observed",
    "pep_id",
    "policy_version",
    "reason_code",
    "reason_detail",
    "receipt_type",
    "trust_domain",
)


def test_corpus_covers_required_deny_classes_and_one_allow():
    rows = list_corpus_rows()
    assert REQUIRED_DENY_CLASSES <= corpus_deny_classes()
    assert any(row.expected_decision == "ALLOW" for row in rows)
    assert all(row.expected_decision in ("ALLOW", "DENY") for row in rows)


@pytest.mark.parametrize("row", list_corpus_rows(), ids=lambda r: r.row_id)
def test_corpus_row_matches_expected_receipt(row):
    policy_before = DEMO_POLICY.digest
    invoked = {"n": 0}

    def tool():
        invoked["n"] += 1
        return "ok"

    decision, result = gated_corpus_row(row, tool)
    live = decision.to_dict()
    expected = row.expected_receipt

    assert decision.verdict == row.expected_decision == expected["decision"]
    for key in COMPARE_KEYS:
        assert live[key] == expected[key]
    assert set(live) == FROZEN_RECEIPT_KEYS == set(expected)
    validate_receipt(live)
    validate_receipt(expected)
    assert live["envelope_hash"] == sha256_prefixed(row.envelope) == expected["envelope_hash"]
    assert live["judge"]["path"] == "host_runtime_deterministic"
    assert live["judge"]["llm_cot_transcript_judge"] is False
    assert live["judge"]["agent_prose_used_as_policy"] is False
    assert live["negative_controls_observed"]["monitor_coax_accepted"] is False
    assert live["negative_controls_observed"]["policy_file_unchanged"] is True
    assert live["brand"] == "Agent Control Lab"
    assert live["licence"] == "Apache-2.0"
    assert DEMO_POLICY.current_digest() == policy_before
    assert "shell.exec" not in DEMO_POLICY.allowed_tools()
    if row.expected_decision == "DENY":
        assert result is None
        assert invoked["n"] == 0
        assert live["negative_controls_observed"]["tool_invoke_executed"] is False
    else:
        assert result == "ok"
        assert invoked["n"] == 1


def test_allow_row_cannot_rewrite_catalog():
    rows = [row for row in list_corpus_rows() if row.expected_decision == "ALLOW"]
    assert rows
    row = rows[0]
    rewrite = row.envelope.get("policy_context", {}).get("expected_tool_allowlist", [])
    assert "shell.exec" in rewrite
    decision = evaluate_corpus_row(row)
    assert decision.verdict == "ALLOW"
    assert "shell.exec" not in DEMO_POLICY.allowed_tools()
    assert "lab.catalog.rewrite" not in DEMO_POLICY.allowed_tools()
    assert set(DEMO_POLICY.allowed_tools()) == {"echo.ping"}
    assert DEMO_POLICY.bytes_unchanged()


def test_official_demo_row_still_denies_independently_of_corpus():
    decision, invoked = evaluate_official_row()
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == "TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY"
    assert invoked is False
