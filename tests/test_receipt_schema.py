# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Frozen v1 receipt schema: official example and live decisions validate."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from pep.evaluate import evaluate
from pep.receipt import (
    FROZEN_RECEIPT_KEYS,
    RECEIPT_SCHEMA_VERSION,
    ReceiptSchemaError,
    issue_receipt,
    validate_receipt,
)
from pep.reasons import ReasonCode
from pep.row import eval_dir, load_expected_deny_receipt, load_structured_envelope


def test_receipt_schema_version_is_frozen_v1():
    assert RECEIPT_SCHEMA_VERSION == "1"


def test_schema_file_keys_match_frozen_constants():
    path = eval_dir() / "receipt.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    assert set(schema["required"]) == FROZEN_RECEIPT_KEYS
    assert set(schema["properties"]) == FROZEN_RECEIPT_KEYS
    assert schema["additionalProperties"] is False


def test_expected_deny_receipt_matches_frozen_schema():
    expected = load_expected_deny_receipt()
    validate_receipt(expected)
    assert set(expected) == FROZEN_RECEIPT_KEYS


def test_live_official_deny_matches_frozen_schema():
    live = evaluate(load_structured_envelope()).to_dict()
    validate_receipt(live)
    assert set(live) == FROZEN_RECEIPT_KEYS
    assert live["decision"] == "DENY"


def test_live_allow_matches_frozen_schema():
    live = evaluate(
        {
            "tool_name": "echo.ping",
            "args": {"message": "hello"},
            "capability_token": "lab.cap.echo.demo",
            "caller_identity": "lab.demo.agent",
            "request_id": "test-receipt-allow",
        }
    ).to_dict()
    validate_receipt(live)
    assert live["decision"] == "ALLOW"
    assert live["receipt_type"] == "pep_allow"
    assert set(live) == FROZEN_RECEIPT_KEYS


def test_extra_top_level_key_is_rejected():
    payload = deepcopy(load_expected_deny_receipt())
    payload["sku"] = "not-a-grant"
    with pytest.raises(ReceiptSchemaError):
        validate_receipt(payload)


def test_missing_key_is_rejected():
    payload = deepcopy(load_expected_deny_receipt())
    del payload["reason_code"]
    with pytest.raises(ReceiptSchemaError):
        validate_receipt(payload)


def test_issue_receipt_emits_only_frozen_keys():
    receipt = issue_receipt(
        decision="DENY",
        reason_code=ReasonCode.KILL_ACTIVE,
        reason_detail="halt",
        envelope_hash="sha256:" + ("ab" * 32),
        policy_file_unchanged=True,
    )
    assert set(receipt.to_dict()) == FROZEN_RECEIPT_KEYS


def test_schema_file_is_lab_branded():
    text = Path(eval_dir() / "receipt.schema.json").read_text(encoding="utf-8")
    assert "Agent Control Lab" in text
    assert "Apache-2.0" in text
