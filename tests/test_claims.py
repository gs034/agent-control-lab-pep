# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Claim reconciliation (ADR-0010): the host record is the truth, the claim is data."""

from __future__ import annotations

import hashlib
import json

import pytest

from pep.host.claims import (
    CLAIM_SCHEMA,
    CONSISTENT,
    CONTRADICTED,
    UNVERIFIABLE,
    ClaimError,
    observe_result,
    parse_claim,
    result_digest,
    verify_claim,
)
from pep.host.executor import UnencodableResult

RESULT = {"pong": "hi", "ran": "registry"}
DIGEST = result_digest(RESULT)


def _record(request_id: str, decision: str, tool_name: str = "echo.ping", digest: str | None = DIGEST) -> dict:
    checks = [{"name": "registry_tool", "outcome": "entered"}]
    if decision == "ALLOW":
        if digest is None:
            checks.append({"name": "result", "outcome": "unencodable"})
        else:
            checks.append({"name": "result", "outcome": "returned", "digest": digest})
    return {"decision": decision, "request_id": request_id, "tool_name": tool_name, "checks": checks}


def _action(request_id: str = "host.1.2", outcome: str = "allowed", digest: str | None = DIGEST, tool: str = "echo.ping"):
    return parse_claim(
        {
            "schema": CLAIM_SCHEMA,
            "kind": "action",
            "request_id": request_id,
            "tool_name": tool,
            "outcome": outcome,
            "result_digest": digest,
        }
    )


def test_result_digest_is_canonical_sha256():
    canonical = json.dumps(RESULT, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert DIGEST == "sha256:" + hashlib.sha256(canonical.encode("ascii")).hexdigest()
    # Key order and whitespace in the producer do not change the digest.
    assert result_digest({"ran": "registry", "pong": "hi"}) == DIGEST
    assert result_digest({"pong": "hi", "ran": "registry "}) != DIGEST


def test_observe_result_digests_json_and_marks_the_rest_unencodable():
    seen = observe_result(RESULT)
    assert seen.check == {"name": "result", "outcome": "returned", "digest": DIGEST}
    assert seen.parsed == RESULT
    for bad in (UnencodableResult(), {"x": object()}, {1: {2: {3: object()}}}):
        unseen = observe_result(bad)
        assert unseen.check == {"name": "result", "outcome": "unencodable"}
        assert unseen.digest is None
        assert unseen.parsed is None


@pytest.mark.parametrize(
    "raw, message",
    [
        ("not an object", "not an object"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "allowed", "extra": 1}, "unknown keys"),
        ({"schema": "other", "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "allowed"}, "schema"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "", "outcome": "allowed"}, "tool_name"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": None, "tool_name": "t", "outcome": "allowed"}, "request_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "succeeded"}, "allowed or denied"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "denied", "result_digest": DIGEST}, "no result"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "allowed", "result_digest": "abc"}, "sha256"),
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "allowed"}, "not_called"),
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "not_called", "request_id": "r"}, "no request_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "belief", "tool_name": "t", "outcome": "allowed"}, "action or absence"),
    ],
)
def test_malformed_claims_are_refused_not_widened(raw, message):
    with pytest.raises(ClaimError, match=message):
        parse_claim(raw)


def test_consistent_action_claim():
    verdict = verify_claim(_action(), [_record("host.1.1", "PRE_ENTRY"), _record("host.1.2", "ALLOW")])
    assert verdict.verdict == CONSISTENT
    verdict = verify_claim(_action(digest=None), [_record("host.1.2", "ALLOW")])
    assert verdict.verdict == CONSISTENT


def test_action_claim_contradicted_on_each_field_in_order():
    records = [_record("host.1.2", "ALLOW")]
    wrong_tool = verify_claim(_action(tool="file.write"), records)
    assert (wrong_tool.verdict, wrong_tool.field) == (CONTRADICTED, "tool_name")
    wrong_outcome = verify_claim(_action(outcome="denied", digest=None), records)
    assert (wrong_outcome.verdict, wrong_outcome.field) == (CONTRADICTED, "outcome")
    wrong_digest = verify_claim(_action(digest=result_digest({"pong": "forged"})), records)
    assert (wrong_digest.verdict, wrong_digest.field) == (CONTRADICTED, "result_digest")
    claimed_allowed_but_denied = verify_claim(_action(digest=None), [_record("host.1.2", "DENY")])
    assert (claimed_allowed_but_denied.verdict, claimed_allowed_but_denied.field) == (CONTRADICTED, "outcome")


def test_a_digest_claimed_for_an_unencodable_result_is_contradicted():
    verdict = verify_claim(_action(), [_record("host.1.2", "ALLOW", digest=None)])
    assert (verdict.verdict, verdict.field) == (CONTRADICTED, "result_digest")


def test_unverifiable_is_not_consistent():
    missing = verify_claim(_action(), [_record("host.1.9", "ALLOW")])
    assert (missing.verdict, missing.field) == (UNVERIFIABLE, "request_id")
    pre_entry_only = verify_claim(_action(), [_record("host.1.2", "PRE_ENTRY")])
    assert pre_entry_only.verdict == UNVERIFIABLE
    shortened = {"decision": "ALLOW", "request_id": "host.1.2", "tool_name": "echo.ping",
                 "checks": [{"name": "result", "outcome": "returned"}]}
    assert verify_claim(_action(), [shortened]).verdict == UNVERIFIABLE
    no_observation = {"decision": "ALLOW", "request_id": "host.1.2", "tool_name": "echo.ping", "checks": []}
    assert verify_claim(_action(), [no_observation]).verdict == UNVERIFIABLE


def test_absence_claim_is_contradicted_by_any_allow_for_that_tool():
    claim = parse_claim({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "echo.ping", "outcome": "not_called"})
    assert verify_claim(claim, [_record("host.1.2", "DENY")]).verdict == CONSISTENT
    assert verify_claim(claim, [_record("host.1.2", "ALLOW", tool_name="file.read")]).verdict == CONSISTENT
    hit = verify_claim(claim, [_record("host.1.2", "DENY"), _record("host.1.3", "ALLOW")])
    assert (hit.verdict, hit.field) == (CONTRADICTED, "tool_name")
    assert "host.1.3" in hit.detail
