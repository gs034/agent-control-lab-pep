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
    bind_claim_session,
    parse_claim,
    result_digest,
    verify_claim,
    verify_connected_claim,
)
from pep.host.executor import UnencodableResult

RESULT = {"pong": "hi", "ran": "registry"}
DIGEST = result_digest(RESULT)


def _record(request_id: str, decision: str, tool_name: str = "echo.ping", digest: str | None = DIGEST) -> dict:
    checks: list[dict[str, str]] = []
    if decision == "ALLOW":
        checks.append({"name": "registry_tool", "outcome": "entered"})
        if digest is None:
            checks.append({"name": "result", "outcome": "unencodable"})
        else:
            checks.append({"name": "result", "outcome": "returned", "digest": digest})
    elif decision == "DENY":
        # A refusal before PRE_ENTRY. It does not show that the tool was called.
        checks.append({"name": "evaluate", "outcome": "deny"})
    return {"decision": decision, "request_id": request_id, "tool_name": tool_name, "checks": checks}


def _absence(tool: str = "echo.ping", session: str = "u1.c1"):
    return parse_claim(
        {
            "schema": CLAIM_SCHEMA,
            "kind": "absence",
            "tool_name": tool,
            "outcome": "not_called",
            "session_id": session,
        }
    )


def _pre_entry(request_id: str, tool: str = "echo.ping") -> dict:
    return {
        "decision": "PRE_ENTRY",
        "reason_code": "ok",
        "reason_detail": "checks recorded; tool not entered yet",
        "request_id": request_id,
        "tool_name": tool,
        "checks": [{"name": "evaluate", "outcome": "allow"}],
    }


def _tool_failed(request_id: str, detail: str, tool: str = "echo.ping") -> dict:
    """The DENY written after PRE_ENTRY when the tool does not return a result."""
    return {
        "decision": "DENY",
        "reason_code": "tool_failed",
        "reason_detail": detail,
        "request_id": request_id,
        "tool_name": tool,
        "checks": [{"name": "registry_tool", "outcome": "raised"}],
    }


def _marker(decision: str, session: str, seq: int) -> dict:
    return {
        "decision": decision,
        "reason_code": "session_open" if decision == "SESSION_OPEN" else "session_close",
        "request_id": f"{session}.{decision}",
        "session_id": session,
        "seq": seq,
        "checks": [],
    }


def _bounded(middle: list[dict], session: str = "u1.c1") -> list[dict]:
    """One session, seq 1 through N, open at the start and close at the end."""
    records = [_marker("SESSION_OPEN", session, 1)]
    for index, record in enumerate(middle, start=2):
        item = dict(record)
        item["seq"] = index
        item["session_id"] = session
        records.append(item)
    records.append(_marker("SESSION_CLOSE", session, len(records) + 1))
    return records


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


def test_nan_result_is_unencodable():
    """NaN is not JSON. allow_nan false makes the round-trip fail closed."""
    for bad in (float("nan"), {"value": float("nan")}, [float("inf")], {"value": float("-inf")}):
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
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "not_called"}, "session_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "not_called", "session_id": ""}, "session_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "not_called", "session_id": None}, "session_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "absence", "tool_name": "t", "outcome": "not_called", "session_id": 1}, "session_id"),
        ({"schema": CLAIM_SCHEMA, "kind": "action", "request_id": "r", "tool_name": "t", "outcome": "allowed", "session_id": "u1.c1"}, "no session_id"),
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
    claim = _absence()
    hit = verify_claim(claim, _bounded([_record("host.1.2", "DENY"), _record("host.1.3", "ALLOW")]))
    assert (hit.verdict, hit.field) == (CONTRADICTED, "tool_name")
    assert "host.1.3" in hit.detail


def test_absence_is_consistent_only_inside_a_complete_session():
    """Another tool's line, or a refusal before entry, proves nothing alone.

    Consistent needs the session open and the session close, and every seq
    between them. Dropping a line leaves a gap.
    """
    claim = _absence()
    other = _record("host.1.2", "ALLOW", tool_name="file.read")
    other["seq"] = 1
    other["session_id"] = "u1.c1"
    refusal = _record("host.1.2", "DENY")
    refusal["seq"] = 1
    refusal["session_id"] = "u1.c1"
    assert verify_claim(claim, [other]).verdict == UNVERIFIABLE
    assert verify_claim(claim, [refusal]).verdict == UNVERIFIABLE
    assert verify_claim(claim, []).verdict == UNVERIFIABLE

    bounded_other = _bounded([_record("host.1.2", "ALLOW", tool_name="file.read")])
    assert verify_claim(claim, bounded_other).verdict == CONSISTENT
    # A DENY before PRE_ENTRY is a refusal, not a call, once the session is closed.
    bounded_refusal = _bounded([_record("host.1.2", "DENY")])
    assert verify_claim(claim, bounded_refusal).verdict == CONSISTENT

    gapped = [bounded_other[0], bounded_other[-1]]
    assert verify_claim(claim, gapped).verdict == UNVERIFIABLE
    opened = bounded_other[:-1]
    assert verify_claim(claim, opened).verdict == UNVERIFIABLE
    closed = bounded_other[1:]
    assert verify_claim(claim, closed).verdict == UNVERIFIABLE


def test_absence_checks_only_the_named_sessions_span():
    """A finished other session is not this claim. A neighbor's call is not either.

    Seq from this session's open through its close must all be present.
    Dropping the neighbor's line leaves a gap.
    """
    claim = _absence(session="u1.c1")
    other_session = _bounded([_record("host.9.1", "ALLOW")], session="u2.c2")
    assert verify_claim(claim, other_session).verdict == UNVERIFIABLE

    neighbors_call = _record("host.2.3", "ALLOW")
    neighbors_call["session_id"] = "u2.c2"
    neighbors_call["seq"] = 3
    interleaved = [
        _marker("SESSION_OPEN", "u1.c1", 1),
        _marker("SESSION_OPEN", "u2.c2", 2),
        neighbors_call,
        _marker("SESSION_CLOSE", "u2.c2", 4),
        _marker("SESSION_CLOSE", "u1.c1", 5),
    ]
    assert verify_claim(claim, interleaved).verdict == CONSISTENT
    assert verify_claim(_absence(session="u2.c2"), interleaved).verdict == CONTRADICTED
    gapped = [record for record in interleaved if record["seq"] != 3]
    assert verify_claim(claim, gapped).verdict == UNVERIFIABLE


def test_absence_entered_then_raised_is_contradicted():
    """PRE_ENTRY admits the call. A later DENY tool_failed with raised means it did not return."""
    claim = _absence()
    records = _bounded([_pre_entry("host.4.1"), _tool_failed("host.4.1", "host tool raised after entry")])
    verdict = verify_claim(claim, records)
    assert (verdict.verdict, verdict.field) == (CONTRADICTED, "tool_name")
    assert "host.4.1" in verdict.detail
    # The same admission outside a session span does not settle the claim.
    assert verify_claim(claim, [_pre_entry("host.4.2")]).verdict == UNVERIFIABLE
    entered = {
        "decision": "DENY",
        "reason_code": "kill_active",
        "request_id": "host.4.3",
        "tool_name": "echo.ping",
        "checks": [{"name": "registry_tool", "outcome": "entered"}],
    }
    assert verify_claim(claim, _bounded([entered])).verdict == CONTRADICTED


def test_absence_timeout_is_contradicted():
    claim = _absence()
    records = _bounded([_pre_entry("host.5.1"), _tool_failed("host.5.1", "host tool timed out")])
    assert verify_claim(claim, records).verdict == CONTRADICTED
    # Clipping can drop the raised check and still keep reason_code tool_failed.
    clipped = {
        "decision": "DENY",
        "reason_code": "tool_failed",
        "reason_detail": "host tool timed out",
        "request_id": "host.5.2",
        "tool_name": "echo.ping",
    }
    assert verify_claim(claim, _bounded([clipped])).verdict == CONTRADICTED


def test_absence_frame_cap_is_contradicted():
    claim = _absence()
    records = _bounded(
        [
            _pre_entry("host.6.1"),
            _tool_failed("host.6.1", "host tool reply exceeded the executor frame limit"),
        ]
    )
    assert verify_claim(claim, records).verdict == CONTRADICTED
    # A raise recorded only as the check, with no tool_failed reason, is still a call.
    raised = {
        "decision": "DENY",
        "reason_code": "kill_active",
        "request_id": "host.6.2",
        "tool_name": "echo.ping",
        "checks": [{"name": "registry_tool", "outcome": "raised"}],
    }
    assert verify_claim(claim, _bounded([raised])).verdict == CONTRADICTED


def test_absence_with_no_records_is_unverifiable():
    verdict = verify_claim(_absence(), [])
    assert (verdict.verdict, verdict.field) == (UNVERIFIABLE, "session_id")
    assert verdict.verdict != CONSISTENT


def test_duplicate_final_records_do_not_let_the_last_win():
    """ALLOW then DENY for one request_id disagree. The later line does not win.

    The disagreement on the decision is unverifiable. A record that names a
    different tool, or an ALLOW whose digest differs, contradicts the claim.
    """
    allowed = _record("r1", "ALLOW")
    denied = _record("r1", "DENY")
    for outcome, digest in (("allowed", DIGEST), ("denied", None)):
        verdict = verify_claim(_action(request_id="r1", outcome=outcome, digest=digest), [allowed, denied])
        assert (verdict.verdict, verdict.field) == (UNVERIFIABLE, "request_id")
        assert verdict.verdict != CONSISTENT
    other_tool = _record("r1", "ALLOW", tool_name="file.write")
    wrong_tool = verify_claim(_action(request_id="r1", outcome="denied", digest=None), [other_tool, denied])
    assert (wrong_tool.verdict, wrong_tool.field) == (CONTRADICTED, "tool_name")
    forged = _record("r1", "ALLOW", digest=result_digest({"pong": "forged"}))
    wrong_digest = verify_claim(_action(request_id="r1"), [forged, denied])
    assert (wrong_digest.verdict, wrong_digest.field) == (CONTRADICTED, "result_digest")
    # Agreeing finals still match. The last line is not a special case.
    assert verify_claim(_action(request_id="r1"), [allowed, _record("r1", "ALLOW")]).verdict == CONSISTENT


def _span(session: str, start: int, middle: list[dict]) -> list[dict]:
    """One session's open-to-close range, with seq starting at ``start``."""
    records = [_marker("SESSION_OPEN", session, start)]
    seq = start + 1
    for record in middle:
        item = dict(record)
        item["seq"] = seq
        item["session_id"] = session
        records.append(item)
        seq += 1
    records.append(_marker("SESSION_CLOSE", session, seq))
    return records


def _not_called(session: str, tool: str = "echo.ping") -> dict:
    return {
        "schema": CLAIM_SCHEMA,
        "kind": "absence",
        "tool_name": tool,
        "outcome": "not_called",
        "session_id": session,
    }


def test_bind_claim_session_overwrites_the_body():
    """The helper replaces the body's session_id and does not edit the original."""
    raw = _not_called("u2.c2")
    bound = bind_claim_session(raw, "u1.c1")
    assert bound["session_id"] == "u1.c1"
    assert raw["session_id"] == "u2.c2"
    assert parse_claim(bound).session_id == "u1.c1"
    missing = dict(raw)
    del missing["session_id"]
    assert bind_claim_session(missing, "u1.c1")["session_id"] == "u1.c1"
    action = {
        "schema": CLAIM_SCHEMA,
        "kind": "action",
        "request_id": "host.1.2",
        "tool_name": "echo.ping",
        "outcome": "allowed",
        "session_id": "u2.c2",
    }
    stripped = bind_claim_session(action, "u1.c1")
    assert "session_id" not in stripped
    assert action["session_id"] == "u2.c2"
    assert parse_claim(stripped).session_id is None
    with pytest.raises(ClaimError, match="session principal"):
        bind_claim_session(raw, "")


def test_agent_facing_absence_claim_is_bound_to_the_connection():
    """A tool ran on s1. The agent names idle s2. The connection forces s1.

    The same body checked offline, as an already attested claim, still
    trusts s2 and is consistent. An honest body that already names s1 is
    contradicted too.
    """
    caller = "u1.c1"
    idle = "u2.c2"
    records = _span(caller, 1, [_record("host.1.2", "ALLOW")]) + _span(idle, 10, [])
    forged = _not_called(idle)
    honest = _not_called(caller)
    forced = verify_connected_claim(forged, caller, records)
    assert (forced.verdict, forced.field) == (CONTRADICTED, "tool_name")
    assert forged["session_id"] == idle
    assert verify_connected_claim(honest, caller, records).verdict == CONTRADICTED
    # Offline attested check: the body session stands.
    assert verify_claim(parse_claim(forged), records).verdict == CONSISTENT
    assert verify_claim(parse_claim(honest), records).verdict == CONTRADICTED
