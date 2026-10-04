# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0003: standing capability tokens bound to host-attested principals.

Each test is a row of the ADR-0003 acceptance table, run against a custom
policy document so holder-only cases (uncovered tool, required-capability
mismatch, malformed expiry) are reachable. The principal is passed by the
host, never read from the envelope.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pep.evaluate import PepRuntime, evaluate
from pep.policy import PolicyStore
from pep.reasons import ReasonCode

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
OWNER = "lab.demo.agent"
OTHER = "lab.other.agent"
UNIFORM = "capability token not valid for this caller"

_ARGS_SCHEMA = {
    "type": "object",
    "properties": {"message": {"type": "string"}},
    "additionalProperties": False,
}
_FUTURE = "2099-01-01T00:00:00+00:00"


def _token(tools, *, principals=(OWNER,), expires_at=_FUTURE, **extra):
    record = {"tools": list(tools), "expires_at": expires_at, **extra}
    if principals is not None:
        record["principals"] = list(principals) if isinstance(principals, tuple) else principals
    return record


POLICY_DOC = {
    "policy_id": "lab.pep.test.adr0003",
    "policy_version": "test",
    "fail_closed": True,
    "allowed_tools": {
        "echo.ping": {"required_capability": "lab.cap.echo.demo", "args_schema": _ARGS_SCHEMA},
        "echo.other": {"required_capability": "lab.cap.other", "args_schema": _ARGS_SCHEMA},
        "echo.legacy": {"required_capability": "lab.cap.legacy", "args_schema": _ARGS_SCHEMA},
    },
    "capability_tokens": {
        "lab.cap.echo.demo": _token(["echo.ping"]),
        "lab.cap.echo.expired": _token(["echo.ping"], expires_at="2020-01-01T00:00:00+00:00"),
        "lab.cap.other": _token(["echo.other"]),
        "lab.cap.both": _token(["echo.ping", "echo.other"]),
        "lab.cap.badexp": _token(["echo.ping"], expires_at="not-a-date"),
        "lab.cap.p.empty": _token(["echo.ping"], principals=[]),
        "lab.cap.p.string": _token(["echo.ping"], principals=OWNER),
        "lab.cap.p.bad": _token(["echo.ping"], principals=["Bad Id"]),
        "lab.cap.p.int": _token(["echo.ping"], principals=[7]),
        "lab.cap.legacy": _token(["echo.legacy"], principals=None),
    },
}
POLICY = PolicyStore.from_document(POLICY_DOC)


def _runtime() -> PepRuntime:
    return PepRuntime(policy=POLICY)


def _envelope(token: str, *, tool: str = "echo.ping", identity: str = OWNER, approval_id=None) -> dict:
    return {
        "tool_name": tool,
        "args": {"message": "hello"},
        "capability_token": token,
        "caller_identity": identity,
        "request_id": "test-capability-principal",
        "approval_id": approval_id,
    }


def _run(envelope: dict, *, principal=OWNER, runtime=None):
    return evaluate(envelope, runtime=runtime or _runtime(), now=NOW, principal=principal)


def _assert_uniform(decision, token: str) -> None:
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    detail = decision.receipt.reason_detail
    assert detail == UNIFORM
    assert OWNER not in detail and OTHER not in detail and token not in detail


def test_listed_holder_with_valid_token_allows():
    decision = _run(_envelope("lab.cap.echo.demo"))
    assert decision.verdict == "ALLOW"


def test_no_attested_principal_denies_with_its_own_detail():
    decision = _run(_envelope("lab.cap.echo.demo"), principal=None)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    assert decision.receipt.reason_detail == "no attested principal"


def test_unlisted_principal_gets_the_uniform_detail():
    _assert_uniform(_run(_envelope("lab.cap.echo.demo", identity=OTHER), principal=OTHER), "lab.cap.echo.demo")


def test_envelope_identity_disagreeing_with_host_gets_the_uniform_detail():
    _assert_uniform(_run(_envelope("lab.cap.echo.demo", identity=OTHER)), "lab.cap.echo.demo")


def test_non_holder_learns_nothing_about_token_state():
    """Expired, uncovered, malformed-expiry and mismatched tokens look the same to a non-holder."""
    for token in ("lab.cap.echo.expired", "lab.cap.other", "lab.cap.badexp", "lab.cap.both"):
        _assert_uniform(_run(_envelope(token, identity=OTHER), principal=OTHER), token)


def test_holder_still_gets_specific_details():
    expired = _run(_envelope("lab.cap.echo.expired"))
    assert expired.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    assert expired.receipt.reason_detail == "capability token expired"

    uncovered = _run(_envelope("lab.cap.other"))
    assert uncovered.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    assert uncovered.receipt.reason_detail == "capability token does not cover tool"

    malformed = _run(_envelope("lab.cap.badexp"))
    assert malformed.receipt.reason_code == ReasonCode.CAPABILITY_MISSING
    assert malformed.receipt.reason_detail == "capability expiry unparseable; fail-closed"

    mismatched = _run(_envelope("lab.cap.both"))
    assert mismatched.receipt.reason_code == ReasonCode.POLICY_MISS


def test_malformed_principals_authorise_nobody():
    for token in ("lab.cap.p.empty", "lab.cap.p.string", "lab.cap.p.bad", "lab.cap.p.int"):
        _assert_uniform(_run(_envelope(token)), token)


def test_non_holder_token_with_valid_approval_denies_and_keeps_the_approval():
    runtime = _runtime()
    grant = runtime.issue_approval(
        tool_name="echo.ping", args={"message": "hello"}, ttl_seconds=60, now=NOW, principal=OTHER
    )
    decision = _run(
        _envelope("lab.cap.echo.demo", identity=OTHER, approval_id=grant.approval_id),
        principal=OTHER,
        runtime=runtime,
    )
    _assert_uniform(decision, "lab.cap.echo.demo")
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_holder_token_with_approval_of_another_principal_is_approval_mismatch():
    runtime = _runtime()
    grant = runtime.issue_approval(
        tool_name="echo.ping", args={"message": "hello"}, ttl_seconds=60, now=NOW, principal=OTHER
    )
    decision = _run(_envelope("lab.cap.echo.demo", approval_id=grant.approval_id), runtime=runtime)
    assert decision.receipt.reason_code == ReasonCode.APPROVAL_PRINCIPAL_MISMATCH
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_holder_token_with_own_approval_allows():
    runtime = _runtime()
    grant = runtime.issue_approval(
        tool_name="echo.ping", args={"message": "hello"}, ttl_seconds=60, now=NOW, principal=OWNER
    )
    decision = _run(_envelope("lab.cap.echo.demo", approval_id=grant.approval_id), runtime=runtime)
    assert decision.verdict == "ALLOW"
    assert runtime.approvals.lookup(grant.approval_id).consumed()


def test_record_without_principals_authorises_nobody():
    """ADR-0003 phase 2: ``principals`` is required; a record without it is unusable."""
    _assert_uniform(
        _run(_envelope("lab.cap.legacy", tool="echo.legacy", identity=OTHER), principal=OTHER), "lab.cap.legacy"
    )
    _assert_uniform(_run(_envelope("lab.cap.legacy", tool="echo.legacy")), "lab.cap.legacy")


def test_unknown_token_and_non_holder_share_one_detail():
    unknown = _run(_envelope("lab.cap.not.issued"))
    non_holder = _run(_envelope("lab.cap.echo.demo", identity=OTHER), principal=OTHER)
    _assert_uniform(unknown, "lab.cap.not.issued")
    _assert_uniform(non_holder, "lab.cap.echo.demo")
    assert unknown.receipt.reason_detail == non_holder.receipt.reason_detail


def test_lab_shape_envelope_is_bound_the_same_way():
    lab = {
        "caller": {"identity": OWNER},
        "envelope_version": "1.0",
        "invoke": {
            "tool_name": "echo.ping",
            "argv": [],
            "schema_fields": {"capability_token": "lab.cap.echo.demo"},
        },
        "pep_eval_id": "acl-pep-capability-principal-lab",
    }
    other = {**lab, "caller": {"identity": OTHER}}
    lab_policy = PolicyStore.from_document(
        {
            **POLICY_DOC,
            "allowed_tools": {
                "echo.ping": {
                    "required_capability": "lab.cap.echo.demo",
                    "args_schema": {"type": "object", "properties": {"argv": {"type": "array"}}, "additionalProperties": False},
                }
            },
        }
    )
    runtime = PepRuntime(policy=lab_policy)
    assert evaluate(lab, runtime=runtime, now=NOW, principal=OWNER).verdict == "ALLOW"
    _assert_uniform(evaluate(other, runtime=runtime, now=NOW, principal=OWNER), "lab.cap.echo.demo")
    _assert_uniform(evaluate(other, runtime=runtime, now=NOW, principal=OTHER), "lab.cap.echo.demo")
