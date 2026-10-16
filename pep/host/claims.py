# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Host-owned result observation and claim reconciliation (ADR-0010).

The host observes every result it returns and writes a digest of it into
the ALLOW record before the result leaves the host. An agent's later
statement about a mediated action is a *claim*: structured data checked
against that record. The record is the truth; the claim is never trusted.

This covers mediated actions only. A claim about intent, belief or any
fact the host did not observe cannot be checked here and is not accepted
as a claim at all. This is claim-record reconciliation, not deception
detection, not a transcript judge, and not a polygraph.

An agent-facing check does not trust ``session_id`` in the claim body.
``verify_connected_claim`` replaces it with the connection's own session
principal before ``verify_claim``. ``verify_claim`` itself still reads the
``session_id`` on a claim the host has already attested.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pep.host.executor import UnencodableResult

CLAIM_SCHEMA = "acl-pep-claim-v1"
CLAIM_KEYS = frozenset({"schema", "kind", "request_id", "tool_name", "outcome", "result_digest", "session_id"})
ACTION_OUTCOMES = frozenset({"allowed", "denied"})
ABSENCE_OUTCOME = "not_called"

CONSISTENT = "consistent"
CONTRADICTED = "contradicted"
UNVERIFIABLE = "unverifiable"

_DIGEST_PREFIX = "sha256:"
_DIGEST_HEX = 64
_FINAL_DECISIONS = frozenset({"ALLOW", "DENY"})
_CALLED_OUTCOMES = frozenset({"entered", "raised"})

# Written by the host around one served connection. An absence claim is
# consistent only when a pair of these bounds the given records with no
# missing seq between them.
SESSION_OPEN = "SESSION_OPEN"
SESSION_CLOSE = "SESSION_CLOSE"


class ClaimError(ValueError):
    """The claim is not well-formed. Callers must not treat it as consistent."""


@dataclass(frozen=True)
class ResultObservation:
    """What the host saw of a tool result, taken before the ALLOW is written."""

    check: dict[str, str]
    digest: str | None
    parsed: Any


@dataclass(frozen=True)
class Claim:
    kind: str
    tool_name: str
    outcome: str
    request_id: str | None
    result_digest: str | None
    session_id: str | None


@dataclass(frozen=True)
class ClaimVerdict:
    verdict: str
    field: str | None
    detail: str


def result_digest(value: Any) -> str:
    """Digest of a JSON value in canonical form: sorted keys, no spaces, ASCII."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _DIGEST_PREFIX + hashlib.sha256(canonical.encode("ascii")).hexdigest()


def observe_result(result: Any) -> ResultObservation:
    """Observe a tool result the host is about to return.

    A result that is not JSON is recorded as ``unencodable`` with no digest
    and is not returned. NaN and infinity are not JSON. Anything else is
    round-tripped through JSON and digested in canonical form. The result
    body itself is never logged.
    """
    unencodable = ResultObservation({"name": "result", "outcome": "unencodable"}, None, None)
    if isinstance(result, UnencodableResult):
        return unencodable
    try:
        parsed = json.loads(json.dumps(result, ensure_ascii=True, allow_nan=False))
    except (TypeError, ValueError, RecursionError):
        return unencodable
    digest = result_digest(parsed)
    return ResultObservation({"name": "result", "outcome": "returned", "digest": digest}, digest, parsed)


def digest_ok(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(_DIGEST_PREFIX):
        return False
    tail = value[len(_DIGEST_PREFIX) :]
    return len(tail) == _DIGEST_HEX and all(ch in "0123456789abcdef" for ch in tail)


def parse_claim(raw: Any) -> Claim:
    """Parse one claim. Any doubt is ``ClaimError``; a claim is never widened."""
    if not isinstance(raw, Mapping):
        raise ClaimError("claim is not an object")
    unknown = set(raw) - CLAIM_KEYS
    if unknown:
        raise ClaimError(f"claim has unknown keys: {sorted(str(key) for key in unknown)}")
    if raw.get("schema") != CLAIM_SCHEMA:
        raise ClaimError("claim schema is not " + CLAIM_SCHEMA)
    kind = raw.get("kind")
    tool_name = raw.get("tool_name")
    outcome = raw.get("outcome")
    request_id = raw.get("request_id")
    digest = raw.get("result_digest")
    if not isinstance(tool_name, str) or not tool_name:
        raise ClaimError("claim needs a tool_name")
    if request_id is not None and (not isinstance(request_id, str) or not request_id):
        raise ClaimError("claim request_id must be a non-empty string or null")
    if digest is not None and not digest_ok(digest):
        raise ClaimError("claim result_digest is not a sha256 digest")
    if kind == "action":
        if outcome not in ACTION_OUTCOMES:
            raise ClaimError("an action claim's outcome is allowed or denied")
        if request_id is None:
            raise ClaimError("an action claim needs the host request_id")
        if outcome == "denied" and digest is not None:
            raise ClaimError("a denied action has no result to digest")
        if "session_id" in raw:
            raise ClaimError("an action claim carries no session_id")
        return Claim("action", tool_name, outcome, request_id, digest, None)
    if kind == "absence":
        if outcome != ABSENCE_OUTCOME:
            raise ClaimError("an absence claim's outcome is not_called")
        if request_id is not None or digest is not None:
            raise ClaimError("an absence claim carries no request_id and no digest")
        session_id = raw.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise ClaimError("an absence claim needs a session_id")
        return Claim("absence", tool_name, outcome, None, None, session_id)
    raise ClaimError("claim kind is action or absence")


def verify_claim(claim: Claim, records: Sequence[Mapping[str, Any]]) -> ClaimVerdict:
    """Check a parsed claim against host decision records.

    ``records`` is the host's own log, as ``ReferenceHost.decision_records``
    returns it. The verdict names the first field the record contradicts. A
    claim the record cannot settle is ``unverifiable``, which is not
    ``consistent``.

    An absence claim names one ``session_id`` and is checked only against
    that session's ``SESSION_OPEN`` and ``SESSION_CLOSE``. Every ``seq`` from
    the open line through the close line must be present, including lines
    another connection wrote in between. A missing ``seq`` is a gap, and the
    verdict is ``unverifiable``. Inside that span, only a call by the claimed
    session contradicts ``not_called``: a ``PRE_ENTRY`` line, an ``ALLOW``
    line, a ``registry_tool`` check of ``entered`` or ``raised``, or a
    ``DENY`` with reason ``tool_failed``. Another connection's call does not.
    A complete span for a different session does not settle the claim.

    Duplicate final records for one ``request_id`` are not settled by the
    last line. Final means ``ALLOW`` or ``DENY``. When those records disagree
    on the decision, the verdict is ``unverifiable``: the log does not settle
    the outcome, and that disagreement is not itself a contradiction. If any
    of them contradicts the claim on ``tool_name`` or ``result_digest``, the
    verdict is ``contradicted`` instead. When the duplicate finals agree on
    the decision, each record is checked, and the first contradiction stands.

    This trusts the ``session_id`` already on the parsed claim. That is the
    offline check of a claim the host has attested. An agent-facing caller
    uses ``verify_connected_claim``, which replaces the body's ``session_id``
    with the connection principal before parsing.
    """
    if claim.kind == "absence":
        return _verify_absence(claim, records)
    return _verify_action(claim, records)


def bind_claim_session(raw: Mapping[str, Any], session_principal: str) -> dict[str, Any]:
    """Copy a claim and set its session from the connection, not the body.

    An agent-facing path calls this before ``parse_claim``. The ``session_id``
    in the body is ignored. An absence claim is checked as
    ``session_principal``. An action claim carries no ``session_id``, so one
    in the body is dropped. The caller's mapping is left unchanged.
    """
    if not isinstance(session_principal, str) or not session_principal:
        raise ClaimError("the connection has no session principal")
    if not isinstance(raw, Mapping):
        raise ClaimError("claim is not an object")
    body = dict(raw)
    if body.get("kind") == "absence":
        body["session_id"] = session_principal
    else:
        body.pop("session_id", None)
    return body


def verify_connected_claim(
    raw: Mapping[str, Any],
    session_principal: str,
    records: Sequence[Mapping[str, Any]],
) -> ClaimVerdict:
    """Check a claim an agent submitted on a connection.

    ``session_principal`` is that connection's own principal
    (``Session.principal``, stored on each record as ``session_id``). The
    ``session_id`` in ``raw`` is not used. ``verify_claim`` remains the
    offline check of a claim whose ``session_id`` the host has already
    attested.
    """
    return verify_claim(parse_claim(bind_claim_session(raw, session_principal)), records)


def _verify_absence(claim: Claim, records: Sequence[Mapping[str, Any]]) -> ClaimVerdict:
    span = _session_span(records, claim.session_id)
    if span is None:
        return ClaimVerdict(
            UNVERIFIABLE,
            "session_id",
            "no gap-free session span for this session_id",
        )
    for record in span:
        if record.get("session_id") == claim.session_id and _shows_call(record, claim.tool_name):
            return ClaimVerdict(
                CONTRADICTED,
                "tool_name",
                f"host record {record.get('request_id')!s} shows {claim.tool_name} was admitted or entered",
            )
    return ClaimVerdict(
        CONSISTENT,
        None,
        "this session's open and close bound a complete range, and this session did not call the tool",
    )


def _marker_seq(records: Sequence[Mapping[str, Any]], session_id: str | None, decision: str) -> int | None:
    """The one seq of this session's open or close, or None if it is not singular."""
    found: int | None = None
    for record in records:
        if record.get("decision") != decision or record.get("session_id") != session_id:
            continue
        seq = record.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 or found is not None:
            return None
        found = seq
    return found


def _session_span(records: Sequence[Mapping[str, Any]], session_id: str | None) -> list[Mapping[str, Any]] | None:
    """Records from this session's open through its close, with no missing seq.

    The range is global: another connection's line between the two markers
    has to be present. The caller counts a call only when that line belongs
    to ``session_id``.
    """
    start = _marker_seq(records, session_id, SESSION_OPEN)
    end = _marker_seq(records, session_id, SESSION_CLOSE)
    if start is None or end is None or start >= end:
        return None
    by_seq: dict[int, Mapping[str, Any]] = {}
    duplicated: set[int] = set()
    for record in records:
        seq = record.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            continue
        if seq in by_seq:
            duplicated.add(seq)
            continue
        by_seq[seq] = record
    span: list[Mapping[str, Any]] = []
    for seq in range(start, end + 1):
        if seq in duplicated:
            return None
        found = by_seq.get(seq)
        if found is None:
            return None
        span.append(found)
    if span[0].get("session_id") != session_id or span[-1].get("session_id") != session_id:
        return None
    return span


def _verify_action(claim: Claim, records: Sequence[Mapping[str, Any]]) -> ClaimVerdict:
    finals = [
        record
        for record in records
        if record.get("request_id") == claim.request_id and record.get("decision") in _FINAL_DECISIONS
    ]
    if not finals:
        return ClaimVerdict(UNVERIFIABLE, "request_id", "no final host record for this request_id")
    if len(finals) == 1:
        return _judge_final(claim, finals[0])
    decisions = {record.get("decision") for record in finals}
    if len(decisions) > 1:
        for record in finals:
            if record.get("tool_name") != claim.tool_name:
                return ClaimVerdict(CONTRADICTED, "tool_name", f"host record names {record.get('tool_name')!s}")
        if claim.result_digest is not None:
            for record in finals:
                contradicted = _digest_contradiction(claim, record)
                if contradicted is not None:
                    return contradicted
        return ClaimVerdict(
            UNVERIFIABLE,
            "request_id",
            "final records for this request_id disagree on the outcome",
        )
    verdicts = [_judge_final(claim, record) for record in finals]
    for field in ("tool_name", "outcome", "result_digest"):
        for verdict in verdicts:
            if verdict.verdict == CONTRADICTED and verdict.field == field:
                return verdict
    for verdict in verdicts:
        if verdict.verdict == UNVERIFIABLE:
            return verdict
    return verdicts[0]


def _judge_final(claim: Claim, final: Mapping[str, Any]) -> ClaimVerdict:
    if final.get("tool_name") != claim.tool_name:
        return ClaimVerdict(CONTRADICTED, "tool_name", f"host record names {final.get('tool_name')!s}")
    recorded = "allowed" if final.get("decision") == "ALLOW" else "denied"
    if recorded != claim.outcome:
        return ClaimVerdict(CONTRADICTED, "outcome", f"host record is {final.get('decision')!s}")
    if claim.result_digest is None:
        return ClaimVerdict(CONSISTENT, None, "tool and outcome match the host record")
    observed = _result_check(final)
    if observed is None:
        return ClaimVerdict(UNVERIFIABLE, "result_digest", "host record carries no result observation")
    digest = observed.get("digest")
    if observed.get("outcome") != "returned" or not isinstance(digest, str):
        if observed.get("outcome") == "unencodable":
            return ClaimVerdict(CONTRADICTED, "result_digest", "host returned no result for this call")
        return ClaimVerdict(UNVERIFIABLE, "result_digest", "host record was shortened; no digest kept")
    if digest != claim.result_digest:
        return ClaimVerdict(CONTRADICTED, "result_digest", "host observed a different result")
    return ClaimVerdict(CONSISTENT, None, "tool, outcome and result digest match the host record")


def _digest_contradiction(claim: Claim, record: Mapping[str, Any]) -> ClaimVerdict | None:
    """A digest the claim states and this ALLOW record does not show.

    A DENY has no result, and a shortened ALLOW that kept no digest does not
    contradict the digest. Both leave an outcome disagreement unverifiable.
    """
    if claim.result_digest is None or record.get("decision") != "ALLOW":
        return None
    observed = _result_check(record)
    if observed is None:
        return None
    if observed.get("outcome") == "unencodable":
        return ClaimVerdict(CONTRADICTED, "result_digest", "host returned no result for this call")
    digest = observed.get("digest")
    if observed.get("outcome") == "returned" and isinstance(digest, str) and digest != claim.result_digest:
        return ClaimVerdict(CONTRADICTED, "result_digest", "host observed a different result")
    return None


def _shows_call(record: Mapping[str, Any], tool_name: str) -> bool:
    """True when ``record`` shows ``tool_name`` was admitted or entered.

    ``PRE_ENTRY`` is written before the tool runs. ``ALLOW`` is written after
    it returns and carries ``registry_tool`` ``entered``. ``raised``, and a
    ``DENY`` of ``tool_failed``, are written after that ``PRE_ENTRY`` when the
    tool raises, times out, or exceeds the reply frame limit.
    """
    if record.get("tool_name") != tool_name:
        return False
    decision = record.get("decision")
    if decision in {"PRE_ENTRY", "ALLOW"}:
        return True
    if decision == "DENY" and record.get("reason_code") == "tool_failed":
        return True
    checks = record.get("checks")
    if not isinstance(checks, list):
        return False
    for item in checks:
        if (
            isinstance(item, Mapping)
            and item.get("name") == "registry_tool"
            and item.get("outcome") in _CALLED_OUTCOMES
        ):
            return True
    return False


def _result_check(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    checks = record.get("checks")
    if not isinstance(checks, list):
        return None
    for item in checks:
        if isinstance(item, Mapping) and item.get("name") == "result":
            return item
    return None
