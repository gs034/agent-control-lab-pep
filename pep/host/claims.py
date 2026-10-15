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
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pep.host.executor import UnencodableResult

CLAIM_SCHEMA = "acl-pep-claim-v1"
CLAIM_KEYS = frozenset({"schema", "kind", "request_id", "tool_name", "outcome", "result_digest"})
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
        return Claim("action", tool_name, outcome, request_id, digest)
    if kind == "absence":
        if outcome != ABSENCE_OUTCOME:
            raise ClaimError("an absence claim's outcome is not_called")
        if request_id is not None or digest is not None:
            raise ClaimError("an absence claim carries no request_id and no digest")
        return Claim("absence", tool_name, outcome, None, None)
    raise ClaimError("claim kind is action or absence")


def verify_claim(claim: Claim, records: Sequence[Mapping[str, Any]]) -> ClaimVerdict:
    """Check a parsed claim against host decision records.

    ``records`` is the host's own log, as ``ReferenceHost.decision_records``
    returns it, already narrowed by the caller to the scope the claim is
    about (one session, one window). The verdict names the first field the
    record contradicts. A claim the record cannot settle is ``unverifiable``,
    which is not ``consistent``.

    An absence claim (``not_called``) is contradicted by any record for that
    tool that shows the call was admitted or entered: a ``PRE_ENTRY`` line,
    an ``ALLOW`` line, a ``registry_tool`` check of ``entered`` or ``raised``,
    or a ``DENY`` with reason ``tool_failed``. That denial is the line written
    after ``PRE_ENTRY`` when the tool raises, times out, or exceeds the reply
    frame limit. It is ``consistent`` only when the records include one
    ``SESSION_OPEN`` and one ``SESSION_CLOSE`` for the same session and every
    ``seq`` from the open line through the close line is present. A missing
    ``seq`` is a gap. Anything shorter, including an empty list or another
    tool's records with no such pair around them, is ``unverifiable``.

    Duplicate final records for one ``request_id`` are not settled by the
    last line. Final means ``ALLOW`` or ``DENY``. When those records disagree
    on the decision, the verdict is ``unverifiable``: the log does not settle
    the outcome, and that disagreement is not itself a contradiction. If any
    of them contradicts the claim on ``tool_name`` or ``result_digest``, the
    verdict is ``contradicted`` instead. When the duplicate finals agree on
    the decision, each record is checked, and the first contradiction stands.
    """
    if claim.kind == "absence":
        return _verify_absence(claim, records)
    return _verify_action(claim, records)


def _verify_absence(claim: Claim, records: Sequence[Mapping[str, Any]]) -> ClaimVerdict:
    for record in records:
        if _shows_call(record, claim.tool_name):
            return ClaimVerdict(
                CONTRADICTED,
                "tool_name",
                f"host record {record.get('request_id')!s} shows {claim.tool_name} was admitted or entered",
            )
    if _session_span_is_complete(records):
        return ClaimVerdict(
            CONSISTENT,
            None,
            "session open and close bound these records, and this tool was not called",
        )
    return ClaimVerdict(
        UNVERIFIABLE,
        "tool_name",
        "records are not a complete session, so absence is unverifiable",
    )


def _session_span_is_complete(records: Sequence[Mapping[str, Any]]) -> bool:
    """True when every given record sits in a gap-free open/close pair.

    A pair is one ``SESSION_OPEN`` and one ``SESSION_CLOSE`` for the same
    ``session_id``, and every integer ``seq`` from the open line through the
    close line is present. A record outside every such pair, a missing
    ``seq``, or a second marker for one session leaves the slice incomplete.
    """
    if not records:
        return False
    by_seq: dict[int, Mapping[str, Any]] = {}
    for record in records:
        seq = record.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 or seq in by_seq:
            return False
        by_seq[seq] = record

    opens: dict[str, int] = {}
    closes: dict[str, int] = {}
    for seq, record in by_seq.items():
        decision = record.get("decision")
        if decision not in {SESSION_OPEN, SESSION_CLOSE}:
            continue
        session_id = record.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return False
        bucket = opens if decision == SESSION_OPEN else closes
        if session_id in bucket:
            return False
        bucket[session_id] = seq

    covered: set[int] = set()
    sessions = set(opens) & set(closes)
    if not sessions:
        return False
    for session_id in sessions:
        start = opens[session_id]
        end = closes[session_id]
        if start >= end:
            return False
        for seq in range(start, end + 1):
            found = by_seq.get(seq)
            if found is None:
                return False
            covered.add(seq)
        if by_seq[start].get("session_id") != session_id or by_seq[end].get("session_id") != session_id:
            return False
    return set(by_seq) == covered


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
