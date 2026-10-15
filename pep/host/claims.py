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
    and is not returned. Anything else is round-tripped through JSON and
    digested in canonical form. The result body itself is never logged.
    """
    unencodable = ResultObservation({"name": "result", "outcome": "unencodable"}, None, None)
    if isinstance(result, UnencodableResult):
        return unencodable
    try:
        parsed = json.loads(json.dumps(result, ensure_ascii=True))
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
    """
    if claim.kind == "absence":
        for record in records:
            if record.get("decision") == "ALLOW" and record.get("tool_name") == claim.tool_name:
                return ClaimVerdict(
                    CONTRADICTED,
                    "tool_name",
                    f"host record {record.get('request_id')!s} shows {claim.tool_name} entered",
                )
        return ClaimVerdict(CONSISTENT, None, "no ALLOW record for this tool in the given records")

    final: Mapping[str, Any] | None = None
    for record in records:
        if record.get("request_id") == claim.request_id and record.get("decision") in _FINAL_DECISIONS:
            final = record
    if final is None:
        return ClaimVerdict(UNVERIFIABLE, "request_id", "no final host record for this request_id")
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


def _result_check(record: Mapping[str, Any]) -> Mapping[str, Any] | None:
    checks = record.get("checks")
    if not isinstance(checks, list):
        return None
    for item in checks:
        if isinstance(item, Mapping) and item.get("name") == "result":
            return item
    return None
