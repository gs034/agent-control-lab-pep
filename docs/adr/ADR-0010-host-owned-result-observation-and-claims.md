# ADR-0010: Host-owned result observation and claim reconciliation

Status: Proposed. Built on the owner's Go of 15 October 2026. Accepted when merged by the owner.

## Context

An agent's statements about what it did are the cheapest thing for it to get wrong, by mistake or on purpose: hiding a failure, reporting a result it did not get, saying a tool was not used. The host already decides and records every mediated call. It did not record what the tool returned, and it had no way to check a later statement against the record.

Reading the agent's reasoning to detect such statements is not viable in this architecture: the reasoning text is the agent's output and is under its control. The record is not.

## Decision

1. **The host observes every result itself.** Before the ALLOW line is written, the host round-trips the tool result through JSON and records a check `{"name": "result", "outcome": "returned", "digest": "sha256:..."}` in that line. The digest is over the canonical JSON form (sorted keys, no spaces, ASCII). A result that is not JSON is recorded as `{"name": "result", "outcome": "unencodable"}` and is not returned, as before. NaN and infinity are not JSON: the round-trip uses `allow_nan` false and records those values as `unencodable`. The result body is never written to the log.
2. **The reply carries the same digest** as `result_digest`, next to `result` and `result_origin`.
3. **A claim is structured data, checked against the record.** `pep/host/claims.py` defines `acl-pep-claim-v1` with two kinds. An *action* claim names a host `request_id`, a `tool_name`, an outcome of `allowed` or `denied`, and optionally the `result_digest` the agent says it received. An *absence* claim names a `session_id` and says a tool was `not_called`. `verify_claim` returns `consistent`, `contradicted` with the first field the record contradicts, or `unverifiable`. Unverifiable is not consistent.
4. **An absence claim is checked only against the named session's span.** The span is that session's `SESSION_OPEN` and `SESSION_CLOSE`. Every `seq` from the open line through the close line must be present, including a line another connection wrote in between. A missing `seq` is a gap, and the verdict is `unverifiable`. Inside the span, a record for that same session contradicts `not_called` when it is a `PRE_ENTRY` line, an `ALLOW` line (the tool entered), a `registry_tool` check of `entered` or `raised`, or a `DENY` whose `reason_code` is `tool_failed`. That denial is the line written after `PRE_ENTRY` when the tool raises, times out, or exceeds the reply frame limit. A refusal before `PRE_ENTRY` does not contradict the claim. Another connection's call does not contradict it either. A complete span for a different session does not settle the claim. An empty list is `unverifiable`. The host writes the two marker lines when it serves a connection, one after the session is accepted and one when the connection ends.
5. **Duplicate final records do not let the last line win.** Final means `ALLOW` or `DENY` for one `request_id`. When those records disagree on the decision, the verdict is `unverifiable`: the log does not settle the outcome, and that disagreement is not itself a contradiction of the claim. If any of them contradicts the claim on `tool_name` or `result_digest`, the verdict is `contradicted` instead. When the duplicate finals agree on the decision, each record is checked, and the first contradiction stands.
6. **Claims are parsed fail-closed.** Unknown keys, a wrong schema, a malformed digest, a digest on a denied action, a missing or empty `session_id` on an absence claim, a `session_id` on an action claim, or a kind other than action or absence is `ClaimError`. A claim about intent, belief or anything the host did not observe is not a claim under this schema.
7. **An agent-facing path uses the connection's session, not the `session_id` in the claim body.** Before `verify_claim`, `verify_connected_claim` copies the claim and replaces `session_id` with the connection's own principal (`Session.principal`, the same value the host stores as `session_id` on each record). `ReferenceHost.verify_agent_claim` is that path: it passes the connection's principal and this host's log. A body that names another session, or names none, is checked as this connection. An action claim still carries no `session_id`; one in the body is dropped. The `session_id` in the claim body is only for an offline check of a claim the host has already attested. `verify_claim` still reads that attested value. This repository has no console that accepts a claim from an agent. A console path that did would overwrite the same way before calling `verify_claim`.

## Consequences

- An agent's statement about a mediated call can now be settled from the host's own record, including whether the result it reports is the result it was given.
- The ALLOW line grows by one check of about 90 bytes. The line cap and clipping in `pep/host/log.py` are unchanged; a line shortened to names and outcomes loses the digest, and a claim against such a line is `unverifiable`, not `consistent`. A `DENY` `tool_failed` line shortened to core fields still names `tool_failed`, so an absence claim against it stays `contradicted`.
- An empty log does not support `not_called`. Neither does a gap in the named session's seq range, nor a finished span that belongs to a different session. Another connection may call the same tool while this session is open; that call does not contradict this session. Two final lines for one `request_id` that disagree on `ALLOW` and `DENY` do not support either outcome.
- A served connection adds two short lines, `SESSION_OPEN` and `SESSION_CLOSE`. They carry no tool result. In-process calls that never pass through the socket are not bounded by those lines.
- On an agent-facing path the host does not trust `session_id` from the agent. The connection principal replaces it. An offline check of an already attested claim still uses the `session_id` on that claim.
- Nothing is enforced at runtime by this ADR. Who submits claims, when, and what a `contradicted` verdict triggers (a halt, an operator alert, a kill) is deployment policy and a later decision. The agent socket still accepts only a tool name and arguments. `verify_agent_claim` is how a connection checks a claim; it is not a new socket command. The console's ledger-versus-prose comparison is a natural caller; it is not wired here.
- Coverage is mediated actions only. Provider-executed tools, actions outside the host, and the alternate paths named in the coverage notes are not observed and cannot be claimed about.

## What this is not

Not deception detection. Not a transcript or reasoning judge. Not Path A, which is unchanged and still unrun. Not a polygraph: a `contradicted` verdict means the agent's structured statement and the host's record disagree about a mediated action, nothing more. No efficacy is claimed or measured.

## Related work items

L3.6 (tamper-evident host log) makes the record this ADR relies on resistant to rewriting by the thing it judges. L3.1 (grant revocation) shortens the window in which a contradicted claim can be followed by further mediated actions. Both are separate ADRs.
