# ADR-0002: Bind single-use approvals to a host-attested principal

- **Status:** Proposed (owner decision 2026-10-04: bearer approvals are not the intended design). Not implemented on this tree.
- **Date:** 2026-10-04
- **Supersedes:** nothing. Amends ADR-0001 "Capability language", item 3.
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

ADR-0001 makes an operator-issued `approval_id` a single-use, TTL-bound grant for one exact invoke (`tool_name` plus canonical args), with an optional host-observed state digest. It does not say who may spend the grant.

On this tree the grant is a bearer capability:
- `ApprovalRecord` has no principal field.
- `ApprovalStore.consume` never reads an identity (`pep/approval.py`).
- The module docstring says approvals "are capability grants, not caller identity".

`tests/test_approval_laundering_classes.py::test_delegation_is_bearer_residual` shows the consequence:
1. A second caller presents the same `approval_id` with the exact invoke.
2. The second caller gets ALLOW, and the tool runs.
3. The caller the approval was minted for then gets DENY `approval_consumed`.

So one grant can be spent by the wrong party, and spending it denies the right party. This is the Delegation class in Approval Laundering (arXiv:2609.38983v1, a single-harness working draft). That paper measured it at a bound-gap rate of 0.947 (18 of 19 runs) in one coding-agent harness. The paper and that rate are class inspiration only; this repo makes no measured attack-success-rate claim.

The envelope already carries an identity, but ADR-0001 rules it out as authority:
- The Lab shape uses `caller.identity` and the flat shape uses `caller_identity`, both matching `IDENTITY_RE` (`pep/envelope.py`).
- The value is caller-asserted.
- ADR-0001 says "Identity strings and free-text are not allow authorities".
- `docs/threat-model.md` lists "caller identity as authority" as a capability-spoof attempt.

Binding approvals to that string alone would be cosmetic: a delegate that copies the owner's identity string would pass.

## Decision

An approval is bound, at mint, to one **principal**. Only a call whose principal is **attested by the host**, not asserted by the envelope, can consume it.

1. **Mint.**
   - `PepRuntime.issue_approval(...)` and `ApprovalStore.issue(...)` take a required keyword `principal: str` that matches `IDENTITY_RE`.
   - It is stored on `ApprovalRecord.principal`.
   - `invoke_binding` and `binding_digest` stay as they are (tool plus canonical args). The principal is checked on its own, so it gets its own reason code instead of surfacing as `approval_binding_mismatch`.
   - Mint without a principal raises `ApprovalError`. There is no unbound mode.
2. **Attest.**
   - `evaluate`, `begin_invoke` and `gated_invoke` take a keyword `principal: str | None`, supplied by the host.
   - This uses the same trust channel as `state_observer`: it is a function argument from the code that owns the session, never an envelope field.
   - The host derives it from its own session state, for example the console host's per-session handle. It never copies it from the envelope.
3. **Consume.** Inside `ApprovalStore.consume`, under the store lock, after the existence, single-use, expiry and invoke-binding checks and before any state observation:
   - If the host passed no principal, the result is DENY `approval_principal_mismatch` (detail: "no attested principal").
   - If the host principal differs from `record.principal`, the result is DENY `approval_principal_mismatch`.
   - If the envelope's caller identity differs from the host principal, the result is DENY `approval_principal_mismatch`. This is a consistency check that catches a host/envelope disagreement; the envelope string never authorises anything.
   - None of these denials consume the grant, so a wrong caller cannot burn the owner's approval. This matches the existing rule that a binding mismatch does not consume.
4. **No transitive delegation.** A delegate, sub-agent or second session needs its own approval, minted by the operator for the delegate's principal. Delegation grants, meaning one principal authorising another, are out of scope for this ADR and would need their own.
5. **Receipts.**
   - The receipt stays on frozen schema v1. `reason_code` is a free string in `eval/receipt.schema.json`, so `approval_principal_mismatch` needs no schema bump.
   - `reason_detail` names the failed check but does not echo either principal string. That keeps the deny from becoming an oracle for valid principals.
   - Adding a principal field to the receipt would be a schema bump and is not proposed here.
6. **Version.** This is a behaviour change to the mint signature, so the package moves to 0.4.0.

## Options considered

| Option | What it binds | Why accepted or rejected |
| --- | --- | --- |
| A. Envelope `caller_identity` only | A caller-asserted string | Rejected. It turns an identity string into partial authority, contrary to ADR-0001, and a delegate that copies the string passes. |
| **B. Host-attested principal, envelope string as a consistency check (chosen)** | Principal from the host's own session state | Matches the existing `state_observer` trust model. No key material. Closes the measured Delegation case for callers that go through a host route. |
| C. Keyed token, HMAC over principal, agent, session, tool, args, scope and expiry (as in arXiv:2609.38983v1, sec. 6) | A keyed capability | Not needed in-process: records already live server-side in `ApprovalStore`, and the key would sit in the same process as the attacker this ADR excludes. Worth revisiting only if approvals persist out of process (ADR-0001, Consequences). |
| D. Keep bearer approvals and document them | Nothing | Rejected by the owner on 2026-10-04. |

## Residuals (what this does not fix)

- **In-process callers can claim any principal.** Code that calls `PepRuntime.evaluate` directly can pass any `principal` it likes. ADR-0001 puts the trust boundary at the function boundary, so this binding defends routes where the host, not the agent, supplies the principal. It does not defend against an agent with equivalent process access, which remains outside the boundary (joint-eval `docs/lab-threat-model.md`).
- **Standing capability tokens are still bearer.** `capability_token` in the envelope is checked for existence, expiry and tool coverage, not for who presents it. This ADR does not cover it. A follow-up decision is needed.
- **Effects below the tool boundary.** Effect divergence from pre-existing hooks and scripts, and `PATH`-level program resolution, are unchanged by this ADR. The Scope and Argument cases in arXiv:2609.38983v1, which defeated that paper's own token defence, also fall here. See the `docs/threat-model.md` non-goals.
- **No cross-process principal.** `HaltStore` and any future out-of-process approval store would need to persist and verify `principal` too.

## Consequences and dependent changes

**pep, this repository.** The changes touch:
- `pep/approval.py`: record field, binding key, consume check.
- `pep/evaluate.py`: `issue_approval` and `evaluate` signatures.
- `pep/gate.py`: `begin_invoke` and `gated_invoke` pass-through.
- `pep/reasons.py`: the new code.
- `pep/corpus.py:110`: corpus mint.
- the existing approval tests and corpus rows: every mint gains `principal`.

That is more than five files, so implementation splits into two reviewed phases:
1. Core and new tests.
2. Corpus, docs, ROADMAP and the version bump.

**joint-eval.** `joint_eval/story.py:264` mints an approval and must pass a principal. It also pins pep, so it needs a pin bump to the 0.4.0 commit.

**console.** It has no direct mint (`issue_approval` does not appear on console `main`). It pins joint-eval, so it moves when joint-eval moves. Each repo's declared pins are updated in the same change as its code.

## Comparison experiment and acceptance

Re-run `tests/test_approval_laundering_classes.py` before and after the change, at named commits.

| Case | Before (this tree) | Required after |
| --- | --- | --- |
| Delegation: second principal, same `approval_id`, exact invoke | ALLOW, grant spent | DENY `approval_principal_mismatch`; grant **not** consumed; the owner's next call is ALLOW |
| Host passes no principal for an approval call | n/a | DENY `approval_principal_mismatch`; not consumed |
| Host principal matches the record, envelope identity differs | n/a | DENY `approval_principal_mismatch`; not consumed |
| Owner principal, exact invoke | ALLOW | ALLOW (unchanged) |
| Temporal (TTL, after consume) and residual replay | DENY | DENY (unchanged codes) |
| Execute-then-write state mismatch | DENY `approval_state_mismatch` | Unchanged. The principal check runs before the observer, so a wrong principal never triggers a host read. |
| Pre-existing hook; `PATH` substitution | ALLOW (residual) | ALLOW (unchanged; still a residual) |
| Two principals race one grant (threaded) | n/a | Exactly one consume, and only by the record's principal |
| Mint without `principal` | allowed | `ApprovalError` |

Further acceptance requirements:
- No receipt-schema change.
- `reason_detail` contains no principal string.
- The full pep, joint-eval and console suites pass at the bumped pins.
- The brand-wall checks are clean.
- The `test_delegation_is_bearer_residual` row in `docs/threat-model.md` is replaced by the new behaviour.
- An independent, cross-family review of each phase diff.

**Rollback.** Revert the 0.4.0 commit and restore the previous pins in joint-eval and console. Approvals are process-local, so no persisted state needs migrating.

**What success would establish.** On this tree, an approval can be spent only through a host route that attests its principal, and a wrong caller cannot burn it.

**What it would not establish.** It would not establish any measured attack-success rate, resistance to an in-process attacker that forges the host argument, or live enforcement. Soft DEMO ≠ live ≠ live enforcement ≠ efficacy ≠ safety case.
