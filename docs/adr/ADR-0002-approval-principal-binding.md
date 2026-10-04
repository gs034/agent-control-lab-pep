# ADR-0002: Bind single-use approvals to a host-attested principal

- **Status:** Accepted, 2026-10-04 (owner). Bearer approvals are not the intended design.
- **Implementation:** done in pep 0.4.0, in two phases on one branch: phase 1 (core and new tests) and phase 2 (principal required at mint, corpus and test migration, docs, version). Not yet done: the joint-eval `story.py` principal and the joint-eval and console pin bumps, which are a separate change.
- **Date:** 2026-10-04
- **Supersedes:** nothing.
- **Amends:** ADR-0001 "Capability language" items 3 and 5, and the "Fail-closed" list, which gains a principal mismatch.
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

ADR-0001 makes an operator-issued `approval_id` a single-use, TTL-bound grant for one exact invoke: `tool_name` plus canonical args, with an optional host-observed state digest. It does not say who may spend the grant.

Before this change (pep 0.3.3, commit `ffd048a`), the grant was a bearer capability:
- `ApprovalRecord` had no principal field.
- `ApprovalStore.consume` took no identity argument (`pep/approval.py`).
- The module docstring said approvals "are capability grants, not caller identity".

`tests/test_approval_laundering_classes.py::test_delegation_is_bearer_residual` (as of commit `506f5ee`; it was renamed `test_delegation_to_a_second_principal_denies_without_spending_the_grant` in 0.4.0) showed the consequence:
1. A second caller presents the same `approval_id` with the exact invoke.
2. That caller gets ALLOW, and the tool runs.
3. The original caller then gets DENY `approval_consumed`.

So one grant can be spent by the wrong party, and spending it denies the right party. The attack class is the Delegation class in Approval Laundering (arXiv:2609.38983v1). It is cited as class inspiration only. This repository makes no attack-success-rate claim.

The envelope already carries an identity: `caller.identity` in the Lab shape and `caller_identity` in the flat shape, both matching `IDENTITY_RE` (`pep/envelope.py`). But it is asserted by the caller. ADR-0001 says "Identity strings and free-text are not allow authorities", and `docs/threat-model.md` lists "caller identity as authority" as a capability-spoof attempt. Binding approvals to that string alone would be cosmetic: a delegate that copies the owner's identity string would pass.

## Decision

An approval is bound, at mint, to one **principal**. Only a call whose principal is attested by the host, not merely asserted by the envelope, can consume it.

1. **Mint.**
   - `PepRuntime.issue_approval(...)` and `ApprovalStore.issue(...)` take `principal: str | None = None`. `None`, or a value that does not match `IDENTITY_RE`, raises `ApprovalError`. There is no unbound mode.
   - The value is stored on `ApprovalRecord.principal`.
   - `invoke_binding` and `binding_digest` are unchanged (tool plus canonical args). The principal is checked on its own, so a principal failure has its own reason code and never surfaces as `approval_binding_mismatch`.
2. **Attest.**
   - `evaluate`, `begin_invoke`, `gated_invoke` and `ApprovalStore.consume` / `try_consume` take `principal: str | None = None`, supplied by the host.
   - This is the same trust channel as `state_observer`: a function argument from the code that owns the caller's session, never an envelope field.
   - **Mapping.** The host principal is the identity the host has assigned to that caller session, in `IDENTITY_RE` format; for example, a host that runs one demo agent assigns it `lab.demo.agent`. A host that runs several callers must give each its own identity, so a sub-agent or second session gets a different principal from its parent.
   - On the `evaluate` / `begin_invoke` / `gated_invoke` route, a host principal that does not match `IDENTITY_RE` is `envelope_invalid` before any grant is touched. A direct `consume` / `try_consume` call treats it as a principal mismatch.
3. **Consume.** Inside `ApprovalStore.consume`, under the store lock:
   - **Order.** Look up the `approval_id`. An unknown id stays `approval_invalid`. **The principal check comes next, immediately after the lookup and before the consumed, expired, binding, single-use-flag and state checks.** A wrong or unattested caller therefore learns only that the id exists, and nothing about whether the grant is spent, expired or bound to other args. Approval ids are random (`lab.appr.<uuid4>`) unless an operator names them.
   - **No attested principal.** If the host passed no principal, the result is DENY `approval_principal_mismatch`, with detail "no attested principal".
   - **Wrong principal.** If the host principal differs from `record.principal`, the result is DENY `approval_principal_mismatch`.
   - **Envelope disagreement.** If the envelope's caller identity differs from the host principal, the result is DENY `approval_principal_mismatch`. This consistency check catches a host/envelope disagreement; the envelope string never authorises anything.
   - **No consumption.** None of these denials consume the grant, so a wrong caller cannot burn the owner's approval. This matches the existing rule that a binding mismatch does not consume.
   - **Owner path.** After the principal check passes, the existing order (consumed, expired, binding, single-use flag, state observer) is unchanged.
4. **No transitive delegation.** A delegate needs its own approval, minted by the operator for the delegate's principal. Delegation grants, where one principal authorises another, are out of scope and would need their own ADR.
5. **Receipts.**
   - The receipt stays on frozen schema v1. `reason_code` is a free string in `eval/receipt.schema.json` (`pep/receipt.py` checks only that it is non-empty), so `approval_principal_mismatch` needs no schema bump.
   - `reason_detail` says only whether a principal was attested ("no attested principal" or "principal check failed"). It never echoes either principal string, and it does not tell a wrong principal apart from an envelope disagreement, so a caller cannot use the wording to confirm a guessed principal.
   - Adding a principal field to the receipt would be a schema bump and is not proposed.
6. **Version.** The mint signature changes behaviour (mint without a principal raises), so the package version moves from 0.3.3 to 0.4.0.

## Options considered

| Option | Binds to | Assessment |
| --- | --- | --- |
| A. Envelope `caller_identity` only | A caller-asserted string | **Rejected.** It turns an identity string into partial authority, contrary to ADR-0001, and a delegate copying the string passes. |
| **B. Host-attested principal; envelope string as a consistency check (chosen)** | The identity the host assigned to the caller session | Matches the existing `state_observer` trust model and needs no key material. It closes the Delegation case for callers that reach the PEP through a host that assigns per-session principals. No such host route sends approvals through pep today (see Consequences), so the console case is prospective. |
| C. Keyed token: HMAC over principal, agent, session, tool, args, scope and expiry (arXiv:2609.38983v1, sec. 6) | A keyed capability | Not needed in process. Records already live in `ApprovalStore`, and the key would sit in the same process as the attacker this ADR excludes. Revisit only if approvals persist out of process (ADR-0001, Consequences). |
| D. Keep bearer approvals and document them | Nothing | **Rejected** by the owner on 2026-10-04. |

## Residuals (what this does not fix)

- **In-process callers can claim any principal.** Code that calls `PepRuntime.evaluate` directly can pass any `principal`. ADR-0001 puts the trust boundary at the function boundary. This binding defends routes where the host, not the agent, supplies the principal; it does not defend against an agent with equivalent process access (joint-eval `docs/lab-threat-model.md`).
- **`PendingInvoke` is still a bearer handle in process.** An ALLOW admission from `begin_invoke` can be completed by whoever holds it. The in-process residual above covers this; this ADR does not change it.
- **Standing capability tokens are still bearer** (at 0.4.0; [ADR-0003](ADR-0003-capability-token-principal-binding.md) closes this in 0.5.0). `capability_token` is checked for existence, expiry, tool coverage and the tool's `required_capability`, but not for who presents it. ADR-0003 is that follow-up decision.
- **The owner's grant can still be spent without the tool running.** This happens when, after the owner's consume, `complete_invoke` re-observes a changed state or a kill or suspend intervenes. That is existing behaviour ("a grant can be spent and the decision still DENY") and is unchanged here. The guarantee is that a *wrong* caller cannot spend it.
- **Effects below the tool boundary are unchanged.** Pre-existing hooks and scripts, and `PATH`-level program resolution, remain residuals; see the `docs/threat-model.md` non-goals.
- **No out-of-process approval store exists.** Any future one would need to persist and verify `principal`. `HaltStore` holds only runtime mode and availability, not approvals, so it is unaffected.

## Consequences and dependent changes

**pep (this repository):**
- `pep/approval.py`:
  - `ApprovalRecord.principal`;
  - `issue(principal=)` with validation;
  - `consume` and `try_consume` take `principal=` and run the new early check.
- `pep/evaluate.py`: `issue_approval(principal=)`; `PepRuntime.evaluate` and module-level `evaluate` pass `principal=` through to consume.
- `pep/gate.py`: `begin_invoke` and `gated_invoke` pass `principal=` through.
- `pep/reasons.py`: `APPROVAL_PRINCIPAL_MISMATCH`.
- `pep/corpus.py`, which needs a principal source (for example, a runtime-spec field):
  - the fixture mint;
  - the fixture pre-consume `try_consume`, which raises if consume denies;
  - the `evaluate`, `gated_invoke` and `begin_invoke` calls in the row runners.
- Existing approval tests and `eval/corpus/` rows: every mint and every approval-path evaluate gains a principal.
- `docs/threat-model.md`:
  - replace the delegation non-goal bullet;
  - add the principal check to the Capability-spoof defence cell.
- ADR-0001: amend items 3 and 5 and the Fail-closed list.

That is more than five files, so implementation splits into two reviewed phases:
1. Core and new tests.
2. Corpus, docs, ROADMAP and the version bump.

**joint-eval:**
- `joint_eval/story.py:264` (mint) must pass a principal.
- `joint_eval/story.py:212` (the `pep_gated(...)` call) must pass the same principal as host.
- `eval/joint_story/` fixtures may need a principal field.
- Its pep pin moves to the 0.4.0 commit.

**console:**
- **No change today:** console `main` has no `issue_approval`, and its pep call sites (`stories.py`, `witness.py`) use no approvals.
- **Pins:** console pins pep directly (`pyproject.toml`) and also pins joint-eval. Both pins move together when the joint-eval change lands.

Each repository updates its declared pins in the same change as its code.

## Comparison experiment and acceptance

Re-run `tests/test_approval_laundering_classes.py` before and after the change, at named commits.

| Case | Before (0.3.3) | Required after |
| --- | --- | --- |
| Delegation: second principal, same `approval_id`, exact invoke | ALLOW; grant spent | DENY `approval_principal_mismatch`; grant **not** consumed; the owner's next call is ALLOW |
| Host passes no principal, issued `approval_id` (any grant state) | n/a | DENY `approval_principal_mismatch`; not consumed |
| Host passes no principal, unknown `approval_id` | `approval_invalid` | `approval_invalid` (unchanged) |
| Wrong principal against a spent, expired or args-mismatched grant | n/a | DENY `approval_principal_mismatch`, so no status or binding oracle |
| Host principal matches record, envelope identity differs | n/a | DENY `approval_principal_mismatch`; not consumed |
| Malformed host principal | n/a | DENY `envelope_invalid`; no grant touched |
| Owner principal, exact invoke | ALLOW | ALLOW (unchanged) |
| Owner: temporal (TTL, after consume) and residual replay | DENY `approval_expired` / `approval_consumed` | Unchanged |
| Owner: execute-then-write state mismatch | DENY `approval_state_mismatch` | Unchanged. A wrong principal never triggers a host state read |
| Pre-existing hook; `PATH` substitution | ALLOW (residual) | ALLOW (unchanged; still residual) |
| Two principals race one grant (threaded) | n/a | Exactly one consume, by the record's principal. The other caller gets `approval_principal_mismatch` whichever order they run in, because the principal check precedes the consumed check |
| Mint with `principal=None` or a malformed value | Allowed | `ApprovalError` |

Further acceptance criteria:
- No receipt-schema change.
- `reason_detail` contains no principal string.
- The full pep, joint-eval and console suites pass at the bumped pins.
- The brand-wall checks are clean.
- The delegation non-goal bullet in `docs/threat-model.md` is replaced.
- Each phase diff gets an independent, cross-family review.

**Rollback:** revert the ADR-0002 implementation commits (`edde7ae`, `6c21669`, `a5fbc41`, `61b183d` and any follow-up review fixes) and restore the previous pins in joint-eval and console. Approvals are process-local, so no persisted state needs migrating.

**What success would establish:** on this tree, an approval can be spent only through a host route that attests its principal, and a wrong caller can neither spend it nor learn its state.

**What it would not establish:**
- any attack-success rate;
- resistance to an in-process attacker who forges the host argument;
- live enforcement;
- a safety case.
