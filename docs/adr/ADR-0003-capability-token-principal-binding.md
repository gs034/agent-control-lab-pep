# ADR-0003: Bind standing capability tokens to host-attested principals

- **Status:** Accepted, 2026-10-04 (owner). Implemented on the ADR-0002 branch in three phases (see Phases). Phase 1 is in progress. Its transitional bearer behaviour, for records without `principals`, is removed in phase 2, and the branch does not merge before then.
- **Date:** 2026-10-04
- **Depends on:** [ADR-0002](ADR-0002-approval-principal-binding.md), which supplies the host-attested `principal` argument.
- **Amends:** ADR-0001 "Capability language" items 2 and 5, the "Fail-closed" list, and the Consequences line that keeps `policy_version` at `0.1.0-stub`.
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

**How tokens work today.** ADR-0001 item 2 makes a standing capability token a grant. The token must be known, unexpired, cover the tool, and match the tool's `required_capability` when there is one. Tokens are records in the frozen policy document (`capability_tokens`, `pep/policy.py`). The envelope carries the token id (`capability_token`), and `_capability_deny` in `pep/evaluate.py` checks it.

**Nothing asks who presents it.** On this tree a capability token is therefore a bearer credential. ADR-0002 closed the same gap for single-use approvals, but tokens are the wider gap, for three reasons.

**Tokens are multi-use.** An approval is spent once. A token admits every matching invoke until it expires, and the stub token `lab.cap.echo.demo` expires in 2099.

**The id is not secret.** It is a policy key, and it appears in several places:
- the public policy document;
- the corpus envelopes;
- the joint-eval fixtures and tests;
- the console witness (`lab_console/witness.py`).

Knowing the id is the whole credential.

**PEP responses leak token state.** An unknown token returns "capability token unknown", while an expired one returns "capability token expired". A token that does not cover the tool returns a third detail under reason code `capability_missing`. A `required_capability` mismatch returns reason code `policy_miss`. So any caller can probe the PEP to learn which ids exist and what state they are in. Joint-eval pins this as an observation: `tests/test_evasion_alternate_paths.py::test_capability_detail_reveals_token_state_observation`.

ADR-0002's residuals already name the gap: "Standing capability tokens are still bearer."

## Decision

Each capability token in policy names the principals that may present it. Only a call whose host-attested principal is one of them can use the token.

1. **Policy field.** Every `capability_tokens` record gains a required `principals` field:
   - It must be a JSON array of one or more strings, each matching `IDENTITY_RE`.
   - If `principals` is missing, empty, not an array, or holds a malformed entry, the record authorises nobody: fail closed. A bare string is rejected, so a substring test can never pass.
   - The binding lives in operator-authored policy, not in a mint call. Tokens stay standing and multi-use; this changes who may use them, not how long they last.
2. **Attestation.** The host-attested `principal` from ADR-0002 is reused unchanged. It is a function argument on `evaluate`, `begin_invoke` and `gated_invoke`, and is never an envelope field. On those routes, a malformed principal is already `envelope_invalid` before any grant is touched.
3. **Check order in `_capability_deny`:**
   1. No attested principal: DENY `capability_missing`, "no attested principal". This is checked before the token lookup, so it reveals nothing about the token. It matches ADR-0002, keeping a host wiring error distinguishable from a refused caller.
   2. Look up the token.
   3. If the token is unknown, the attested principal is not in the record's `principals`, or the envelope identity differs from the attested principal: DENY `capability_missing`, "capability token not valid for this caller". All three cases return the same result, so a caller that is not a holder learns nothing *from the PEP's response*: not whether the id exists, not its expiry, not its coverage.
   4. Only a listed holder then reaches the existing checks, with their existing details:
      - malformed or missing expiry: `capability_missing`;
      - expired: `capability_missing`;
      - does not cover the tool: `capability_missing`;
      - does not match the tool policy: `policy_miss`.
   No new reason code is introduced.
4. **Approvals are unchanged.** The order inside `evaluate` stays as it is: a presented token is checked first, then the args schema, then any presented `approval_id` is consumed under the ADR-0002 principal check. A failing token check denies before the approval is touched, so the approval is not consumed.
5. **Policy version.** Adding `principals` changes both the policy bytes and their meaning.
   - The `POLICY_VERSION` constant, and with it `STUB_POLICY_DOCUMENT` and the empty-policy fallback receipt, moves from `0.1.0-stub` to `0.2.0-stub`.
   - Fixture envelopes carry `policy_context.policy_version`, which is metadata, not policy. These move to `0.2.0-stub` as well, so the fixtures do not misstate the policy they run against.
   - Because `envelope_hash` covers the whole envelope, those rows' `envelope_hash` changes too.
6. **Receipts.**
   - Schema v1 is unchanged, and there is no new reason code.
   - Decisions and codes change only in the cases the acceptance table lists: callers that are not holders go from ALLOW or `policy_miss` to `capability_missing`.
   - No detail echoes a principal or a token id.
7. **Version.** The package moves to 0.5.0. The policy field and the deny behaviour are breaking changes for any caller that presents tokens without attesting a principal.

## Options considered

| Option | Binds to | Assessment |
| --- | --- | --- |
| **A. Policy-listed holders, host-attested principal (chosen)** | The `principals` list on each token in frozen policy | The binding sits with the rest of capability policy, which is operator-authored and digest-attested. It reuses the ADR-0002 channel and needs no key material. |
| B. Per-session tokens minted by the host, like approvals | A runtime record per principal | Duplicates the approval store for a standing grant, and moves capability authority out of frozen policy, which ADR-0001 keeps as the source of truth. Rejected. |
| C. Secret or keyed tokens (random ids, HMAC) | Possession of a secret | Still bearer: anyone the secret is passed to can use it. The secret would also sit in the same process as the attacker that ADR-0002 already excludes. Rejected. |
| D. Keep bearer tokens, document them | Nothing | Leaves a multi-use credential with a public id that is weaker than approvals are after ADR-0002. Rejected. |
| E. Uniform deny details only | Nothing | Closes the response oracle, but not the bearer gap. Folded into A as decision 3. |

## Residuals (what this does not fix)

- **Forged principals in process.** An in-process caller can still claim any principal, as with ADR-0002. Code with the same process access can pass any `principal` to `evaluate`. The binding defends host routes that assign per-session principals, not callers with equivalent access.
- **The policy itself is public.** The policy document lists every token id, its tools, its expiry and now its `principals`. Decision 3 removes the oracle in the PEP's *response*, not knowledge of the published policy. Publishing holder identities is acceptable, because a holder's principal is attested by the host rather than presented by the caller, so knowing a holder's name does not let a caller become that holder.
- **Shared holder lists.** A token that lists several principals is shared among them. Policy authors should list the narrowest set.
- **Policy authorship is trusted.** An operator who lists the wrong principal grants it the capability.
- **Holders still see specific details.** A listed holder can tell an expired token from an uncovered tool. This is accepted, because holders are the principals the operator assigned.
- **Expiry is unchanged.** Long-lived tokens stay long-lived; shortening them is a policy decision.

## Consequences and dependent changes

### Sibling pins

On `main`, joint-eval and console still pin pep `ffd048a` (0.3.3). ADR-0002's own sibling work is also still pending: the joint-eval `story.py` principal and the pin bumps. Plan **one combined sibling change** once ADR-0002 and ADR-0003 are both merged in pep, rather than two separate pin moves.

### pep (this repository)

**Code**
- `pep/policy.py`:
  - `principals` on the stub token records;
  - `POLICY_VERSION` set to `0.2.0-stub`;
  - a `principals` parser that rejects non-arrays. Note that `_freeze` turns lists into tuples.
- `pep/evaluate.py`: `_capability_deny` takes the attested principal and the envelope identity, and gets the new checks.

**Corpus and fixtures**
- `eval/corpus/`:
  - **Runtime fixtures.** The token rows that reach the token check today are `allow_catalog_bound` and `late_effect_fence`. They gain a top-level `principal` so they keep their outcomes. `capability_spoof` presents an unknown id and needs no attestation for its outcome. Its detail changes to the uniform one, or to "no attested principal" if no principal is attested. The phase plan gives it an attested principal, so that it exercises the uniform non-holder path. The 13 other token rows deny earlier (prose, kill, suspend, missing policy), and their decisions are unchanged.
  - **Envelopes.** Every envelope's `policy_context.policy_version` moves to `0.2.0-stub`.
  - **Expected receipts.** All are regenerated.
- The official `eval/expected_deny_receipt.example.json`, `eval/structured_envelope.example.json` and `eval/ACL_PEP_Eval_Row_2609_19587_class_2026-09-18.md` (policy version).

**Tests**
- Tests that present the live token `lab.cap.echo.demo` attest `lab.demo.agent`. These include `tests/test_approval.py`, `test_deny_path.py`, `test_fail_closed.py`, `test_halt_store.py`, `test_late_effect_fence.py`, `test_prose_ignored.py` and `test_receipt_schema.py`.
  - `git grep capability_token tests` over-matches: it also finds null tokens and `test_envelope.py`, whose tool is not allowlisted, so its token is never checked.
- `tests/test_demo.py` hard-codes `0.1.0-stub`.
- New holder-only tests need a custom policy document, because the stub policy has no uncovered or mismatched holder case.

**Docs**
- `README.md`: fail-closed list and policy version.
- `SECURITY.md`: fail-closed list and policy version.
- `docs/ROADMAP.md`: "still bearer" line and version history.
- `docs/threat-model.md`: asset row, Capability-spoof defence, capability-check row, non-goal bullet.
- `eval/corpus/README.md`: the runtime `principal` now matters for token rows.
- ADR-0001: as listed under Amends.
- ADR-0002: annotate the "still bearer" residual.

**Receipt regeneration**

No receipt-regeneration tool exists on this tree, so phase 2 adds a small script. It:
1. evaluates each row;
2. rewrites only the compared receipt fields;
3. leaves `timestamp` as it is in the file, because 18 of the 24 runtime fixtures have no frozen `now`, and `timestamp` is not a compared key.

The diff is reviewed: only `policy_version`, `envelope_hash` (where the envelope's `policy_context` changed) and the intended details may change.

### Phases

A transition like ADR-0002's keeps every phase green.

| Phase | Scope | Green during transition because |
| --- | --- | --- |
| 1. Core check and new tests | `_capability_deny` enforces the checks for records that carry a valid `principals` field. Records without the field keep today's bearer behaviour, for this phase only. New tests use custom policy documents. | Stub records have no `principals` yet, so existing outcomes do not change. |
| 2. Policy, fixtures, receipts | `principals` becomes required (missing means nobody); stub `principals`; `POLICY_VERSION` 0.2.0-stub; corpus fixtures and envelopes; regeneration script and regenerated receipts; existing tests attest. | All callers that present the live token attest a listed holder. |
| 3. Docs and version 0.5.0 | Everything listed under Docs above. | Docs only. |

The branch is not merged until phase 2 lands.

### joint-eval (in the combined sibling change)

- `tests/test_evasion_alternate_paths.py` presents `ALLOWED_CAPABILITY` without attesting a principal, and several of its tests assert ALLOW. They must attest a principal so that they keep measuring the residuals they measure. Turning their expected results into DENY would hide those residuals.
- `test_capability_detail_reveals_token_state_observation` is replaced by a test that asserts the uniform non-holder detail.
- Both joint_story expected receipts (`pep_monitor_bypass_prose`, `pep_approval_binding`) change `policy_version`. `tests/test_receipts.py` compares them, so both are regenerated. `pep_monitor_bypass_prose` still denies `agent_prose_rejected`, because the prose check runs before the token. What changes is its receipt, not its outcome.
- Measured-corpus notes that quote receipt details or the policy version are checked.

### console (in the combined sibling change)

- `lab_console/witness.py` begins an invoke with `lab.cap.echo.demo` and expects ALLOW. It must attest a principal.
- Its pins move together with joint-eval's and pep's.

## Comparison experiment and acceptance

Run before and after, at named commits. "Before" is the merged ADR-0002 tree (0.4.0).

| Case | Before (0.4.0) | Required after |
| --- | --- | --- |
| Listed holder, valid token, covered tool | ALLOW | ALLOW |
| No attested principal, valid token | ALLOW | DENY `capability_missing`, "no attested principal" |
| Unlisted principal, valid token | ALLOW | DENY `capability_missing`, "capability token not valid for this caller" |
| Holder attested, envelope identity differs | ALLOW | DENY `capability_missing`, same uniform detail |
| Unknown token id, attested caller | DENY `capability_missing` "capability token unknown" | DENY `capability_missing`, same uniform detail |
| Non-holder presents an expired, uncovered, malformed-expiry or `required_capability`-mismatched token | Distinct details, or `policy_miss` | The uniform non-holder result |
| Holder presents an expired, uncovered, malformed-expiry or mismatched token (custom policy) | `capability_missing` / `capability_missing` / `capability_missing` / `policy_miss` | Unchanged |
| Token record with a missing, empty, non-array or malformed `principals` | n/a | DENY for every attested caller, uniform detail |
| Non-holder: valid token plus a valid approval bound to the attested principal | ALLOW | DENY `capability_missing`; approval **not** consumed |
| Holder: valid token plus an approval bound to another principal | DENY `approval_principal_mismatch`; not consumed | Unchanged |
| Holder: valid token plus an approval bound to the same principal | ALLOW | ALLOW |
| Official `python -m pep.demo` row | DENY `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY` | Same decision and code; `policy_version` `0.2.0-stub` |

Further acceptance requirements:
- No receipt-schema change.
- No detail echoes a principal or a token id.
- Full suites pass in pep, joint-eval and console at the bumped pins.
- The brand-wall checks are clean.
- Receipts are regenerated by the phase 2 script; the reviewed diff shows only the intended fields changed.
- Each phase diff gets an independent, cross-family review.

**Rollback:** revert the implementation commits and restore the previous pep pins in joint-eval and console.

**What success would establish:** on this tree, a standing capability token can be used only by a host-attested principal that the operator listed in policy. A caller that is not a holder learns nothing from the PEP's response about which tokens exist or their state.

**What it would not establish:**
- any measured attack-success rate;
- resistance to an in-process attacker that forges the host argument;
- correctness of the policy;
- secrecy of the published policy;
- live enforcement.
