# ADR-0003: Bind standing capability tokens to host-attested principals

- **Status:** Proposed. The owner asked for this ADR on 2026-10-04, after ADR-0002. It is not implemented on this tree.
- **Date:** 2026-10-04
- **Depends on:** [ADR-0002](ADR-0002-approval-principal-binding.md), which supplies the host-attested `principal` argument.
- **Amends:** ADR-0001 "Capability language" item 2 and the "Fail-closed" list.
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

ADR-0001 item 2 makes a standing capability token a grant. The token must be known, unexpired, cover the tool, and match the tool's `required_capability` when the tool names one. Tokens are records in the frozen policy document (`capability_tokens` in `pep/policy.py`). The envelope carries the token id (`capability_token`), and `_capability_deny` in `pep/evaluate.py` checks it.

The checks never ask who is presenting the token, so on this tree a capability token is a bearer credential. ADR-0002 closed the same gap for single-use approvals, but tokens are the wider gap:

- **Multi-use.** An approval is spent once. A token allows every matching invoke until it expires; the stub token `lab.cap.echo.demo` expires in 2099.
- **Not secret.** The token id is a policy key. It appears in the public policy document, in corpus envelopes, in joint-eval fixtures and in the console witness (`lab_console/witness.py`). Knowing the id is the whole credential.
- **Deny details leak token state.** For an unknown token the detail is "capability token unknown"; for an expired one it is "capability token expired". Uncovered tools and `required_capability` mismatches give different details again: `capability_missing` against `policy_miss`. Any caller can learn which guessed ids exist and what state they are in. Joint-eval pins this as an observation: `tests/test_evasion_alternate_paths.py::test_capability_detail_reveals_token_state_observation`.

The ADR-0002 residuals already name this: "Standing capability tokens are still bearer."

## Decision

Each capability token in policy names the principals that may present it. Only a call whose host-attested principal is one of them can use the token.

1. **Policy.**
   - Every `capability_tokens` record gains a required `principals` field: a non-empty list of identities matching `IDENTITY_RE`.
   - A record with a missing, empty or malformed `principals` field authorises nobody (fail closed).
   - The binding lives in operator-authored policy, not in a mint call. Tokens stay standing and multi-use; this ADR changes who may use them, not how long they last.
2. **Attest.** The host-attested `principal` from ADR-0002 is used unchanged. It is the same function argument on `evaluate`, `begin_invoke` and `gated_invoke`, never an envelope field.
3. **Check order.** In `_capability_deny`:
   - Look up the token. Then, before the expiry, coverage and `required_capability` checks, require all three of the following:
     - a host principal is attested;
     - it is in the record's `principals`;
     - the envelope identity equals it.
   - **An unknown token and a failed principal check give the same result:** DENY `capability_missing` with one detail, "capability token not valid for this caller". A caller who is not a holder learns nothing: not whether the id exists, not whether it has expired, and not what it covers.
   - Only a listed holder gets the specific details:
     - expired: `capability_missing`;
     - does not cover the tool: `capability_missing`;
     - does not match the tool policy: `policy_miss`.
   - No new reason code is needed.
4. **Interaction with approvals.** The order inside `evaluate` is unchanged. A presented token is checked first, and a presented `approval_id` is consumed after the args schema check, with the ADR-0002 principal check. An envelope that carries both must pass both under the same attested principal.
5. **Policy version.** Adding `principals` changes the policy bytes and their meaning. `STUB_POLICY_DOCUMENT` moves from `policy_version` `0.1.0-stub` to `0.2.0-stub`.
   - Every receipt that attests the policy version changes with it. That covers every corpus expected receipt and the official `eval/` row.
   - No tool regenerates expected receipts on this tree. Phase 2 adds a small script that evaluates each row and rewrites its expected receipt. The resulting diff is reviewed so that only the intended fields change; receipts are not hand-edited.
   - A receipt that still said `0.1.0-stub` for a policy that now binds principals would misdescribe what was enforced.
6. **Receipts.** Schema v1 does not change. The reason codes stay the same; only `reason_detail` text changes for non-holders, and no detail echoes a principal or a token id.
7. **Version.** The package moves to 0.5.0. Adding the policy field and changing deny behaviour is a breaking change for any caller that presents tokens without attesting a principal.

## Options considered

| Option | What it binds | Assessment |
| --- | --- | --- |
| **A. Policy-listed holders, host-attested principal (chosen)** | Each token's `principals` list in frozen policy | The binding sits with the rest of capability policy, which is operator-authored and digest-attested. It reuses the ADR-0002 attestation channel and adds no key material. |
| B. Per-session tokens minted by the host, like approvals | A runtime record per principal | Duplicates the approval store for a standing grant and moves capability authority out of the frozen policy, which ADR-0001 keeps as the source of truth. Rejected. |
| C. Secret or keyed tokens (random ids, HMAC) | Possession of a secret | This makes possession harder, but it is still bearer: anyone holding the secret, including a delegate it was passed to, can use it. The secret would also share a process with the attacker that ADR-0002 already excludes. Rejected. |
| D. Keep bearer tokens and document them | Nothing | Leaves a multi-use, public-id credential that is weaker than the approvals ADR-0002 just bound. Rejected. |
| E. Uniform deny details only, no binding | Nothing | Closes the oracle but not the bearer gap. It is folded into A as decision 3. |

## Residuals (what this does not fix)

- **In-process callers can still claim any principal.** As in ADR-0002, code with the same process access can pass any `principal` to `evaluate`. The binding defends host routes that assign per-session principals, not equivalent-access callers.
- **A token listing several principals is shared among them.** The PEP does not tell listed holders apart beyond their identity, so policy authors should list the narrowest set.
- **Policy authorship is trusted.** An operator who lists the wrong principal grants them the capability. The PEP enforces policy; it does not audit it.
- **Holders still get specific details.** A listed holder can still tell an expired token from an uncovered tool. This is accepted, because holders are the principals the operator assigned.
- **Expiry is unchanged.** Long-lived tokens such as the stub's 2099 expiry stay long-lived. Shortening them is a policy decision, not part of this ADR.

## Consequences and dependent changes

### pep (this repository)

- `pep/policy.py`:
  - `principals` on the stub token records;
  - `policy_version` set to `0.2.0-stub`.
- `pep/evaluate.py`:
  - `_capability_deny` takes the attested principal and the envelope identity;
  - the new early check;
  - the uniform non-holder detail.
- `eval/corpus/`: runtime fixtures for token rows gain a top-level `principal`. All expected receipts are regenerated for the policy version, and token rows also change detail where the caller is not a holder (for example `capability_spoof`).
- The official `eval/` row's expected receipt is regenerated (`policy_version`).
- `README.md` and `docs/ROADMAP.md`: the stated policy version and its history.
- `docs/threat-model.md`: the Capability-spoof defence; the non-goal bullet; the capability-check row.
- ADR-0001: item 2, the Fail-closed list, and the Consequences line that says `policy_version` remains `0.1.0-stub`.
- Tests that present tokens: they now attest `lab.demo.agent`.
  - Today these are `tests/test_approval.py`, `test_deny_path.py`, `test_envelope.py`, `test_fail_closed.py`, `test_halt_store.py`, `test_late_effect_fence.py`, `test_prose_ignored.py` and `test_receipt_schema.py`.
  - Find the full list with `git grep capability_token tests`.

This is well over five files, so implementation would be phased. Expected receipts and fixtures are mechanical.
1. Core check and new tests, with `principals` read but the version unchanged.
2. Policy field, policy version, fixtures and regenerated receipts.
3. Docs and the version bump.

### joint-eval

- `eval/joint_story/pep_monitor_bypass_prose` presents `lab.cap.echo.demo`, so the story must attest a principal.
- `tests/test_evasion_alternate_paths.py::test_capability_detail_reveals_token_state_observation` will fail on the bump, as intended. It is replaced by a test that asserts the uniform detail.
- The measured-corpus notes that quote receipt details or the policy version need checking.
- The pin moves to the merged pep commit.

### console

- `lab_console/witness.py` builds an envelope with `lab.cap.echo.demo` for the PEP admit colour. It must attest a principal, or its expected ALLOW becomes DENY.
- The pins move with joint-eval and pep.

## Comparison experiment and acceptance

Run before and after at named commits. The "before" commit is the merged ADR-0002 tree.

| Case | Before (0.4.0) | Required after |
| --- | --- | --- |
| Listed holder presents a valid token for a covered tool | ALLOW | ALLOW (unchanged) |
| Unlisted principal presents a valid token | ALLOW | DENY `capability_missing`, "capability token not valid for this caller" |
| No attested principal, valid token | ALLOW | DENY `capability_missing`, same detail |
| Holder attested, envelope identity differs | ALLOW | DENY `capability_missing`, same detail |
| Unknown token id, any caller | DENY `capability_missing` "capability token unknown" | DENY `capability_missing`, same uniform detail |
| Non-holder presents an expired, uncovered or `required_capability`-mismatched token | Distinct details or codes | The uniform non-holder result: no oracle |
| Holder presents an expired / uncovered / mismatched token | `capability_missing` / `capability_missing` / `policy_miss` | Unchanged |
| Token record with missing, empty or malformed `principals` | n/a | DENY for every caller, with the uniform detail |
| Token and approval in one envelope, both bound to the attested principal | ALLOW | ALLOW |
| Token and approval in one envelope, approval bound to another principal | n/a | DENY `approval_principal_mismatch`; grant not consumed |
| Official `python -m pep.demo` row | DENY `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY` | Same decision and code; receipt `policy_version` `0.2.0-stub` |

The change is also accepted only when all of the following hold:
- No receipt-schema change.
- No detail echoes a principal or a token id.
- Full suites pass in pep, joint-eval and console at the bumped pins.
- The brand-wall checks are clean.
- Expected receipts are regenerated by the phase 2 script, not by hand, and the diff shows that only `policy_version` and the intended non-holder details changed.
- Every phase diff gets an independent cross-family review.

**Rollback:** revert the implementation commits, and restore the previous pep pins in joint-eval and console.

**What success would establish:** on this tree, a standing capability token can be used only by a principal that the operator listed in policy, attested by the host. A caller that is not a holder learns nothing about which tokens exist or what state they are in.

**What it would not establish:**
- any measured attack-success rate;
- resistance to an in-process attacker who forges the host argument;
- correctness of the policy itself;
- live enforcement.
