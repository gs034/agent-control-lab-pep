# Roadmap (Agent Control Lab host/runtime PEP)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**. This is a public-goods reference PEP, not a shipping product.

Versions below are **lab milestones**, not a vendor SKU. Package `0.6.0` lets an approval bind the implementation resolved at mint (ADR-0004). `0.5.0` binds every standing capability token to its policy-listed, host-attested holders, and moves the stub policy to `0.2.0-stub` (ADR-0003). `0.4.0` binds every approval to a host-attested principal (ADR-0002). `0.3.3` adds an optional state digest to approval binding. `0.3.2` is a patch on v0.3.1 (in-process late-effect fence after kill). `0.3.1` remains the approval-binding patch on v0.3 / EOI **M1**. The official allowlist / eval receipt attests `policy_version: 0.2.0-stub` (it was `0.1.0-stub` before 0.5.0).

## stub (published 0.1)

Existence-proof host/runtime deny over structured envelopes.

- Frozen allowlist (`echo.ping` only); capability tokens with expiry.
- `evaluate()` / `gated_invoke()` trust boundary; no model on the evaluate path.
- Official `eval/` row: `shell.exec` + null grants → **DENY** (`TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`).
- `python -m pep.demo` prints the live fail-closed receipt.
- Lab-only brand wall and forbidden-token CI.

## v0.2 foundation

Architecture freeze plus in-process enforcement APIs. See [`docs/adr/ADR-0001-lab-pep-architecture.md`](adr/ADR-0001-lab-pep-architecture.md).

| Work | Status |
| --- | --- |
| ADR-0001 (host/runtime PEP, separate trust domain, structured envelopes, fail-closed, kill/suspend, attested receipts) | In tree |
| Single-use TTL approval path (`PepRuntime.issue_approval`, envelope `approval_id`; v0.3.1 binds tool + canonical args) | In tree |
| Kill / suspend API (`kill`, `suspend`, `resume`; kill irreversible) | In tree |
| Frozen receipt schema v1 (`eval/receipt.schema.json`, `validate_receipt`) | In tree |
| Official demo remains fail-closed **DENY** | Required invariant |

## v0.3 / M1 (this tree)

Evaluator corpus plus a durable kill/suspend store. Same PEP trust domain (`pep.evaluate` / `pep.gated_invoke`). Receipt schema stays frozen v1.

| Work | Status |
| --- | --- |
| `eval/corpus/` deny classes: prose-as-policy, capability spoof, monitor coax, missing policy, kill/suspend, approval replay / TTL | In tree |
| Allowlisted **ALLOW** fixture that cannot rewrite the catalog | In tree |
| Durable halt store (`pep.halt.HaltStore` JSON file; survives process restart) | In tree |
| `resume` cannot clear a kill (including after reload) | In tree |
| Unavailable PEP remains fail-closed DENY | In tree |
| Operator API stays kill / suspend / resume — no product UI | In tree |
| Official `python -m pep.demo` DENY unchanged | Required invariant |

Corpus rows stay host/runtime deterministic. No LLM/CoT/transcript judge as enforcement. Still not a measured attack-success-rate claim.

## v0.3.1 / approval binding (this tree)

Same PEP trust domain. A HITL/TTL approval is not a control if the operation presented for approval is not exactly what later executes (Loopjacking-class representation mismatch / post-approval state-substitution; existence-proof threat pattern: [arXiv:2609.21081](https://arxiv.org/abs/2609.21081); not a measured ASR claim).

| Work | Status |
| --- | --- |
| Mint freezes `tool_name` + canonical args digest on `ApprovalRecord` | In tree |
| `try_consume` / `evaluate` require exact binding; mismatch → `approval_binding_mismatch` | In tree |
| Prose / `policy_context` / untrusted attachments ignored for binding | In tree |
| Corpus: mutated args DENY; exact bind ALLOW then single-use consume / replay DENY | In tree |
| Official `python -m pep.demo` DENY unchanged | Required invariant |

## v0.3.2 / late-effect fence (this tree)

Same PEP trust domain. `kill()` must fence late effects, not only flip the halt bit. Existence-proof for the authorization-revocation / quiescence class ([arXiv:2609.21284](https://arxiv.org/abs/2609.21284); not a measured attack-success-rate claim).

| Work | Status |
| --- | --- |
| `kill()` engages an in-process cut epoch (fence) as well as mode `killed` | In tree |
| `begin_invoke` / `complete_invoke`; one-shot entry permit under the runtime lock before `tool()`; replay DENY `admission_consumed` | In tree |
| Pre-cut admission completed after kill → DENY `late_effect_fence` (`cut+fence` in the detail). No tool entry | In tree |
| Fresh post-kill evaluate stays `kill_active`. ALLOW is published only under the runtime lock after a fence re-check | In tree |
| Corpus row `eval/corpus/late_effect_fence/` and `python -m pep.demo --late-effect-fence` | In tree |
| Receipt schema stays frozen v1 (no new fields) | Required invariant |
| Official `python -m pep.demo` DENY unchanged | Required invariant |

Still open on this patch: once `tool()` has started, that call is not preempted or rolled back; a process-external callback that skips `complete_invoke` is outside the trust domain; `HaltStore` does not reconstruct another process’s admissions (reload denies new work as `kill_active` only). Also deferred: an approval may be consumed before a later suspend or kill deny, so the grant is spent without ALLOW; `_spent_admissions` is unbounded for a long-lived runtime.

## v0.3.3 / approval state digest (this tree)

Same PEP trust domain. Binding `tool_name` plus canonical args closes the Loopjacking-class representation mismatch, not its second failure mode: the approved operation is unchanged but the object it acts on is swapped between approval and execute (post-approval state substitution; [arXiv:2609.21081](https://arxiv.org/abs/2609.21081) as a pattern name; not a measured ASR claim).

| Work | Status |
| --- | --- |
| `issue_approval(..., state_digest=)` freezes a host-computed `sha256:` digest of the target state on `ApprovalRecord` (optional) | In tree |
| Envelope `schema_fields.state_digest` (Lab form) / `state_digest` (flat form) carries the host-observed digest; it is not part of args and prose cannot supply it | In tree |
| `state_observer` callable on `evaluate` / `begin_invoke` / `gated_invoke`: `ApprovalStore.consume` calls it under the store lock after existence, single-use, expiry and binding checks pass; it overrides the envelope field, is never called for grants without a frozen digest or for grants that fail an earlier check, and a raise or non-digest return is a mismatch (receipt detail says `state observer failed` or `... mismatch`). The observer runs with the store lock held: it must be quick and must not call back into the store or runtime; a callback into the store is refused as `state observer re-entered store` rather than deadlocking | In tree |
| `begin_invoke` keeps the observer on the `PendingInvoke`; `complete_invoke` reads the fence first (a cut denies `late_effect_fence` and skips the observer), then re-observes at tool entry when the admission consumed a frozen digest, and a changed target is DENY `approval_state_mismatch` with the grant already spent (same shape as a suspend after consume) | In tree |
| `try_consume` requires an equal observed digest when one was frozen; missing or different → `approval_state_mismatch`, grant not consumed; args mismatch still reports first | In tree |
| Grants without a frozen digest ignore any envelope digest (behaviour of every existing row unchanged) | In tree |
| Corpus: `approval_state_substitution` DENY and `allow_approval_state_bound` ALLOW-then-consume | In tree |
| Corpus: threat-model classes named in the joint-eval [measured-corpus v0 seed](https://github.com/gs034/agent-control-lab-joint-eval/blob/main/docs/measured-corpus-v0.md) as rows, no new mechanism: `multi_session_plant` (planted prior-session grant → `approval_invalid`) and `deferred_tool` (effect fires after the checked turn's TTL → `approval_expired`) | In tree |
| Receipt schema stays frozen v1 (new reason code only) | Required invariant |
| Official `python -m pep.demo` DENY unchanged | Required invariant |

Still open: the digest is host-computed. With the observer the read happens inside the approval store's consume step, after the grant has passed its other checks, and again at tool entry in `complete_invoke`, which narrows the window between check and use to the re-observation itself; without it the envelope value is whatever the host wrote when it built the envelope. In both cases the PEP does not read the target and cannot verify that the host's observer digests the right object; a host that lies is outside the trust domain like a caller that skips `gated_invoke`. What counts as "the state" is the operator's definition at mint time, not the PEP's.

## v0.4.0 / approval principal binding

Same PEP trust domain. [ADR-0002](adr/ADR-0002-approval-principal-binding.md) closes the Delegation class from Approval Laundering ([arXiv:2609.38983v1](https://arxiv.org/abs/2609.38983v1), class inspiration only; not a measured ASR claim). Before this release, an approval was a bearer grant that any caller presenting the id could spend.

| Work | Status |
| --- | --- |
| `issue_approval(..., principal=)` is required; mint without a valid principal raises `ApprovalError` | In tree |
| Host-attested `principal=` on `evaluate` / `begin_invoke` / `gated_invoke` / `consume` / `try_consume`. It is never read from the envelope. On the `evaluate` route a malformed value is `envelope_invalid`; a direct `consume` call treats it as a mismatch | In tree |
| Principal check under the store lock, straight after the lookup. A missing or wrong principal, or an envelope identity that disagrees, is `approval_principal_mismatch`, does not consume, and the detail names no identity | In tree |
| Corpus fixtures name the grant principal and the attested principal; envelopes and expected receipts are unchanged | In tree |
| Receipt schema stays frozen v1 (new reason code only) | Required invariant |
| Joint-eval `story.py` passes a principal; joint-eval and console pins move to the 0.4.0 commit | Pending (separate change) |

Still open at 0.4.0: an in-process caller can pass any principal; standing capability tokens were still bearer (closed in 0.5.0); effects below the tool boundary are unchanged.

## v0.5.0 / capability token holders

Same PEP trust domain. [ADR-0003](adr/ADR-0003-capability-token-principal-binding.md) removes the bearer property of standing capability tokens. Before this release a token was multi-use, its id was a public policy key, and the deny details told any caller whether a guessed id existed and what state it was in.

| Work | Status |
| --- | --- |
| Every `capability_tokens` record lists `principals`, a non-empty array of identities. If it is missing, empty, not an array or holds a malformed entry, the record authorises nobody | In tree |
| `_capability_deny` checks for a host-attested principal before the lookup (`no attested principal`). An unknown token, a non-holder and a disagreeing envelope identity then all give one detail, `capability token not valid for this caller`. Only holders reach the expiry, coverage and required-capability checks | In tree |
| Stub tokens list `lab.demo.agent`; `POLICY_VERSION` is `0.2.0-stub`; fixture envelopes carry the new version | In tree |
| `scripts/regen_corpus_receipts.py` rewrites the compared receipt fields and `envelope_hash` from live evaluation and keeps timestamps; `--check` exits 1 on drift | In tree |
| Receipt schema stays frozen v1 (no new reason code) | Required invariant |
| joint-eval and console attest principals for token callers; their pins move to the merged pep commit together with the ADR-0002 change | Pending (one combined sibling change) |

Still open at 0.5.0: an in-process caller can pass any principal; the published policy lists every token id, holder and expiry; shared holder lists are shared; expiry policy is unchanged.

## v0.6.0 / approval implementation binding (this tree)

Same PEP trust domain. [ADR-0004](adr/ADR-0004-approval-implementation-binding.md) lets a single-use approval bind the implementation its tool name resolves to at mint. Before this release, a `PATH` reorder between mint and tool entry ran a different program under the same grant (`test_path_resolution_substitution_is_residual`).

| Work | Status |
| --- | --- |
| `issue_approval(..., implementation_digest=)` is optional per grant; a malformed value raises `ApprovalError` | In tree |
| Host-only `implementation_observer=` on `evaluate` / `begin_invoke` / `gated_invoke`, and `observe_implementation=` on `consume` / `try_consume`. No envelope field: a top-level `implementation_digest` key is `envelope_invalid` in both shapes, and one inside a lab envelope's `schema_fields` is dropped and never read | In tree |
| Consume checks it after the binding and before the state check, under the store lock. Missing, raising, non-digest or different observations, and observer re-entry, are `approval_implementation_mismatch` and do not consume. Earlier exits never call the observer | In tree |
| `complete_invoke` checks the fence, then whether the admission was already spent, then the implementation, then the state. An entry mismatch, including a missing entry observer, denies with the grant spent | In tree |
| `pep/implementation.py`: optional host helpers `executable_digest` and `callable_digest` | In tree |
| Receipt schema stays frozen v1 (new reason code only); corpus receipts and `POLICY_VERSION` unchanged | Required invariant |
| Measured added cost of a bound `gated_invoke` with `executable_digest`: 129.7 µs median over 2,000 runs, local container | Measured |

Still open: grants minted without a digest; the check-to-exec race after the entry check; implementations that were already unsafe at mint; capability-token invokes, which have no mint moment (a per-tool policy pin is a candidate later ADR); a host that misreports its observation. No sibling pin needs to move, because the change is additive.

## Remaining v1 notes

v1 may persist single-use TTL approvals out of process. Catalog extension, marketplace adapters, and production UI remain non-goals.

## Invariants that do not move

1. Deny path is host/runtime policy, not a model judge.
2. PEP trust domain is independent of model / monitor / MCP host.
3. Structured envelopes only; agent prose is data.
4. Fail-closed: miss, expiry, kill, late effect after kill, suspend, PEP down → DENY + receipt; no tool entry.
5. Brand: Agent Control Lab. Apache-2.0. Lab-only keep-out stays green.
