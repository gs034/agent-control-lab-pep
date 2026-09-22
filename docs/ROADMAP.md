# Roadmap (Agent Control Lab host/runtime PEP)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**. This is a public-goods reference PEP, not a shipping product.

Versions below are **lab milestones**, not a vendor SKU. Package `0.3.3` adds an optional state digest to approval binding. `0.3.2` is a patch on v0.3.1 (in-process late-effect fence after kill). `0.3.1` remains the approval-binding patch on v0.3 / EOI **M1**. The official allowlist / eval receipt still attests `policy_version: 0.1.0-stub`.

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
| `try_consume` requires an equal observed digest when one was frozen; missing or different → `approval_state_mismatch`, grant not consumed; args mismatch still reports first | In tree |
| Grants without a frozen digest ignore any envelope digest (behaviour of every existing row unchanged) | In tree |
| Corpus: `approval_state_substitution` DENY and `allow_approval_state_bound` ALLOW-then-consume | In tree |
| Receipt schema stays frozen v1 (new reason code only) | Required invariant |
| Official `python -m pep.demo` DENY unchanged | Required invariant |

Still open: the digest is host-computed and host-observed; the PEP does not read the target itself, so a host that computes the digest over the wrong object, or that omits it where the operator froze one, is outside this control (the omission case fails closed). What counts as "the state" is the operator's definition at mint time, not the PEP's.

## Remaining v1 notes

v1 may persist single-use TTL approvals out of process. Catalog extension, marketplace adapters, and production UI remain non-goals.

## Invariants that do not move

1. Deny path is host/runtime policy, not a model judge.
2. PEP trust domain is independent of model / monitor / MCP host.
3. Structured envelopes only; agent prose is data.
4. Fail-closed: miss, expiry, kill, late effect after kill, suspend, PEP down → DENY + receipt; no tool entry.
5. Brand: Agent Control Lab. Apache-2.0. Lab-only keep-out stays green.
