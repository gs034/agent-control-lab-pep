# Roadmap (Agent Control Lab host/runtime PEP)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**. This is a public-goods reference PEP, not a shipping product.

Versions below are **lab milestones**, not a vendor SKU. Package `0.3.1` is a patch on v0.3 / EOI **M1** (approval invoke binding). The official allowlist / eval receipt still attests `policy_version: 0.1.0-stub`.

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

## Remaining v1 notes

v1 may persist single-use TTL approvals out of process. Catalog extension, marketplace adapters, and production UI remain non-goals.

## Invariants that do not move

1. Deny path is host/runtime policy, not a model judge.
2. PEP trust domain is independent of model / monitor / MCP host.
3. Structured envelopes only; agent prose is data.
4. Fail-closed: miss, expiry, kill, suspend, PEP down → DENY + receipt; no tool entry.
5. Brand: Agent Control Lab. Apache-2.0. Lab-only keep-out stays green.
