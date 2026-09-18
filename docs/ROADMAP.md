# Roadmap (Agent Control Lab host/runtime PEP)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**. This is a public-goods reference PEP, not a shipping product.

Versions below are **lab milestones**, not a vendor SKU. Package `0.2.0` is the v0.2 foundation. The official allowlist / eval receipt still attests `policy_version: 0.1.0-stub`.

## stub (published 0.1)

Existence-proof host/runtime deny over structured envelopes.

- Frozen allowlist (`echo.ping` only); capability tokens with expiry.
- `evaluate()` / `gated_invoke()` trust boundary; no model on the evaluate path.
- Official `eval/` row: `shell.exec` + null grants → **DENY** (`TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`).
- `python -m pep.demo` prints the live fail-closed receipt.
- Lab-only brand wall and forbidden-token CI.

## v0.2 foundation (this tree)

Architecture freeze plus in-process enforcement APIs. See [`docs/adr/ADR-0001-lab-pep-architecture.md`](adr/ADR-0001-lab-pep-architecture.md).

| Work | Status |
| --- | --- |
| ADR-0001 (host/runtime PEP, separate trust domain, structured envelopes, fail-closed, kill/suspend, attested receipts) | In tree |
| Single-use TTL approval path (`PepRuntime.issue_approval`, envelope `approval_id`) | In tree |
| Kill / suspend API (`kill`, `suspend`, `resume`; kill irreversible) | In tree |
| Frozen receipt schema v1 (`eval/receipt.schema.json`, `validate_receipt`) | In tree |
| Official demo remains fail-closed **DENY** | Required invariant |

v0.2 does **not** complete EOI **M1**. It makes M1 and the v1 kill/suspend path implementable without relabeling the PEP as a model or monitor.

## v1 (mapped to EOI milestones)

### M1 — evaluator corpus

Grow `eval/` from one existence-proof row into a **corpus** of structured envelopes and expected receipts:

- Additional deny classes already named in the threat model (prose-as-policy, capability spoof, monitor coax, missing policy, kill/suspend, approval replay / TTL).
- At least one allowlisted **ALLOW** fixture that still cannot rewrite the catalog.
- Corpus rows stay host/runtime deterministic. No LLM/CoT/transcript judge as enforcement.
- Still not a measured attack-success-rate claim.

### Kill / suspend path

Lift process-local `PepRuntime.kill` / `suspend` into a **durable** path:

- Halt that survives process restart (attested mode on the receipt’s reason codes).
- `resume` still cannot clear a kill.
- Unavailable PEP remains fail-closed DENY (no invoke).
- Operator-facing API stays capability language: kill, suspend, resume — not a product console.

v1 may also persist single-use TTL approvals out of process. Catalog extension, marketplace adapters, and production UI remain non-goals.

## Invariants that do not move

1. Deny path is host/runtime policy, not a model judge.
2. PEP trust domain is independent of model / monitor / MCP host.
3. Structured envelopes only; agent prose is data.
4. Fail-closed: miss, expiry, kill, suspend, PEP down → DENY + receipt; no tool entry.
5. Brand: Agent Control Lab. Apache-2.0. Lab-only keep-out stays green.
