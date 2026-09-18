# ADR-0001 — Lab host/runtime PEP architecture

- **Status:** Accepted (v0.2 foundation)
- **Date:** 2026-09-18
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

This repository is a public-goods **host/runtime Policy Enforcement Point (PEP)**. Callers submit a structured invoke envelope. The PEP is the only allow authority for tool entry. The official `eval/` row is an existence-proof **DENY** for the monitor-bypass / policy-rewrite-coax *class* (inspiration: arXiv:2609.19587). It is not a measured attack-success-rate result.

v0.2 freezes the architecture so later evaluator-corpus work (EOI milestone **M1**) and a durable kill/suspend path (v1) do not relabel this plane as a model or monitor.

## Decision

The `pep` package is a **trust domain independent of the model, an optional monitor, and any MCP / tool host**. Those planes are callers or downstream of ALLOW. They cannot mint policy, capability, or approval.

| Plane | Role relative to this PEP |
| --- | --- |
| **PEP** | `pep.evaluate` / `pep.gated_invoke`. In-process import is allowed; the function boundary is the trust boundary. |
| **Model** | Not on the evaluate path. Output is caller material, not policy. |
| **Monitor** | Optional caller or observer. A monitor “SAFE” / allow coax is not an allow authority. |
| **MCP / tool host** | Downstream of ALLOW only. Hosting a tool does not mint policy, capability, or approval. |
| **Agent / HITL UI** | Callers. Identity strings and free-text are not allow authorities. |

### Structured envelopes only

Policy-relevant input is a structured invoke envelope (Lab or flat JSON object). Agent free-text, coax keys, and attachments are **untrusted data** and never become policy. Envelope `policy_context` is fixture metadata, not a rewrite channel.

### Capability language (grants)

Allow is a **grant check**, not a judgement:

1. **Frozen catalog.** Only allowlisted tools can run. An approval cannot extend the catalog.
2. **Standing capability.** A capability token must be known, unexpired, cover the tool, and match the tool’s required capability when present.
3. **Single-use TTL approval.** An operator-issued `approval_id` is a one-shot grant for an already-catalogued tool. It has a TTL. The first successful ALLOW consumes it. Replay, expiry, unknown id, or uncovered tool → **DENY**.
4. **Neither grant.** Allowlisted tool with no capability and no approval → **DENY** (`capability_missing`). Unknown tool with both grants absent → official eval reason `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`.
5. **Presented grant must hold.** A spoofed or stale approval fails closed even if a standing capability would otherwise allow.

Prose cannot insert a capability row or an approval row.

### Fail-closed

Missing policy, unknown tool, expired or missing capability, invalid/expired/consumed approval, parse failure, PEP unavailable, **kill**, or **suspend** → **DENY + receipt**. `gated_invoke` does not enter the tool. There is no fail-open path.

### Kill and suspend

Process-local runtime modes:

- **active** — evaluate proceeds.
- **suspend** — every envelope DENY (`suspend_active`). `resume()` returns to active.
- **kill** — every envelope DENY (`kill_active`). Irreversible in-process; `resume()` cannot clear a kill.
- **unavailable** — treated as kill (`kill_active`).

Kill wins over suspend. These APIs are the v0.2 foundation for the v1 durable kill/suspend path.

### Attested receipts

Every decision emits a receipt that attests `decision`, `reason_code`, `envelope_hash`, judge path (`host_runtime_deterministic`), and negative controls (policy bytes unchanged, tool not executed, monitor coax not accepted). The public object is **frozen schema v1** (`eval/receipt.schema.json`, `pep.receipt.validate_receipt`). Additive fields require a schema bump and a new ADR. Brand on the receipt is Agent Control Lab; licence is Apache-2.0.

## Consequences

- Diligence readers can treat `pep/evaluate.py` as the enforcement plane, not a model-graded monitor.
- Official `eval/` deny (`python -m pep.demo`) stays a fail-closed DENY with the frozen receipt shape (`policy_version` remains `0.1.0-stub` on that allowlist).
- Package version `0.2.0` names the foundation (approval store, kill/suspend API, frozen receipt), not a production control plane.
- EOI **M1** (evaluator corpus) adds rows under `eval/`; it does not move allow authority onto a model or monitor.
- v1 may persist kill/suspend and approvals out of process; the grant and fail-closed rules above stay.

## Non-goals

- Not an LLM / CoT / transcript judge.
- Not production SaaS, multi-tenant control plane, marketplace adapter, live git host, or production UI.
- Not a measured ASR / classifier claim.
- Not a complete model, monitor, or MCP platform threat model — those planes are untrusted inputs here.
