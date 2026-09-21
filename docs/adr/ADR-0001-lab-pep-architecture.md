# ADR-0001 — Lab host/runtime PEP architecture

- **Status:** Accepted (v0.3.2 / late-effect fence; v0.3.1 approval invoke binding remains)
- **Date:** 2026-09-21
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

This repository is a public-goods **host/runtime Policy Enforcement Point (PEP)**. Callers submit a structured invoke envelope. The PEP is the only allow authority for tool entry. The official `eval/` row is an existence-proof **DENY** for the monitor-bypass / policy-rewrite-coax *class* (inspiration: arXiv:2609.19587). It is not a measured attack-success-rate result.

v0.2 froze the architecture so evaluator-corpus work (EOI milestone **M1**) and a durable kill/suspend path do not relabel this plane as a model or monitor. v0.3 lands those two items on the same trust boundary. v0.3.1 keeps that plane and binds single-use TTL approvals to the approved invoke. v0.3.2 keeps that plane and fences late effects after `kill()`.

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
3. **Single-use TTL approval.** An operator-issued `approval_id` is a one-shot grant for an already-catalogued **invoke**. Mint freezes `tool_name` plus canonical JSON args (`pep.canonical` / `sha256_prefixed`). The first successful ALLOW of that exact binding consumes it. Replay, expiry, unknown id, uncovered tool, or a post-mint args substitution → **DENY**. `policy_context` and untrusted attachments are not part of the binding. This closes the Loopjacking-class gap where a HITL/TTL approval is not a control if the operation presented for approval is not exactly what later executes (existence-proof threat pattern: [arXiv:2609.21081](https://arxiv.org/abs/2609.21081); not a measured attack-success-rate claim).
4. **Neither grant.** Allowlisted tool with no capability and no approval → **DENY** (`capability_missing`). Unknown tool with both grants absent → official eval reason `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`.
5. **Presented grant must hold.** A spoofed or stale approval fails closed even if a standing capability would otherwise allow.

Prose cannot insert a capability row or an approval row.

### Fail-closed

Missing policy, unknown tool, expired or missing capability, invalid/expired/consumed/binding-mismatched approval, parse failure, PEP unavailable, **kill**, or **suspend** → **DENY + receipt**. `gated_invoke` does not enter the tool. There is no fail-open path.

### Kill and suspend

Runtime modes:

- **active** — evaluate proceeds.
- **suspend** — every envelope DENY (`suspend_active`). `resume()` returns to active.
- **kill** — every new envelope DENY (`kill_active`). Irreversible; `resume()` cannot clear a kill. The same call engages an in-process late-effect fence (below).
- **unavailable** — treated as kill (`kill_active`) for a new evaluate. It does not by itself bump the cut epoch.

Kill wins over suspend. Process-local mode is the default. Optional `HaltStore` (JSON file) persists mode and availability so a new `PepRuntime` on the same path reloads the halt. Corrupt or unreadable store bytes fail closed to kill. Operator API stays capability language: kill, suspend, resume — not a product console.

### Late-effect fence (v0.3.2)

`kill()` is a **cut** (mode `killed`, sticky) **and** a **fence** (in-process cut epoch, bumped once). Receipt schema stays frozen v1. The fence signal is `reason_code: late_effect_fence` plus `reason_detail` containing `cut+fence`. That deny is not `kill_active`.

| Moment | Result |
| --- | --- |
| New `evaluate` / `gated_invoke` after the cut | DENY `kill_active`. No tool entry. |
| `begin_invoke` before the cut, `complete_invoke` after it (queue or callback) | DENY `late_effect_fence`. No tool entry. |
| `kill()` during `evaluate`, before ALLOW is returned | DENY `late_effect_fence` if the admission epoch is already stale. |
| `complete_invoke` with no kill | Tool runs only when the admission was ALLOW and `claim_entry` recorded a one-shot permit under the runtime lock before the call. |
| Second `complete_invoke` on that same admission | DENY `admission_consumed`. The tool is entered at most once. |

`gated_invoke` is begin then complete, so tool entry uses the same permit. The fence check and the permit are one locked transition: `kill()` cannot grant a permit after the cut, and a replay cannot take a second permit. `HaltStore` does not store the epoch or the ticket. A restarted process denies new work as `kill_active`. It does not rebuild another process’s queue.

This is an existence-proof control for the authorization-revocation / quiescence class ([arXiv:2609.21284](https://arxiv.org/abs/2609.21284); not a measured attack-success-rate claim). It does not preempt a tool body that has already been entered, and it does not fence a process-external callback that never re-enters `complete_invoke`.

### Attested receipts

Every decision emits a receipt that attests `decision`, `reason_code`, `envelope_hash`, judge path (`host_runtime_deterministic`), and negative controls (policy bytes unchanged, tool not executed, monitor coax not accepted). The public object is **frozen schema v1** (`eval/receipt.schema.json`, `pep.receipt.validate_receipt`). Additive fields require a schema bump and a new ADR. Brand on the receipt is Agent Control Lab; licence is Apache-2.0.

## Consequences

- Diligence readers can treat `pep/evaluate.py` as the enforcement plane, not a model-graded monitor.
- Official `eval/` deny (`python -m pep.demo`) stays a fail-closed DENY with the frozen receipt shape (`policy_version` remains `0.1.0-stub` on that allowlist).
- Package version `0.3.2` names the late-effect fence on the v0.3.1 / approval-binding tree, not a production control plane. `0.3.1` remains the approval-binding patch.
- EOI **M1** (evaluator corpus) adds rows under `eval/corpus/`; v0.3.1 adds approval-binding rows on the same path. The official demo row stays at `eval/` root. Allow authority does not move onto a model or monitor.
- Approvals may later persist out of process; the grant and fail-closed rules above stay.

## Non-goals

- Not an LLM / CoT / transcript judge.
- Not production SaaS, multi-tenant control plane, marketplace adapter, live git host, or production UI.
- Not a measured ASR / classifier claim.
- Not a complete model, monitor, or MCP platform threat model — those planes are untrusted inputs here.
