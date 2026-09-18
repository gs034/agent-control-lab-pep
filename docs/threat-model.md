# Host/runtime PEP threat model (Agent Control Lab)

Public threat model for this repository’s **host/runtime Policy Enforcement Point (PEP)** plane only. It describes what the stub claims to enforce, where trust stops, and which deny controls are in code. It is not a measured evaluation and not a production assurance case.

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

## Assets

| Asset | Why it matters |
| --- | --- |
| Frozen policy bytes (`pep/policy.py`, `PolicyStore`) | Allowlist and capability records. Agents must not rewrite them. Stub catalog is `echo.ping` only. |
| Structured invoke envelope | Sole policy-relevant input. Lab fixture: `eval/structured_envelope.example.json`. |
| Capability records | Presence, expiry, and tool coverage. Missing, unknown, expired, or uncovered tokens must not become allow. |
| Single-use TTL approvals | Operator-issued grants in `ApprovalStore`. Replay, expiry, unknown id, or uncovered tool must not become allow. Approvals cannot extend the catalog. |
| Tool invoke path | Side-effecting callables (`gated_invoke`) must not run on DENY. |
| Deny/allow receipt | Frozen v1 schema. Attests `decision`, `reason_code`, `envelope_hash`, judge path, and negative controls. |
| PEP availability / kill / suspend | Process-local `PepRuntime` modes. Kill and unavailability deny as `kill_active`. Suspend denies as `suspend_active`. Resume cannot clear a kill. |

`eval/malicious_agent_prose.txt` is an asset only as **untrusted data**. It is never policy.

## Trust boundaries

```
agent / model / optional monitor / HITL UI / MCP or tool host
                         |  structured envelope only
                         v
              pep.evaluate / pep.gated_invoke     <-- PEP trust domain
                         |  ALLOW only
                         v
                     tool invoke
```

| Plane | Role relative to this PEP |
| --- | --- |
| **PEP** | `pep` package. `evaluate()` / `gated_invoke()` is the enforcement boundary. In-process import is allowed; the function boundary is the trust boundary. |
| **Model** | Not on the evaluate path. Output is caller material, not policy. |
| **Monitor** | Optional caller or observer. A monitor “SAFE” / allow coax is not an allow authority. |
| **MCP / tool host** | Downstream of ALLOW only. Hosting a tool does not mint policy, capability, or approval. |
| **Agent / HITL UI** | Callers. Identity strings and free-text are not allow authorities. |

Receipt field `trust_domain.model_monitor_mcp` is `untrusted_relative_to_pep`. Envelope `policy_context` is fixture metadata and is not loaded as a rewrite channel.

## Adversaries (this plane)

| Class | What they try | Stub stance |
| --- | --- | --- |
| **Prompt / prose injection** | Free-text, coax keys, or attachments that ask the PEP (or a co-located monitor) to ignore, rewrite, or skip policy. | Prose is data. Coax keys and non-empty prose channels are rejected. Attachments are not loaded as policy. |
| **Capability spoof** | Missing, empty, unknown, expired, or tool-uncovered tokens; forged “operator approval” in natural language; caller identity as authority. | Standing token must be known, unexpired, and cover the tool. A presented `approval_id` must exist in the PEP store, be unexpired, unused, and cover the tool. Prose cannot mint a token or approval row. |
| **Monitor coax** | Agent text that tells a monitor to classify the turn SAFE / allow so the invoke proceeds. | Evaluate path has no monitor or model judge. Coax cannot become ALLOW. Receipt records `monitor_coax_accepted: false`. |

Inspiration for the official `eval/` row is the monitor-bypass / policy-rewrite-coax *class* discussed in [arXiv:2609.19587](https://arxiv.org/abs/2609.19587). This stub is an existence-proof deny for that class, not a paper reproduction and not an attack-success-rate claim.

## Control taxonomy → fail-closed structured-envelope deny

Every control below ends in **DENY + receipt** and, when callers use `gated_invoke`, **no tool entry**. There is no “soft fail” to invoke.

| Control | Mechanism | Typical `reason_code` |
| --- | --- | --- |
| Structured envelopes only | Parse Lab or flat JSON objects. Free-text payloads and unknown/coax keys fail closed. | `envelope_invalid`, `agent_prose_rejected` |
| Prose is not policy | `untrusted_agent_text`, non-empty `metadata`, `untrusted_attachments` file bytes, and coax keys are not allowlist input. | `agent_prose_rejected` |
| Frozen allowlist | Unknown `tool_name` cannot run. Official row: `shell.exec` vs `echo.ping`. | `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`, `unknown_tool` |
| Capability check | Token (when presented) looked up, unexpired, covers the tool, matches required capability; args must match the tiny schema. | `capability_missing`, `policy_miss` |
| Single-use TTL approval | Operator-minted grant consumed on first ALLOW. Replay / expiry / unknown / uncovered tool deny. Does not unlock tools outside the catalog. | `approval_invalid`, `approval_expired`, `approval_consumed` |
| Policy present and readable | Empty store, unreadable spec, or missing schema → deny. | `policy_miss` |
| Kill / unavailable | `kill()` or `available=false` denies even an otherwise allowlisted envelope. Resume cannot clear a kill. | `kill_active` |
| Suspend | `suspend()` denies every envelope until `resume()`. | `suspend_active` |
| Parse / type failure | Null, bad JSON, malformed ids, non-object args. | `envelope_invalid` |
| Gate | `gated_invoke` calls the tool only after `allowed()`. Bypass of the helper is outside this trust domain. | (no invoke on DENY) |

Receipts also attest `fail_closed: true`, `judge.path: host_runtime_deterministic`, `llm_cot_transcript_judge: false`, `agent_prose_used_as_policy: false`, and `negative_controls_observed` (policy bytes unchanged, tool not executed, monitor coax not accepted).

## Explicit non-goals

This document and this repository do **not** claim:

- Enforcement by an LLM, chain-of-thought, or transcript judge.
- A production control plane, multi-tenant SaaS, or shipping product.
- Marketplace adapters, live git hosts, or a production UI.
- Measured attack-success-rate, classifier quality, or paper-figure reproduction.
- That callers who skip `gated_invoke` are still enforced (they are outside the PEP boundary).
- Confidentiality of policy bytes against a hostile process that can write the PEP’s memory or disk.
- A complete MCP, model, or monitor threat model — those planes are untrusted *inputs* here, not assets this stub defends as a platform.

See `SECURITY.md` for the fail-closed default and how to report issues. See `README.md` for how to reproduce the official deny.
