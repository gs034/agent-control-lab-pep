# Host/runtime PEP threat model (Agent Control Lab)

Public threat model for this repository’s **host/runtime Policy Enforcement Point (PEP)** plane only. It describes what the stub claims to enforce, where trust stops, and which deny controls are in code. It is not a measured evaluation and not a production assurance case.

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

## Assets

| Asset | Why it matters |
| --- | --- |
| Frozen policy bytes (`pep/policy.py`, `PolicyStore`) | Allowlist and capability records. Agents must not rewrite them. Stub catalog is `echo.ping` only. |
| Structured invoke envelope | Sole policy-relevant input. Lab fixture: `eval/structured_envelope.example.json`. |
| Capability records | Presence, expiry, and tool coverage. Missing, unknown, expired, or uncovered tokens must not become allow. |
| Single-use TTL approvals | Operator-issued grants in `ApprovalStore`, each frozen to one invoke (`tool_name` + canonical args). Replay, expiry, unknown id, uncovered tool, or post-mint args substitution must not become allow. Approvals cannot extend the catalog. |
| Tool invoke path | Side-effecting callables (`gated_invoke`, and `complete_invoke` after `begin_invoke`) must not run on DENY. A pre-cut admission must not enter the tool after `kill()`. |
| Deny/allow receipt | Frozen v1 schema. Attests `decision`, `reason_code`, `envelope_hash`, judge path, and negative controls. |
| PEP availability / kill / suspend / fence | `PepRuntime` modes, optionally persisted by `HaltStore` (JSON file). Kill and unavailability deny new work as `kill_active`. `kill()` also engages an in-process late-effect fence so a pre-cut admission denies as `late_effect_fence`. Suspend denies as `suspend_active`. Resume cannot clear a kill, including after process restart. The fence epoch is process-local and is not stored in the halt file. |

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
| **Capability spoof** | Missing, empty, unknown, expired, or tool-uncovered tokens; forged “operator approval” in natural language; caller identity as authority. | Standing token must be known, unexpired, and cover the tool. A presented `approval_id` must exist in the PEP store, be unexpired, unused, and match the frozen invoke binding. Prose cannot mint a token or approval row. |
| **Monitor coax** | Agent text that tells a monitor to classify the turn SAFE / allow so the invoke proceeds. | Evaluate path has no monitor or model judge. Coax cannot become ALLOW. Receipt records `monitor_coax_accepted: false`. |
| **Approval state substitution** | Keep the approved tool and args exactly, but swap the object they act on between approval and execute (file contents, target record). | Operator may freeze a host-computed `state_digest` at mint; consume requires an equal host-observed digest, taken by the host's `state_observer` callable inside the approval store at consume time and again in `complete_invoke` at tool entry (the envelope field is the fallback when no observer is passed). Missing, failing or different → `approval_state_mismatch`, grant not consumed. Grants without a frozen digest are unchanged. Loopjacking-class second failure mode ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)); pattern name only. |
| **Multi-session plant** | A grant or instruction planted in one session's transcript is presented again in a later session as if the operator had approved it. | The PEP consults only its own approval store and the envelope in front of it; transcript prose from any session is data. An approval id the store never issued is `approval_invalid`. This does not detect cross-session planting; it shows the plant cannot become a grant. |
| **Deferred tool** | A tool effect is deferred past the approval or the turn that was checked, for example by a dormant instruction that fires later. | The action is evaluated when it fires, against the grant's TTL and single-use state, not against the checked turn. A grant whose window has passed is `approval_expired`; a spent one is `approval_consumed`. The dormant instruction itself is not detected. |
| **Approval binding mismatch** | Mint a HITL/TTL approval for a benign invoke, then substitute args (or otherwise change the operation) before execute. | Mint freezes `tool_name` + canonical args. Consume requires an exact binding match. Mismatch → `approval_binding_mismatch` and does not consume. Prose / `policy_context` / attachments are ignored for the binding. |
| **Auth revocation / late effect** | Treat kill as only a halt bit, so a queued or in-flight invoke that was already admitted still completes successfully. | `kill()` is a cut plus an in-process fence. Completion after the cut is DENY `late_effect_fence` (receipt detail includes `cut+fence`). A new invoke after the cut stays `kill_active`. Existence-proof for the authorization-revocation / quiescence class ([arXiv:2609.21284](https://arxiv.org/abs/2609.21284)). Not a measured attack-success-rate claim. |

Inspiration for the official `eval/` row is the monitor-bypass / policy-rewrite-coax *class* discussed in [arXiv:2609.19587](https://arxiv.org/abs/2609.19587). This stub is an existence-proof deny for that class, not a paper reproduction and not an attack-success-rate claim.

The approval-binding control is an existence-proof stance against the Loopjacking-class pattern that a HITL/TTL approval is not a control if the approved representation is not exactly what later executes ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)). This tree does not claim a measured attack-success rate for that paper.

The late-effect fence is an existence-proof stance against the authorization-revocation / quiescence class: a halt or cancellation that does not close already queued or in-flight effects ([arXiv:2609.21284](https://arxiv.org/abs/2609.21284)). This tree does not claim a measured attack-success rate for that paper. The fence is the in-process cut on `PepRuntime`, not a provider-side certificate.

## Control taxonomy → fail-closed structured-envelope deny

Every control below ends in **DENY + receipt** and, when callers use `gated_invoke`, **no tool entry**. There is no “soft fail” to invoke.

| Control | Mechanism | Typical `reason_code` |
| --- | --- | --- |
| Structured envelopes only | Parse Lab or flat JSON objects. Free-text payloads and unknown/coax keys fail closed. | `envelope_invalid`, `agent_prose_rejected` |
| Prose is not policy | `untrusted_agent_text`, non-empty `metadata`, `untrusted_attachments` file bytes, and coax keys are not allowlist input. | `agent_prose_rejected` |
| Frozen allowlist | Unknown `tool_name` cannot run. Official row: `shell.exec` vs `echo.ping`. | `TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`, `unknown_tool` |
| Capability check | Token (when presented) looked up, unexpired, covers the tool, matches required capability; args must match the tiny schema. | `capability_missing`, `policy_miss` |
| Single-use TTL approval | Operator-minted grant consumed on first ALLOW of the frozen invoke. Replay / expiry / unknown / uncovered tool / args substitution deny. Does not unlock tools outside the catalog. | `approval_invalid`, `approval_expired`, `approval_consumed`, `approval_binding_mismatch` |
| Policy present and readable | Empty store, unreadable spec, or missing schema → deny. | `policy_miss` |
| Kill / unavailable | `kill()` or `available=false` denies even an otherwise allowlisted envelope. Resume cannot clear a kill. Durable store reloads the same deny after restart. | `kill_active` |
| Late-effect fence | `kill()` bumps an in-process cut epoch and refuses new entry permits. `begin_invoke` admits without entering a tool. `complete_invoke` (and `gated_invoke`) records a one-shot permit under the runtime lock, then calls the tool only if that permit was issued. A stale epoch is DENY `late_effect_fence`. A second complete on the same admission is DENY `admission_consumed`. Corpus row `acl-pep-eval-late-effect-fence-001` and `python -m pep.demo --late-effect-fence` exercise the cut. | `late_effect_fence`, `admission_consumed` |
| Suspend | `suspend()` denies every envelope until `resume()`. Persisted suspend reloads as `suspend_active`. A suspend between admit and complete does not enter the tool. | `suspend_active` |
| Parse / type failure | Null, bad JSON, malformed ids, non-object args. | `envelope_invalid` |
| Gate | `gated_invoke` calls the tool only after `allowed()`. Bypass of the helper is outside this trust domain. | (no invoke on DENY) |

Receipts also attest `fail_closed: true`, `judge.path: host_runtime_deterministic`, `llm_cot_transcript_judge: false`, `agent_prose_used_as_policy: false`, and `negative_controls_observed` (policy bytes unchanged, tool not executed, monitor coax not accepted).

## Explicit non-goals

This document and this repository do **not** claim:

- Enforcement by an LLM, chain-of-thought, or transcript judge.
- A production control plane, multi-tenant SaaS, or shipping product.
- Marketplace adapters, live git hosts, or a production UI.
- Measured attack-success-rate, classifier quality, or paper-figure reproduction.
- That callers who skip `gated_invoke` / `complete_invoke` are still enforced (they are outside the PEP boundary).
- Preemption or rollback of a callable that has already been entered when `kill()` arrives. The entry permit is recorded under the runtime lock before `tool()` is called. Once that call has started, the fence does not unwind it.
- Process-external provider callbacks that perform the effect without re-entering `complete_invoke`. Another process’s in-memory admissions are not reconstructed. `HaltStore` reload still denies **new** evaluates as `kill_active` only.
- Root-scoped quiescence across delegated providers, provider-local fences, or a cross-process cut certificate. This stub’s fence is the in-process epoch on `PepRuntime`.
- Reordering approval consume against a later suspend or kill deny. A grant can be spent and the decision still DENY, with no ALLOW. `_spent_admissions` is also unbounded for the life of the process.
- Confidentiality of policy bytes against a hostile process that can write the PEP’s memory or disk.
- A complete MCP, model, or monitor threat model — those planes are untrusted *inputs* here, not assets this stub defends as a platform.

See `SECURITY.md` for the fail-closed default and how to report issues. See `README.md` for how to reproduce the official deny.
