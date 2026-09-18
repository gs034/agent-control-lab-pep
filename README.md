# Agent Control Lab — reference host/runtime PEP stub

This repository is a public-goods, Apache-2.0 **reference Policy Enforcement Point (PEP)** stub from **Agent Control Lab** (Navigators / philanthropic AI-control). It is an existence-proof **host/runtime deny path** over structured invoke envelopes. It is **not** a production product, **not** an LLM/CoT/transcript judge, and **not** a human-in-the-loop enforcement path.

The official eval row lives under `eval/` (Deep Research artefacts). The PEP loads `eval/structured_envelope.example.json` as the sole policy-relevant input. `eval/malicious_agent_prose.txt` is untrusted data and is never policy.

**Architecture.** Callers (agent, optional monitor, HITL UI, or MCP/tool host) submit a structured invoke envelope to `pep.evaluate` / `pep.gated_invoke`. That function boundary *is* the PEP: frozen allowlist and capability bytes in the `pep` package decide ALLOW or DENY, emit a receipt, and on DENY never enter the tool. Model output, monitor scores, and agent prose sit outside this plane and cannot rewrite policy. Public threat model: [`docs/threat-model.md`](docs/threat-model.md). Reporting: [`SECURITY.md`](SECURITY.md). Contributing / Lab-only keep-out: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What this is

- A diligence-hard **reference host/runtime PEP** you can read in one sitting.
- A distinct trust domain (`pep`) from any agent or monitor.
- An existence-proof deny for the monitor-bypass / policy-rewrite-coax *class* inspired by [arXiv:2609.19587](https://arxiv.org/abs/2609.19587). Not a measured reproduction.

## Non-goals

- **Not an LLM / CoT / transcript judge as enforcement.** There is no model call on the evaluate path (see `pep/evaluate.py` and `tests/test_no_llm_path.py`). A monitor “SAFE” coax is not an allow.
- **Not production SaaS.** Not a multi-tenant control plane, shipping product, marketplace adapter, live git host, or production UI.
- **Existence-proof stub only.** Demonstrates a host/runtime deny for one attack *class*. Not a measured attack-success-rate result and not a vendor-classifier claim. This stub does not measure attack success.

## Four PEP lines (demonstrated in code)

1. **Non-goal.** The deny path is deterministic host/runtime policy. It is **not** an LLM/CoT/transcript judge. `evaluate()` does not call a model.
2. **Separate trust domain.** The `pep` package is the PEP. Agents and optional monitors are callers. In-process import is allowed; `evaluate()` / `gated_invoke()` is the boundary.
3. **Structured envelopes only.** The PEP consumes the structured envelope. Agent free-text / “please allow” is **untrusted data** and never becomes policy.
4. **Fail-closed.** Missing policy, unknown tool, expired/missing capability, PEP unavailable or kill active, parse failure → **DENY** + receipt; `gated_invoke` does not enter the tool.

## How to run

Requires Python 3.11+. Stdlib-only runtime; pytest for tests.

```bash
python -m pip install -e ".[dev]"
python -m pep.demo
pytest
```

**Reproduce the exercised deny** (official `eval/` row):

```bash
python -m pep.demo
```

That command loads `eval/structured_envelope.example.json`, ignores `eval/malicious_agent_prose.txt` as policy, and prints a live receipt matching `eval/expected_deny_receipt.example.json` in shape and semantics (`decision: DENY`, `reason_code: TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`).

## Receipt shape

Public receipts match `eval/expected_deny_receipt.example.json`:

- `decision`, `reason_code`, `pep_id` (`acl-pep-stub-host-runtime-001`), `policy_version` (`0.1.0-stub`)
- `judge.path: host_runtime_deterministic`, `llm_cot_transcript_judge: false`, `agent_prose_used_as_policy: false`
- `negative_controls_observed`: policy unchanged, no tool invoke, monitor coax not accepted
- `brand: Agent Control Lab`, `licence: Apache-2.0`

`envelope_hash` is `sha256:` plus hex of the **canonical** envelope bytes: UTF-8 JSON, sorted keys, compact separators (see `pep/canonical.py`). The example file hashes on-disk pretty-printed bytes; the live digest may differ.

## Layout

| Path | Role |
| --- | --- |
| `pep/envelope.py` | Lab + flat envelope parse; prose is not policy |
| `pep/policy.py` | Frozen stub allowlist (`echo.ping` only) |
| `pep/evaluate.py` | PEP trust domain: `evaluate(envelope) -> Decision` |
| `pep/gate.py` | Never invoke on DENY |
| `pep/receipt.py` | Receipt matching the `eval/` example |
| `pep/row.py` | Loader for `eval/` artefacts |
| `pep/demo.py` | Prints the live official-row deny receipt |
| `eval/` | Deep Research row, envelope, prose, expected receipt |
| `docs/threat-model.md` | Public host/runtime PEP threat model and control taxonomy |
| `SECURITY.md` | Fail-closed default, trust domain, how to report issues |
| `CONTRIBUTING.md` | Lab-only artefacts; reject commercial/bank paths and brand strings |
| `scripts/check_lab_only.sh` | Wrapper for the Lab-only keep-out (job `forbidden-tokens`) |
| `scripts/lab_brand_wall.py` | Packed keep-out scan (stdlib Python; no ripgrep) |

## Trust domain

```
agent / optional monitor / HITL UI
              |  structured envelope (eval/structured_envelope.example.json)
              v
     pep.evaluate / pep.gated_invoke     <-- PEP (this package)
              |  ALLOW only
              v
          tool invoke
```

A hostile reviewer reading `pep/evaluate.py` should not be able to relabel this as a model-graded monitor. Policy is frozen bytes. Envelope `policy_context` cannot rewrite the allowlist.

## License

Apache License 2.0. See `LICENSE`. Source files carry `SPDX-License-Identifier: Apache-2.0`.

**Brand:** Agent Control Lab. Public-goods / Navigators / philanthropic AI-control reference. Not a commercial product.
