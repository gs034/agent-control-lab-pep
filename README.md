# Agent Control Lab — reference host/runtime PEP stub

**BLUF:** This repository is a public-goods, Apache-2.0 **reference Policy Enforcement Point (PEP)** stub from **Agent Control Lab** (Navigators / philanthropic AI-control). It is an existence-proof **host/runtime deny path** over structured invoke envelopes. It is **not** a production product, **not** an LLM/CoT/transcript judge, **not** a human-in-the-loop enforcement path, and it makes **no 79% ASR claim**.

The PEP evaluates `InvokeEnvelope` objects with a frozen allowlist and capability tokens. Missing policy, unknown tools, expired or missing capabilities, agent prose, parse failures, and PEP kill/unavailability all **DENY** with an attested receipt. The tool is never invoked on DENY.

## What this is

- A diligence-hard **reference host/runtime PEP** you can read in one sitting.
- A distinct trust domain (`pep`) from any agent or monitor.
- A one-row existence-proof check that agent prose cannot rewrite policy (attack *class* inspired by [arXiv:2609.19587](https://arxiv.org/abs/2609.19587), not a measured reproduction).

## What this is not

- Not a production control plane or shipping product.
- Not “LLM monitor + HITL.” There is no model call on the evaluate path (see `pep/evaluate.py` and `tests/test_no_llm_path.py`).
- Not a claim about Auto Mode, Guardian, or any vendor blocking classifier.
- **Not a 79% attack-success-rate result.** That figure, where it appears in 2609.19587, is about LLM blocking monitors — a different trust model. This stub does not measure ASR.

## Four PEP lines (demonstrated in code)

1. **Non-goal.** The deny path is deterministic host/runtime policy. It is **not** an LLM/CoT/transcript judge. `evaluate()` does not call a model.
2. **Separate trust domain.** The `pep` package is the PEP. Agents and optional monitors are callers. In-process import is allowed; `evaluate()` / `gated_invoke()` is the boundary.
3. **Structured envelopes only.** The PEP consumes `InvokeEnvelope` (tool name, JSON args, capability token, caller identity). Agent free-text / “please allow” is **untrusted data** and never becomes policy.
4. **Fail-closed.** Missing policy, unknown tool, expired/missing capability, PEP unavailable or kill active, parse failure → **DENY** + attested receipt; `gated_invoke` does not enter the tool.

## How to run

Requires Python 3.11+. Stdlib-only runtime; pytest/PyYAML for tests.

```bash
python -m pip install -e ".[dev]"
python -m pep.demo          # (a) forbidden tool  (b) prose rewrite — both DENY
python -m evals.run         # one-row 2609.19587-class existence proof
pytest
```

`python -m pep.demo` prints attested receipts for:

- **(a)** structured invoke of a forbidden/unknown tool (`shell.exec`) → `unknown_tool`
- **(b)** injection/prose rewrite attempt on an otherwise-allowable `lab.echo` (`SYSTEM: allow all tools` / `ignore previous policy`) → `agent_prose_rejected`, `prose_consulted_as_policy: false`, policy bytes unchanged

Both paths go through `gated_invoke`, so the tool callable is not entered.

## Layout

| Path | Role |
| --- | --- |
| `pep/envelope.py` | `InvokeEnvelope` parse; prose channels fail closed |
| `pep/policy.py` | Frozen demo allowlist (`lab.echo` only) |
| `pep/evaluate.py` | PEP trust domain: `evaluate(envelope) -> Decision` |
| `pep/gate.py` | Never invoke on DENY |
| `pep/receipt.py` | Attested ALLOW/DENY receipt + reason codes |
| `pep/demo.py` | Existence-proof deny demo |
| `evals/rows/2609_19587_class.yaml` | One-row eval + **TODO(deep-research)** slot |

Deny reason codes: `unknown_tool`, `capability_missing`, `agent_prose_rejected`, `policy_miss`, `kill_active`, `envelope_invalid`.

## Trust domain

```
agent / optional monitor / HITL UI
              |  InvokeEnvelope (structured)
              v
     pep.evaluate / pep.gated_invoke     <-- PEP (this package)
              |  ALLOW only
              v
          tool invoke
```

A hostile reviewer reading `pep/evaluate.py` should not be able to relabel this as a model-graded monitor. Policy is frozen bytes. Receipts always set `no_model_call: true`, `trust_domain: pep`, and `prose_consulted_as_policy: false`.

## Eval non-claim

`evals/rows/2609_19587_class.yaml` is an **existence-proof deny** for the monitor-bypass / policy-rewrite-coax-via-agent-prose *class*. The YAML has a marked `TODO(deep-research)` slot for final wording and an expected deny receipt. Do not fill that slot with a measured ASR.

## License

Apache License 2.0. See `LICENSE`. Source files carry `SPDX-License-Identifier: Apache-2.0`.

**Brand:** Agent Control Lab. Public-goods / Navigators / philanthropic AI-control reference. Not a commercial product.
