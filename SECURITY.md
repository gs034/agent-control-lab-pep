# Security policy (Agent Control Lab PEP stub)

This repository is a public-goods, Apache-2.0 **reference host/runtime Policy Enforcement Point (PEP)** stub. It is an existence-proof deny path over structured invoke envelopes. It is not a production product.

## Fail-closed default

The PEP default is **DENY**. Missing policy, unknown tool, expired or missing capability, PEP unavailable or kill active, and parse failure all yield **DENY + receipt**. `gated_invoke` does not enter the tool on DENY.

There is no documented fail-open path. Do not treat absence of a monitor, model, or approval string as allow.

## Trust domain

The `pep` package is a **separate trust domain** from:

- the **model** (not called on `evaluate()`);
- an optional **monitor** (caller / observer, not an allow authority);
- the **MCP / tool host** (downstream of ALLOW only).

`evaluate()` / `gated_invoke()` is the enforcement boundary. Agent free-text is untrusted data and never becomes policy. Envelope `policy_context` cannot rewrite the frozen allowlist.

Public threat model: [`docs/threat-model.md`](docs/threat-model.md).

## Reporting a security issue

This project does **not** publish a `security@` mailbox. Do not invent or guess an email address for the Lab.

**Preferred:** use GitHub **private vulnerability reporting** / **Security Advisories** on this repository when the Security tab offers “Report a vulnerability”:

https://github.com/gs034/agent-control-lab-pep/security/advisories

That keeps a working deny-bypass or invoke-on-DENY report out of the public issue tracker until it is assessed.

**If private reporting is not enabled or the advisory form is unavailable:** open a GitHub issue on this repository, titled so it is clearly a security report (for example, `security: host/runtime PEP deny bypass`). Describe impact and the trust-boundary violation. Do **not** attach a ready-to-run exploit against third-party systems. For this stub, a minimal structured envelope plus the unexpected `ALLOW` / tool-entry receipt is enough.

Issues: https://github.com/gs034/agent-control-lab-pep/issues

Please include:

- PEP id / policy version if you have a receipt (`acl-pep-stub-host-runtime-001`, `0.1.0-stub` on the published stub);
- whether `gated_invoke` entered a callable on DENY, or `evaluate()` returned ALLOW when a listed fail-closed condition should have denied;
- that you are talking about **this** host/runtime PEP, not a model or monitor judgement.

Out of scope for a vulnerability report against this stub: “the model said allow”, monitor-only coax without a PEP allow, or asking this existence-proof catalog to block tools it does not claim to host.

## Non-goals (security claims)

This stub does not claim production SaaS hardening, marketplace adapters, live git-host isolation, or enforcement by an LLM / chain-of-thought / transcript judge.
