# Evaluator corpus (M1)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

Additional structured-envelope rows for the host/runtime PEP. The official
existence-proof deny remains at the `eval/` root
(`structured_envelope.example.json` + `expected_deny_receipt.example.json`).
`python -m pep.demo` still evaluates that official row only.

Each corpus row is:

- a Lab structured envelope
- a runtime fixture (policy / halt mode / single-use approvals)
- an expected receipt matching frozen schema v1

Enforcement is `pep.evaluate` / `pep.gated_invoke`. This directory is not a
second judge, not an LLM/CoT/transcript path, and not a measured
attack-success-rate claim.

Catalog rewrite is not a grant: the allowlisted ALLOW row still cannot add
tools or capabilities via prose or envelope fields.
