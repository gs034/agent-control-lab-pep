# ADR-0004: Bind single-use approvals to the implementation resolved at mint

- **Status:** Accepted, 2026-10-05 (owner), with the three recommendations under "Owner decisions". Amended by [ADR-0007](ADR-0007-reference-host-process.md): an unknown key inside `schema_fields` or `invoke` is `envelope_invalid`, not dropped.
- **Implementation:** done in pep 0.6.0, in two phases: phase 1 (core, helpers and tests; pep#16) and phase 2 (docs and version). No sibling pin needs to move. Measured added cost of a bound `gated_invoke` with `executable_digest` on the test program: 129.7 µs median over 2,000 runs (local container), under the 1 ms provisional ceiling.
- **Date:** 2026-10-05
- **Depends on:** [ADR-0002](ADR-0002-approval-principal-binding.md) (principal-bound approvals). Independent of [ADR-0003](ADR-0003-capability-token-principal-binding.md).
- **Amends:** ADR-0001 "Fail-closed" list, which would gain an implementation mismatch; the `docs/threat-model.md` non-goal on program resolution.
- **Origin:** research-loop work package WP-RL-006 (run `acl-rl-2026-10-05-0800`, finding RF-20261005-01).
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

**What an approval binds today.** An approval freezes one invoke: `tool_name` plus canonical args (`invoke_binding`, `pep/approval.py:59-63`). ADR-0002 adds the principal that may spend it. An operator may also freeze a state digest at mint: a host-computed digest of the object the invoke acts on. `ApprovalStore.consume` re-observes that digest under the store lock, and `complete_invoke` re-observes it at tool entry (`_state_still_matches`, `pep/gate.py:122-135`).

**What it does not bind.** Nothing records which implementation the tool name will run. The PEP never runs a program itself: the host passes the tool as a callable to `gated_invoke` or `complete_invoke`, and that callable decides what executes. Two residual tests in `tests/test_approval_laundering_classes.py` show the consequence, and `docs/threat-model.md` lists both as non-goals ("Proposed wording, for owner review"):

- `test_path_resolution_substitution_is_residual`: two executables share the name `labtool`. `PATH` is reordered after mint. The tool name, the args and the frozen target are unchanged, so the invoke is ALLOW, and the other program runs.
- `test_preexisting_hook_effect_below_tool_boundary_is_residual`: a hook that already exists at mint writes outside the declared args on tool entry. The invoke is ALLOW.

**Outside evidence.** Two preprints from separate groups name the same gap. Both were read in full by the research run.
- FCD (arXiv:2609.35088v1) calls it "schema-epoch drift": an unchanged, schema-valid call takes a different effect because the handler changed between approval and execution. Its preregistered comparison is small (6 calls).
- COBRA (arXiv:2610.03089v1) pins MCP tool definitions by SHA-256 and binds calls to the approved server. It still names "same call, different server effect" as out of reach.

Neither paper tests a local `PATH` substitution. This ADR takes the mechanism from them, not their numbers, and imports no code from either.

**The state digest already does most of this, but by accident.** A host could fold the resolved program into the state digest it freezes. Three things make that a poor substitute:
- the envelope may carry the observed state digest when the host passes no observer (`pep/approval.py:279-281`; `evaluate` docstring, `pep/evaluate.py:338-343`), which is never acceptable for an implementation;
- a mismatch would read as `approval_state_mismatch`, which hides which of the two changed;
- nothing makes a host include the implementation, so the receipt cannot say whether it was bound.

## Decision

A grant may freeze a host-computed digest of the implementation that the tool name resolves to at mint. If it does, the PEP requires the same digest, observed by the host, at consume and again at tool entry.

1. **Mint.** `PepRuntime.issue_approval` and `ApprovalStore.issue` take an optional `implementation_digest`, in the same `sha256:<64 hex>` form as the state digest. A malformed value is an `ApprovalError` at mint. The digest is stored on `ApprovalRecord`.
2. **Observation is host-only.** `evaluate`, `begin_invoke` and `gated_invoke` take an optional `implementation_observer: Callable[[], object]`, the host's re-resolution of the implementation. There is no envelope field, and no envelope value is ever used as the observation. This differs deliberately from the state digest. A top-level `implementation_digest` key is rejected as `envelope_invalid` by the existing unknown-key check, in both envelope shapes. Inside a lab envelope's `schema_fields` an unknown key was dropped, and never read, until [ADR-0007](ADR-0007-reference-host-process.md). From that ADR it is `envelope_invalid`.
3. **Consume.** In `ApprovalStore.consume` the check runs after the binding check and before the state check, under the store lock:
   - grant froze no implementation digest: no check, and the observer is not called;
   - grant froze one and no observer was given: DENY;
   - observer raises or returns a non-digest: DENY;
   - observed digest differs: DENY.

   Each DENY is the new reason code `approval_implementation_mismatch` and does **not** consume the grant, like a binding or principal mismatch. The observer has the same constraints as the state observer: it must be quick, and it must not call back into the store. A call back into the store from the observer's thread is refused as a mismatch, not deadlocked. Every earlier exit (unknown id, principal, consumed, expired, binding) returns before the observer is called.
4. **Tool entry.** `PendingInvoke` keeps the observer. `complete_invoke` checks in this order: the fence read, then whether the admission was already spent, then the implementation re-observation, then the state re-observation, then `claim_entry`. The implementation-before-state order matches consume. The spent check (added in phase 1 review) makes a second `complete_invoke` return `admission_consumed` without calling either observer; before it, a replay with a state observer re-read the host first. At entry, when the grant froze an implementation digest:
   - no observer: DENY. This differs from `_state_still_matches`, which returns True when no state observer is present (`pep/gate.py:129-130`);
   - observer raises or returns a non-digest: DENY;
   - observed digest differs: DENY.

   Each is `approval_implementation_mismatch` with the grant **already spent**. This matches today's state-digest rule at entry, because consume has already happened. A cut seen by the fence read still denies first, and the entry observer is then not called. `supersede` takes its detail from `_reason_detail` (`pep/evaluate.py:666-695`), which falls through to the kill detail for an unmapped code. The new code therefore gets its own entry-time detail there.
5. **Details.** A detail never echoes a digest or a path. It says only which case failed:
   - "no implementation observer";
   - "implementation observer failed";
   - "implementation observer re-entered store";
   - "implementation mismatch" at consume;
   - at entry, a fixed detail saying the implementation re-observed at tool entry differs, the grant already spent.
6. **What the PEP compares.** The PEP compares opaque digests and does not resolve anything. What goes into the digest is the host's choice. A new module, `pep/implementation.py`, offers two optional host-side helpers, which `evaluate` does not use:
   - `executable_digest(name, path=None)` resolves `name` with `shutil.which` and digests the resolved absolute path plus the file bytes;
   - `callable_digest(fn)` digests the module, the qualified name and the code object of an in-process callable.

   These are conveniences for hosts and tests, not a definition of identity.
7. **Receipts and version.**
   - Schema v1 is unchanged. `reason_code` is a free string, and the new code is additive (`pep/reasons.py`: "New codes are additive").
   - No existing corpus decision changes, because no fixture freezes an implementation digest.
   - The policy bytes and `POLICY_VERSION` are unchanged.
   - The package moves to 0.6.0. The API change is additive; callers that do not use it see no change.

## Options considered

| Option | Binds to | Assessment |
| --- | --- | --- |
| **A. Implementation digest frozen per grant, host observer at consume and entry (proposed)** | The implementation resolved at mint | Would close the post-mint substitution that the `PATH` residual shows, and reuses the state-digest pattern the PEP already has. It is opt-in per grant, so the bound and unbound cases stay distinguishable in tests and receipts. |
| B. Document that hosts fold the implementation into the state digest | Whatever the host chooses | No PEP change. But it accepts an envelope-supplied observation, gives one code for two causes, and cannot be checked. Rejected as the mechanism; kept as a note for hosts that cannot adopt A. |
| C. Pin an implementation digest per tool in frozen policy | The implementation named in policy | Also covers capability-token ALLOWs, which have no mint moment. But every legitimate update needs a policy change; FCD's exact-pinning baseline blocked all 6 of its calls, benign ones included. Deferred: a candidate follow-up ADR for token-admitted invokes. |
| D. Effect-contract verification at the final hop (FCD-style) | Declared effects of the handler | Addresses benign drift better than A, but needs effect profiles per tool, which this tree does not have. Out of scope. |
| E. Keep the residual, document it | Nothing | Leaves a known ALLOW for a different program under the same grant. Rejected. |

## Owner decisions

Settled on 2026-10-05: the owner accepted all three recommendations.

1. **New reason code, or reuse `approval_binding_mismatch`?** Decided: the new code `approval_implementation_mismatch`. A changed program is a different failure from changed args, and the receipt should say which. It is additive and the schema is unchanged.
2. **Optional per grant, or required?** Decided: optional per grant in this ADR. The stub catalog's `echo.ping` has no external program, and the host may not be able to resolve every tool. Making it required per tool belongs with option C, in a later ADR.
3. **Mismatch at entry: spent or not spent?** Decided: spent, consistent with the existing state-digest rule at entry. Refunding a grant after consume would need a new store transition.

## Residuals (what this does not fix)

- **Check-to-exec race.** The entry check runs before `tool()`. If the tool resolves the name again after the check, a `PATH` reorder or symlink swap in that gap still runs the other program. The PEP cannot close this, because the host's callable does the exec. The window runs from the entry re-observation through `claim_entry` to the exec inside `tool()` (`pep/gate.py:104-119`). Running the resolved absolute path does not close it, because the file at that path can still be replaced. A host closes it only by executing the artefact from the same open file descriptor it digested. (Amended by [ADR-0005](ADR-0005-execute-the-digested-artefact.md): a plain open file descriptor does not survive an in-place write; ADR-0005 executes a sealed in-memory copy instead.) Phase 1 adds a test that records the race as a named residual.
- **Implementations that already exist at mint.** The digest proves the implementation did not change after mint. It says nothing about whether that implementation was safe. `test_preexisting_hook_effect_below_tool_boundary_is_residual` therefore stays a residual. The hook did not change after mint, so any implementation digest the host computes, whether or not it covers the hook, matches at consume and at entry. (With `callable_digest`, the hook is not even covered: it is loaded through `runpy` at entry, outside the tool's code object.) (The research work package proposed flipping this test as well. That would be wrong, and this ADR does not do it.)
- **Host honesty.** The observer is host code. A host that returns the mint digest without re-resolving defeats the check. This is the same trust placed in the state observer and the attested principal.
- **Unbound grants.** A grant minted without an implementation digest behaves exactly as today, so the existing `PATH` residual test still passes unchanged. It now documents the unbound case.
- **Capability-token invokes.** An ALLOW admitted by a standing token has no mint moment, so this ADR does not cover it. See option C.
- **In-process equivalent access.** As with ADR-0002, code with the same process access can call the tool without the gate.

## Consequences and dependent changes

### pep (this repository)

**Code**
- `pep/approval.py`:
  - `implementation_digest` on `ApprovalRecord` and `issue`;
  - the consume check;
  - the frozen digest returned on `ConsumeResult`, so the gate can re-observe.
- `pep/evaluate.py`: `issue_approval` and `evaluate` take the new parameters and pass them through; the `Decision` carries the frozen digest, like `frozen_state_digest`; `_reason_detail` maps the new code to its entry-time detail.
- `pep/gate.py`: `begin_invoke`, `gated_invoke` and `PendingInvoke` carry the observer; `complete_invoke` re-checks it at entry.
- `pep/reasons.py`: `APPROVAL_IMPLEMENTATION_MISMATCH`.
- `pep/implementation.py`: the two optional helpers.

**Tests**
- A new `tests/test_approval_implementation_binding.py` holds the acceptance table below.
- The bound variant of the `PATH` case is a DENY test in that file. The existing residual test stays unchanged as the unbound case.
- The hook residual test stays unchanged.

**Docs**
- `README.md` and `SECURITY.md`: the fail-closed lists.
- `docs/threat-model.md`: the program-resolution non-goal is narrowed to unbound grants and the check-to-exec race.
- `docs/ROADMAP.md`.
- ADR-0001: as listed under Amends.

**Corpus.** No receipt regenerates, because no fixture opts in. `scripts/regen_corpus_receipts.py --check` must report nothing.

### Siblings

There is no pin bump to keep behaviour, because the change is additive. joint-eval and console are unaffected until they choose to adopt it. A joint-eval fixture for the bound `PATH` case would be a separate, later change.

### Phases

| Phase | Scope | Green during transition because |
| --- | --- | --- |
| 1. Core and tests | Record field, mint parameter, consume check, entry re-check, reason code, helpers, the new test file and the check-to-exec residual test | Opt-in; no existing caller passes the new arguments |
| 2. Docs and version 0.6.0 | Everything under Docs above | Docs only |

## Comparison experiment and acceptance

Run before and after, at named commits. "Before" is pep `76c6d4b` (0.5.0).

| Case | Before (0.5.0) | Required after |
| --- | --- | --- |
| Bound grant, `PATH` reordered after mint, host observer re-resolves | n/a (no binding); ALLOW and program B runs | DENY `approval_implementation_mismatch` at consume; grant **not** consumed; tool not entered |
| Bound grant, implementation unchanged | n/a | ALLOW; the same program runs |
| Bound grant, implementation changed after admission and before entry (`begin_invoke`, swap, `complete_invoke`) | n/a | DENY `approval_implementation_mismatch` at entry with the entry-time detail (not the kill detail); grant spent; tool not entered |
| Bound grant, entry observer raises or returns a non-digest | n/a | DENY `approval_implementation_mismatch` at entry; grant spent |
| Bound grant, both implementation and state changed after admission | n/a | DENY `approval_implementation_mismatch` at entry (implementation checked first) |
| Bound grant, no observer at consume | n/a | DENY `approval_implementation_mismatch`, "no implementation observer"; not consumed |
| Bound grant, observer raises or returns a non-digest | n/a | DENY, "implementation observer failed"; not consumed |
| Bound grant, observer calls back into the store | n/a | DENY, "implementation observer re-entered store"; not consumed; no deadlock |
| Bound grant, unknown id, consumed, expired or binding mismatch | The existing code | Unchanged; the observer is not called |
| Unbound grant, observer passed | ALLOW | ALLOW; the observer is not called |
| Envelope with a top-level `implementation_digest` key | DENY `envelope_invalid` | Unchanged |
| Two threads consume one bound grant at once | n/a | Exactly one ALLOW |
| Bound grant, in-process handler swapped in a host registry after mint (`callable_digest`) | n/a | DENY `approval_implementation_mismatch`; not consumed |
| Unbound grant, `PATH` reordered (existing residual test) | ALLOW; program B | Unchanged (residual, unbound) |
| Pre-existing hook (existing residual test) | ALLOW | Unchanged (residual) |
| Bound grant, swap after the entry check (check-to-exec race) | n/a | Recorded as a named residual test: ALLOW, other program runs |
| Bound grant, wrong principal | DENY `approval_principal_mismatch` | Unchanged; the principal check runs first and the observer is not called |
| Bound grant, kill between admission and entry | DENY `late_effect_fence` | Unchanged; the fence wins and the observer is not called at entry (it ran once at consume) |
| Replay of a consumed bound grant after re-resolution | DENY `approval_consumed` | Unchanged |
| Malformed `implementation_digest` at mint | n/a | `ApprovalError` |
| Official `python -m pep.demo` row and every corpus row | Current receipts | Byte-identical (`regen_corpus_receipts.py --check` clean) |

Further acceptance requirements:
- No receipt-schema change. No detail echoes a digest or a path.
- The added cost of a bound consume plus entry check, using `executable_digest` on the test program, is measured and reported, with a provisional ceiling of 1 ms median on the local machine. Over that ceiling is a finding, not an automatic fail.
- The full pep suite and the brand-wall checks pass. Each phase gets an independent review.

**Rollback:** revert the implementation commits. Nothing else pins this behaviour.

**What success would establish:** on this tree, a grant that froze an implementation digest is spent only when the host observes the same implementation at consume and at tool entry.

**What it would not establish:**
- that the implementation resolved at mint was safe;
- protection after the entry check (the check-to-exec race);
- coverage of capability-token invokes;
- resistance to a host that misreports;
- any measured attack-success rate;
- live enforcement.
