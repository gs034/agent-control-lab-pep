# Mutation audit 2026-10-06-gate

- PEP commit: `5189e1321143becd15d42b802ae48ffca11f3d78`
- Python: 3.11.15
- Mutants specified by: same-family
- Timeout per run: 120.0 s

The kill rate is reported as measured. There is no pass threshold.

## Kill rate

- Timeouts counted as killed: 8 of 10 (80%)
- Timeouts not counted as killed: 8 of 10 (80%)

Outcomes: killed 8, survived-never-activated 0, survived-oracle-masked 2, timeout 0, invalid 0. Invalid patches (0) are outside the denominator.

## Mutants

| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `pep/approval.py` | `103` | TTL expiry compared with < instead of <=, so a grant is still spendable at the exact instant it expires | Approval TTL fails closed at expiry: 'Replay, expiry ... fail closed' (approval.py module docstring); ADR-0001 item 3 | killed | `tests/test_approval_laundering_classes.py::test_temporal_replay_after_expiry_or_consume_denies`<br>`tests/test_approval_principal_binding.py::test_owner_expiry_consume_and_replay_codes_are_unchanged` | 3.28 |
| M02 | `pep/approval.py` | `367` | Principal check drops the envelope-identity agreement test, so an envelope naming a different caller can spend the owner's grant | ADR-0002: host principal matches but envelope identity differs is DENY approval_principal_mismatch, not consumed ('envelope_identity must then equal it', consume docstring) | killed | `tests/test_approval_principal_binding.py::test_envelope_identity_disagreeing_with_host_denies`<br>`tests/test_approval_principal_binding.py::test_wrong_principal_and_envelope_disagreement_share_one_detail`<br>`tests/test_approval_principal_binding.py::test_lab_shape_envelope_is_bound_the_same_way`<br>`tests/test_approval_principal_binding.py::test_try_consume_passes_principal_through` | 4.11 |
| M03 | `pep/approval.py` | `321` | Successful consume marks a local copy as consumed but never writes it back to the store, so the grant can be replayed | Single-use: 'Single-use is enforced under the lock so two concurrent allows cannot share one grant' (consume docstring); ADR-0001 item 3 one-shot grant | killed | `tests/test_approval.py::test_issue_approval_allows_allowlisted_tool_without_standing_capability`<br>`tests/test_approval.py::test_approval_is_single_use_replay_denies`<br>`tests/test_approval.py::test_valid_capability_and_valid_approval_allows_and_consumes`<br>`tests/test_approval.py::test_concurrent_consume_is_single_use`<br>`tests/test_approval.py::test_exact_binding_allows_then_single_use_consume` | 3.51 |
| M04 | `pep/approval.py` | `374` | state_matches treats an absent observation (None) as nothing to compare and passes it | Frozen state digest: 'a missing or different digest, is APPROVAL_STATE_MISMATCH and does not consume' (consume docstring); the same helper guards re-observation at entry in gate.py | killed | `tests/test_approval.py::test_state_digest_frozen_at_mint_denies_substituted_state_without_consume`<br>`tests/test_approval.py::test_state_observer_failure_or_bad_value_is_deny` | 2.97 |
| M05 | `pep/gate.py` | `149` | Tool-entry implementation re-check passes when no implementation observer was kept on the admission | ADR-0004 decision 4: at tool entry 'no observer: DENY'; _implementation_still_matches docstring 'a frozen digest with no observer fails closed' | killed | `tests/test_approval_implementation_binding.py::test_admission_without_an_entry_observer_fails_closed` | 2.88 |
| M06 | `pep/gate.py` | `169` | A state observer that raises at tool entry is treated as a match, so the tool runs on an unverified target | 'A raising observer is a mismatch' (_state_still_matches docstring); complete_invoke docstring: a change is DENY approval_state_mismatch | killed | `tests/test_approval.py::test_split_admission_enters_tool_when_state_unchanged_and_raising_observer_denies` | 3.08 |
| M07 | `pep/gate.py` | `133` | complete_invoke treats a suspend refusal from claim_entry as non-blocking (suspend is reversible) and enters the tool without a permit | DENY means the tool is never called; tool entry only with a one-shot permit recorded by claim_entry (gate.py module and complete_invoke docstrings; ADR-0001 'complete_invoke' row); suspend denies every envelope (ADR-0001) | survived-oracle-masked | - | 2.92 |
| M08 | `pep/evaluate.py` | `_capability_deny:629` | Capability check no longer requires the token to match the tool's required_capability | ADR-0001 item 2: a capability token must 'match the tool's required capability when present'; ADR-0003 table keeps policy_miss for a mismatched token | killed | `tests/test_capability_principal_binding.py::test_holder_still_gets_specific_details` | 3.64 |
| M09 | `pep/evaluate.py` | `PepRuntime._claim_entry_unlocked:198` | claim_entry under the lock no longer refuses an admission that already holds a permit, so a second or concurrent claim gets another permit | One-shot permit: 'a replay cannot take a second permit' (ADR-0001 fence section); 'A second complete on the same admission is DENY admission_consumed' (gate.py docstring) | survived-oracle-masked | - | 3.26 |
| M10 | `pep/evaluate.py` | `270` | resume() returns any halted mode to ACTIVE, including KILLED, so a kill can be undone and new envelopes are allowed again | Kill is irreversible: 'resume() cannot clear a kill' (ADR-0001 Kill and suspend); resume docstring 'A killed PEP stays killed' | killed | `tests/test_fail_closed.py::test_resume_cannot_clear_kill`<br>`tests/test_fail_closed.py::test_suspend_then_kill_stays_killed`<br>`tests/test_late_effect_fence.py::test_second_kill_does_not_move_the_cut_epoch` | 2.96 |

## Survivors

Each survivor that touches a fail-closed path is filed as a defect.

- M07 (survived-oracle-masked): DENY means the tool is never called; tool entry only with a one-shot permit recorded by claim_entry (gate.py module and complete_invoke docstrings; ADR-0001 'complete_invoke' row); suspend denies every envelope (ADR-0001)
- M09 (survived-oracle-masked): One-shot permit: 'a replay cannot take a second permit' (ADR-0001 fence section); 'A second complete on the same admission is DENY admission_consumed' (gate.py docstring)
