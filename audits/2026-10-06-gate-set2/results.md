# Mutation audit 2026-10-06-gate-set2

- PEP commit: `0bac0f678bbc8688e20ab6ed5fe6d0dbc84060df`
- Python: 3.11.15
- Mutants specified by: other-family
- Timeout per run: 120.0 s

The kill rate is reported as measured. There is no pass threshold.

## Kill rate

- Timeouts counted as killed: 10 of 10 (100%)
- Timeouts not counted as killed: 10 of 10 (100%)

Outcomes: killed 10, survived-never-activated 0, survived-oracle-masked 0, timeout 0, invalid 0, harness-fault 0. Invalid patches (0) and harness faults (0) are outside the denominator.

## Mutants

| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `pep/approval.py` | `ApprovalStore.consume:289` | Skip the host-attested principal check so any caller can spend a bound approval. | ADR-0002 / consume: wrong or unattested principal is APPROVAL_PRINCIPAL_MISMATCH and does not consume. | killed | `tests/test_approval_implementation_binding.py::test_earlier_exits_return_their_own_code_and_never_call_the_observer`<br>`tests/test_approval_laundering_classes.py::test_delegation_to_a_second_principal_denies_without_spending_the_grant`<br>`tests/test_approval_principal_binding.py::test_delegation_to_a_second_principal_denies_and_does_not_consume`<br>`tests/test_approval_principal_binding.py::test_copied_identity_string_without_host_attestation_denies`<br>`tests/test_approval_principal_binding.py::test_envelope_identity_disagreeing_with_host_denies` | 4.4 |
| M02 | `pep/approval.py` | `ApprovalStore.consume:296` | Ignore a post-mint tool/args substitution against the frozen invoke binding. | ADR-0001 / consume: binding mismatch is APPROVAL_BINDING_MISMATCH and does not consume. | killed | `tests/test_approval.py::test_approval_wrong_tool_denies_even_if_id_exists`<br>`tests/test_approval.py::test_mutated_args_deny_binding_mismatch_without_consume`<br>`tests/test_approval.py::test_args_mismatch_is_reported_before_state_mismatch`<br>`tests/test_approval.py::test_state_observer_not_called_when_grant_fails_an_earlier_check`<br>`tests/test_approval_implementation_binding.py::test_earlier_exits_return_their_own_code_and_never_call_the_observer` | 3.96 |
| M03 | `pep/approval.py` | `ApprovalStore.consume:294` | Allow a single-use approval to be consumed after its TTL has elapsed. | ADR-0001 / consume: expired grant is APPROVAL_EXPIRED and does not consume. | killed | `tests/test_approval.py::test_expired_approval_denies`<br>`tests/test_approval.py::test_state_observer_not_called_when_grant_fails_an_earlier_check`<br>`tests/test_approval_implementation_binding.py::test_earlier_exits_return_their_own_code_and_never_call_the_observer`<br>`tests/test_approval_laundering_classes.py::test_temporal_replay_after_expiry_or_consume_denies`<br>`tests/test_approval_principal_binding.py::test_wrong_principal_learns_nothing_about_grant_state` | 3.62 |
| M04 | `pep/approval.py` | `333` | Treat a missing implementation observer as a pass when the grant froze an implementation digest. | ADR-0004 / _implementation_failure: observe is None returns 'no implementation observer' (mismatch, no consume). | killed | `tests/test_approval_implementation_binding.py::test_consume_failures_deny_without_spending[no-observer]`<br>`tests/test_approval_implementation_binding.py::test_lab_envelope_schema_field_implementation_digest_is_never_read` | 3.46 |
| M05 | `pep/gate.py` | `complete_invoke:118` | Skip the pre-claim fence read so a completion after kill can still reach claim_entry and the tool path. | ADR-0001 late-effect fence / complete_invoke: cut after admission is DENY late_effect_fence and does not call tool. | killed | `tests/test_approval.py::test_kill_between_admission_and_entry_denies_fence_first_and_skips_observer`<br>`tests/test_approval_implementation_binding.py::test_kill_between_admission_and_entry_is_the_fence_and_skips_the_entry_observer` | 3.73 |
| M06 | `pep/gate.py` | `149` | Pass the entry-time implementation re-observe when no observer was supplied, despite a frozen digest. | ADR-0004 / _implementation_still_matches: frozen digest with no observer fails closed (returns False). | killed | `tests/test_approval_implementation_binding.py::test_admission_without_an_entry_observer_fails_closed` | 3.23 |
| M07 | `pep/gate.py` | `128`, `complete_invoke:133` | Enter the tool even when claim_entry returned a deny reason (suspend/kill/fence/consumed). | ADR-0001 / complete_invoke: if claim_entry blocks, supersede and do not call tool. | killed | `tests/test_late_effect_fence.py::test_kill_between_fence_check_and_tool_entry_denies`<br>`tests/test_late_effect_fence.py::test_suspend_between_fence_check_and_tool_entry_denies_and_keeps_the_admission`<br>`tests/test_late_effect_fence.py::test_completion_racing_past_the_spent_precheck_enters_at_most_once` | 3.39 |
| M08 | `pep/evaluate.py` | `PepRuntime.evaluate:380` | Skip the kill/unavailable fail-closed check so evaluates continue while the PEP is killed. | ADR-0001 Fail-closed / PepRuntime.evaluate: killed or unavailable returns DENY kill_active. | killed | `tests/test_eval_corpus.py::test_corpus_row_matches_expected_receipt[acl-pep-eval-kill-001]` | 3.53 |
| M09 | `pep/evaluate.py` | `_capability_deny:616` | Accept a capability token from a non-holder or with a disagreeing envelope identity. | ADR-0003 / _capability_deny: non-holder or disagreeing envelope identity is CAPABILITY_MISSING. | killed | `tests/test_approval.py::test_invalid_capability_does_not_consume_valid_approval`<br>`tests/test_capability_principal_binding.py::test_unlisted_principal_gets_the_uniform_detail`<br>`tests/test_capability_principal_binding.py::test_envelope_identity_disagreeing_with_host_gets_the_uniform_detail`<br>`tests/test_capability_principal_binding.py::test_non_holder_learns_nothing_about_token_state`<br>`tests/test_capability_principal_binding.py::test_malformed_principals_authorise_nobody` | 3.67 |
| M10 | `pep/evaluate.py` | `PepRuntime.evaluate:526` | ALLOW even when ApprovalStore.consume returned a fail-closed reason. | ADR-0001 / evaluate: consumed.reason is not None must DENY with that reason. | killed | `tests/test_approval.py::test_approval_is_single_use_replay_denies`<br>`tests/test_approval.py::test_expired_approval_denies`<br>`tests/test_approval.py::test_unknown_approval_denies`<br>`tests/test_approval.py::test_stale_approval_denies_even_when_standing_capability_is_valid`<br>`tests/test_approval.py::test_concurrent_consume_is_single_use` | 4.39 |

## Survivors

None.
