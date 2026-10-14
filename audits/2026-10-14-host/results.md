# Mutation audit 2026-10-14-host

- PEP commit: `653ee4a819c55bb1fadab2421aa62336352ce2e3`
- Python: 3.13.16
- Mutants specified by: same-family
- Timeout per run: 300.0 s

The kill rate is reported as measured. There is no pass threshold.

## Kill rate

- Timeouts counted as killed: 9 of 12 (75%)
- Timeouts not counted as killed: 8 of 12 (67%)

Outcomes: killed 8, survived-never-activated 2, survived-oracle-masked 1, timeout 1, invalid 0, harness-fault 0. Invalid patches (0) and harness faults (0) are outside the denominator.

## Mutants

| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M01 | `pep/host/server.py` | `1151` | Off-by-one on the agent connection cap: _acquire_slot admits one connection more than max_connections. | The host never serves more than max_connections concurrent agent connections; the (max+1)th is answered DENY connection_limit and closed. | killed | `tests/test_reference_host.py::test_connection_cap_denies_the_extra_client`<br>`tests/test_reference_host.py::test_reconnect_needs_a_free_slot_and_is_a_new_session` | 18.83 |
| M02 | `pep/host/server.py` | `1330` | A policy-file digest mismatch on re-read is reported as policy_ok=True, so the request proceeds on changed policy bytes. | A policy file whose bytes changed after load is a fail-closed DENY (policy_miss) with the host latched halted, never an evaluation against the new bytes. | survived-never-activated | - | 14.94 |
| M03 | `pep/host/server.py` | `691` | Skip the second halt-file read between the PRE_ENTRY log line and tool entry; a kill landing in that gap no longer blocks the tool. | A kill observed after the first halt check but before tool entry denies the admitted call; the tool must not run once the halt file is no longer active. | killed | `tests/test_reference_host.py::test_kill_after_the_first_halt_check_stops_the_tool`<br>`tests/test_reference_host.py::test_admitted_denials_are_logged_during_a_flood` | 14.47 |
| M04 | `pep/host/server.py` | `769` | A failed ALLOW append after tool entry no longer turns the reply into DENY; the ALLOW and the tool result are returned with nothing logged. | No ALLOW leaves the host unless the decision log accepted the ALLOW record; an append failure after entry is a fail-closed DENY (kill_active). | killed | `tests/test_reference_host.py::test_a_decision_that_outlives_the_drain_is_counted_not_lost` | 14.2 |
| M05 | `pep/host/client.py` | `_connect_attested:114` | Drop the SO_PEERCRED uid comparison in _connect_attested; the client trusts any listener on a socket file owned by host_uid. | The client attests the accepting process by kernel peer credentials, not only by the socket file's owner; a peer whose uid is not host_uid is DENY host_unattested. | killed | `tests/test_reference_host.py::test_client_denies_when_the_host_is_down_or_the_peer_is_wrong` | 14.13 |
| M06 | `pep/host/client.py` | `266` | Request-id monotonicity check accepts a repeated number (<= becomes <), so a replayed reply line is taken as the answer to a new request. | On a held connection every reply's host request number must strictly rise; a repeated or replayed reply is DENY reply_mismatch and the connection is closed. | killed | `tests/test_reference_host.py::test_held_connection_denies_and_closes_on_a_reused_request_id` | 13.94 |
| M07 | `pep/host/executor.py` | `334` | Remove the whole-call deadline from the worker read; each recv gets a fresh call_timeout window, so a worker that drips bytes is never cut off. | A tool call is bounded by one call_timeout deadline for the whole reply, not a per-recv window; a slow-dripping worker is denied with kind timeout. | timeout | - | 300.19 |
| M08 | `pep/host/executor.py` | `477` | A registry function that raises a non-OSError exception is reported to the gate as status ok with result null instead of error. | A tool that raises after entry is a DENY tool_failed, never an ALLOW carrying a fabricated result. | killed | `tests/test_reference_host.py::test_tool_exception_is_not_logged_as_a_policy_miss`<br>`tests/test_reference_host.py::test_admitted_denials_are_logged_during_a_flood` | 14.23 |
| M09 | `pep/host/executor.py` | `_Worker.call:336` | A worker whose call timed out is not closed or killed, so the stale worker (and its late reply) stays bound to the session for the next call. | A worker that exceeded its call deadline is killed and discarded; a late reply from it can never be returned as the result of a later request. | killed | `tests/test_reference_host.py::test_a_worker_that_drips_bytes_is_cut_off_at_the_call_timeout` | 13.86 |
| M10 | `pep/host/log.py` | `DecisionLog.__init__:119` | Open the decision log without O_NOFOLLOW, so a symlink planted at the log path is followed and receives the records. | The decision log path is opened without following symlinks; a planted link at the log path is refused at host start, not written through. | killed | `tests/test_reference_host.py::test_decision_log_refuses_a_symlink_and_does_not_chmod_the_path` | 13.98 |
| M11 | `pep/host/fsguard.py` | `52` | Widen the private-directory mask from 0o077 to 0o007, so a directory readable, writable or traversable by its group passes as private. | The halt, log and policy directories must have no group or other bits at all (mode 0700); any group access is a PathGuardError and the host refuses to start. | survived-oracle-masked | - | 14.26 |
| M12 | `pep/host/haltfile.py` | `170` | An empty or whitespace-only halt file is classified as ACTIVE instead of CORRUPT. | Any halt file whose bytes do not parse as an active record is halted (fail-closed); emptiness is corruption, not an active state. | survived-never-activated | - | 14.44 |

## Survivors

Each survivor that touches a fail-closed path is filed as a defect.

- M02 (survived-never-activated): A policy file whose bytes changed after load is a fail-closed DENY (policy_miss) with the host latched halted, never an evaluation against the new bytes.
- M11 (survived-oracle-masked): The halt, log and policy directories must have no group or other bits at all (mode 0700); any group access is a PathGuardError and the host refuses to start.
- M12 (survived-never-activated): Any halt file whose bytes do not parse as an active record is halted (fail-closed); emptiness is corruption, not an active state.
