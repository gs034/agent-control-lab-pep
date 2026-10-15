# ADR-0008: Reference host deployment acceptance

- **Status:** Proposed. Glenn chose the direction on 2026-10-12: make the reference host deployable, and make its written claims true. He has not yet accepted this text.
- **Date:** 2026-10-12
- **Depends on:** [ADR-0007](ADR-0007-reference-host-process.md) (the reference host runs as its own process).
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

ADR-0007 and the README "Reference host under its own user" section state what the host does and does not do. Until this change nothing ran those claims against a live host. The unit tests call the host in-process or over a socket from the test process, so they cannot show that a separate operating-system user is kept out of the halt file, the decision log and the admin socket.

Running the README procedure by hand exposed one gap. The shipped client, `pep.host.client.invoke`, makes each call on a new connection. The host grants a call only on a connection that is open when the grant is minted, and `invoke` sends its one request and closes. An agent that used `invoke` therefore had no held connection for the operator to grant, and the README said the agent holds its connection open while the code gave it no way to do that.

## Decision

1. **A live check.** `scripts/reference_host_check/live_check.py` provisions two operating-system users, creates the directories with the README's own `install` commands, starts the host as the host user with the README's flags, and tries each claim in the table below from the agent user. It stops everything it starts. It runs as root on Linux.
2. **A held-connection client.** `pep.host.client.AgentConnection` keeps one connection open. For a dead host, a socket owned by another user, a symlinked path, or a failure to open a socket, it returns DENY and does not raise. `invoke` is unchanged.
3. **A CI run.** `.github/workflows/reference-host-live.yml` runs the live check on every push and pull request on `ubuntu-latest`.
4. **No new claims.** The host's behaviour is unchanged. The check tests claims already written in ADR-0007 and the README.

## Claims checked

| Claim | Where it is written | Checked by |
| --- | --- | --- |
| Socket directory owned by the host user, group the agent group, mode 2750 | README step 3 | live check, after the README's `install` command |
| Agent socket is a socket, owner the host user, group the agent group, mode 0660 | README step 3 and the socket section | live check |
| Halt and log directories mode 0700 owned by the host user; halt file and log mode 0600 owned by the host user | README steps 2 and 4 | live check |
| Agent cannot write or replace the halt file, rewrite or delete the decision log, or create or remove entries in the socket directory | ADR-0007 decisions 5 and 6; README | live check, agent probes |
| Agent cannot list the state directory | README step 2 | live check, agent probe |
| Agent cannot connect to the admin socket (the host user can, as a control) | README step 5 | live check |
| A call with no grant is denied; a grant applies only to its connection; a second connection is a new session | ADR-0007 decision 3 | live check |
| A grant covers exact arguments and stops at its expiry. Only `echo.ping` is registered, so other tool names are not tested | README step 6 | live check |
| Extra request keys are denied; the agent cannot mint a grant over its own socket | ADR-0007 decision 1 | live check |
| Allowed calls are in the decision log under their request id | ADR-0007 decision 6 | live check |
| A request over 64KiB is denied, and JSON nested deeper than 32 is denied, each on a connection that is otherwise granted and allowed | README limits | live check |
| A ninth connection is refused while eight are open | README limits | live check |
| An idle connection is closed after 5 seconds; a trickling connection is closed at 30 seconds | README limits | live check, timed |
| Unadmitted denials are coalesced; stopping the host writes the held count | ADR-0007 decision 6 | live check. The 30-per-window cap and the one-second window are not timed |
| Kill, and a removed or damaged halt file, deny a granted call; a kill survives restart; init-halt does not clear a kill | ADR-0007 decision 5 | live check. Each restart check requires its grant to have landed |
| A peer outside `--allow-uid` is refused | README | live check |
| A socket directory that group members can write is refused at start; a state directory that others can read is refused at start | README step 3 and the directory section | live check, exit status and message |
| The shipped client refuses a socket owned by another user, and a symlinked path | README | live check |
| A held client connection is allowed once granted, and denied for a dead or wrongly owned host | this ADR, decision 2 | live check and `tests/test_reference_host.py` |
| Threads sharing one held client connection each get their own reply; an ungranted caller is never told ALLOW | follow-up to #38 | live check and `tests/test_reference_host.py` |
| Writing the damaged halt file does not follow a symlink | follow-up to #38 | live check |

## Evidence

- Live check on the working tree for this change: 55 of 55 claims pass, in about 50 seconds. After the #38 follow-up, which adds the two rows above for threads and the halt-file symlink: 57 of 57.
- Seeded faults, each in a scratch copy of the code, run against the final harness:
  - a peer allow-list that accepts every peer: "a peer outside --allow-uid is refused" fails;
  - a connection cap of 64 instead of 8: "a ninth connection is refused" fails;
  - a depth cap of 100000 instead of 32: "JSON nested deeper than 32" fails;
  - a size cap of 10 MB instead of 64KiB: "a request over 64KiB" fails;
  - a decision log created with mode 0644: the host refuses to start, so the host-start check and the two scenarios that start a host fail, and the startup check on the socket directory fails with the log message. The check on the state directory still passes, because that refusal happens before the log is opened.
- PEP unit suite: 356 tests pass, which includes four new `AgentConnection` tests. The last one covers a socket that cannot be opened.
- The harness found its own faults during this work: a host imported from the working directory rather than the copy under test, a race in starting the host, a timing read of a log line, a missing group on a clean runner, and a grant made before the held connection had connected. Each is fixed. The mutant runs above were made after those fixes.

## Findings for the owner

- **The connection limits make a held session short.** A held connection is closed after 5 seconds with no bytes, and 30 seconds after it was accepted. An agent must send at least every 5 seconds, and the operator must grant again after each reconnect. ADR-0007 sets these limits so that a slow drip or an idle client cannot hold a slot. Changing them, or making them flags, is a choice for the owner. This ADR does not change them.
- **Timeouts after a send are ambiguous.** If `AgentConnection.call` times out after the request was sent, it returns DENY `host_unreachable`, but the host may have admitted the call and run the tool. The docstring says so. A caller that retries an effect on DENY must check the decision log first.
- **Replies are matched to requests by id since #40.** `AgentConnection` checks that each reply's `request_id` belongs to this connection and rises; a reply that fails that check is DENY `reply_mismatch` (`pep/host/client.py`, `_check_request_id`). At the time this ADR was written the client took the next line from the connection without a check; that paragraph is superseded.
- **The client's socket-owner check and its peer-credential check overlap.** Either one refuses a host owned by another user. The tests show a refusal, not which check made it, so removing one of them is not caught. Adding a test for each would need a separate socket owner that the peer check would not catch, which I did not build.
- **The in-process library still treats a missing halt file as active.** ADR-0007 keeps that default for `HaltStore` only. The host does not use it.
- **`pep/host` has no mutation audit yet.** ADR-0006's default scope covers the gate, approval and implementation files. The live check and the unit tests cover the host, but no frozen-suite mutant run has been made against `pep/host`.

## What this does not claim

- Everything ADR-0007 does not claim still holds.
- The check runs one configuration: the built-in stub policy, the echo tool, the default limits, and one Linux machine. The `reference-host-live` workflow has since run green on GitHub on every main push since `50be0ca` (#38, 12 October 2026); a green run is evidence for the claims the check prints, on that runner only.
- The check does not test the rest of the README. Behaviour the README describes but the table does not list, such as the accept loop waking about every 0.2 seconds, is untested.
- The check does not prove production readiness. No outside review of this host has been done.
- The check does not test an agent running as the host user, or with write access to its directories. ADR-0007 says those break the separation.
- A passing check is evidence for the claims in the table only. A claim that is not in the table is untested.

## Consequences

- The reference host now has a live check of the claims in the table above. The CI job needs root on the runner (`sudo`).
- Operators should use `AgentConnection` for an agent's calls. `invoke` remains for one-shot checks, and it cannot be granted in advance.
- The supply-gate, console and joint-eval repositories are not changed by this ADR. Their pins to the PEP are unchanged.
