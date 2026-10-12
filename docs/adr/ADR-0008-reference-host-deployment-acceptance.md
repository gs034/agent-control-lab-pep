# ADR-0008: Reference host deployment acceptance

- **Status:** Accepted for this reference prototype, 2026-10-12. The direction, to make the reference host deployable and make its written claims true, is Glenn's decision.
- **Date:** 2026-10-12
- **Depends on:** [ADR-0007](ADR-0007-reference-host-process.md) (the reference host runs as its own process).
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

ADR-0007 and the README "Reference host under its own user" section state what the host does and does not do. Until this change nothing ran those claims against a live host. The unit tests call the host in-process or over a socket from the test process, so they cannot show that a separate operating-system user is kept out of the halt file, the decision log and the admin socket.

Running the README procedure by hand exposed one gap. The shipped client, `pep.host.client.invoke`, opens a new connection for each call. The host grants against a live connection, and a new connection has no grant, so an agent that used `invoke` could never receive an ALLOW. The README said the agent holds its connection open, and the code gave the agent no way to do that.

## Decision

1. **A live check.** `scripts/reference_host_check/live_check.py` provisions two operating-system users, starts the host as the host user with the README's flags, and tries each claim from the agent user. It is run by root on Linux and it stops everything it starts. The claims it covers are listed below.
2. **A held-connection client.** `pep.host.client.AgentConnection` keeps one connection open and returns the same DENY values as `invoke` for a dead host, a socket owned by another user, or a symlink path. `invoke` is unchanged.
3. **A CI run.** `.github/workflows/reference-host-live.yml` runs the live check on every push and pull request on `ubuntu-latest`.
4. **No new claims.** The host's behaviour is unchanged. The check tests the claims already written in ADR-0007 and the README.

## Claims checked

| Claim | Where it is written | Checked by |
| --- | --- | --- |
| Socket directory owned by the host user, group the agent group, mode 2750 | README step 3 | live check, layout |
| Agent socket mode 0660 in the agent group; halt and log directories and files 0700 and 0600 owned by the host user | README steps 2 to 4 | live check, layout |
| Agent cannot write or replace the halt file, rewrite or delete the decision log, or create or remove entries in the socket directory | ADR-0007 decision 5 and 6; README | live check, agent probes |
| Agent cannot connect to the admin socket | README step 5 | live check |
| A call with no grant is denied; a grant applies only to its connection; a second connection is a new session | ADR-0007 decision 3 | live check |
| Grant covers one tool and exact arguments, and stops at its expiry | README step 6 | live check |
| Extra request keys are denied; the agent cannot mint a grant over its own socket | ADR-0007 decision 1 | live check |
| Allowed calls are in the decision log under their request id | ADR-0007 decision 6 | live check |
| Request over 64KiB and JSON nested deeper than 32 are denied | README limits | live check |
| Ninth connection is refused while eight are open | README limits | live check |
| Idle connection closed after 5 seconds; trickling connection closed at 30 seconds | README limits | live check |
| Unadmitted denials are coalesced; SIGTERM writes the held count | ADR-0007 decision 6 | live check |
| Kill, and a removed or damaged halt file, deny a granted call; a kill survives restart; init-halt does not clear a kill | ADR-0007 decision 5 | live check |
| Peer outside `--allow-uid` is refused | README | live check |
| A socket dir that group members can write, or a state dir others can read, is refused at start | README | live check |
| Shipped client refuses a socket owned by another user, and a symlinked path | README | live check |
| A held client connection is allowed once granted | this ADR, decision 2 | live check and `tests/test_reference_host.py` |

## Evidence

- Live check, clean tree at this change: 55 of 55 claims pass.
- Seeded faults in a scratch copy, each caught by the claim it breaks: a peer allow-list that accepts every peer (1 claim fails), a connection cap of 64 instead of 8 (1 claim fails), a decision log created with mode 0644 (the host refuses to start, and the scenarios fail).
- PEP unit suite with three new tests for `AgentConnection`: passes.

The live check found three faults in its own harness before any host claim failed. The first was a race in starting the host; the second was that a host could be imported from the working directory rather than the copy under test, which made the first mutant run meaningless; the third was a timing read of a log line written when a window closes. Each is fixed in the harness, and the mutant runs above were made after those fixes.

## Findings for the owner

- **The connection deadline limits a held session to 30 seconds.** A grant lasts for its time-to-live, but a connection stops at 30 seconds after accept, and the agent must reconnect and be granted again. A long-running agent therefore needs an operator grant at least every 30 seconds. ADR-0007 sets the deadline so that a slow drip cannot hold a slot. Raising it, or making it a flag, is a choice for the owner. This ADR does not change it.
- **The in-process library still treats a missing halt file as active.** ADR-0007 keeps that default for `HaltStore` only. The host does not use it.
- **`pep/host` has no mutation audit yet.** ADR-0006's default scope covers the gate, approval and implementation files. The live check and unit tests cover the host, but no mutant run has been made against `pep/host` in the frozen-suite method.

## What this does not claim

Everything ADR-0007 does not claim still holds. In addition:

- The check runs one configuration: the built-in stub policy, the echo tool, the default limits, and this Linux machine.
- The check does not prove production readiness. No outside review of this host has been done.
- The check does not test an agent running as the host user, or with write access to its directories. ADR-0007 says those break the separation.
- A passing check is evidence for the listed claims only. A claim that is not in the table is untested.

## Consequences

- The reference host now has a live test of its deployment claims. The CI job needs root on the runner (`sudo`).
- Operators should use `AgentConnection` for an agent's calls. `invoke` remains for one-shot checks, and it can never produce an ALLOW.
- The supply-gate, console and joint-eval repositories are not changed by this ADR. Their pins to the PEP are unchanged.
