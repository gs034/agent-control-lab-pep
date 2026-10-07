# ADR-0007: Run the policy enforcement point as its own process

- **Status:** Accepted for this reference prototype, 2026-10-07. Glenn's decision, recorded in the task that asked for this host: the gate runs as a separate process under its own operating-system user, not inside the agent's process.
- **Date:** 2026-10-07
- **Depends on:** [ADR-0001](ADR-0001-lab-pep-architecture.md) (the policy enforcement point), [ADR-0002](ADR-0002-approval-principal-binding.md) (approvals bound to a principal the host attests).
- **Amends:** ADR-0001's statement that the in-process function boundary is the trust boundary. ADR-0004's statement that an unknown key inside `schema_fields` is dropped.
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

The policy enforcement point (PEP) is the checkpoint that is supposed to admit or deny every agent tool call. Until this change it was a library. `pep.evaluate` and `pep.gated_invoke` take the function to run, the caller's identity, the clock, and the check callbacks from whoever imports them. A caller that can import the library can choose all of those.

That showed up in a review of main `3098096`. An ALLOW for the harmless tool `echo.ping` ran an arbitrary function, because the function is an argument. An approval that had already expired was accepted when the caller passed an earlier time as `now`. Unknown keys under `invoke` and `schema_fields` were dropped, so a later reader could treat input the PEP never checked as if it had been approved. A missing halt file was treated as active, so deleting the file cleared a kill after restart. A failed write of the kill state was swallowed. Decision receipts included `policy_file_unchanged: true` from a comparison of a byte string with itself, and the only copy of a denial went back to the caller.

The in-process functions stay, because the corpus and the existing tests call them. They are not a security boundary.

## Decision

`pep.host` is a separate process. The agent reaches it only over a Unix socket. The agent sends one JSON object with two keys, `tool_name` and `args`. Any other key is denied. The host does not read a function, a clock, a principal, or a session name from that object.

The host process owns:

1. **The registry.** `tool_name` selects a function the host was given when it started. The request cannot replace that function. If the name is not in the registry, nothing is called.
2. **The clock.** Expiry uses the host's clock. A time in the request is an unknown key and is denied.
3. **Identity.** On Linux the host reads the kernel's peer credentials for the connection (process id, user id, group id). It then assigns a session to that connection. The session name is not a token the agent can send. A second connection is a different session, even when the user id is the same, so session B cannot spend a grant minted for session A.
4. **The policy.** The host loads it. The agent cannot pass a document. When the policy was loaded from a file, each call that reaches the policy check re-reads the file and records the digest it saw. A changed or unreadable file denies the call.
5. **Halt state.** A missing, unreadable, or ill-formed halt file means the gate is halted. The host does not create an active file to fill the gap. `kill` writes a killed file and raises if that write does not land; the process stays halted either way. Deleting the file does not make a new process active. The older `HaltStore` behaviour, where a missing file is active, remains on the in-process library only.
6. **The decision log.** Every decision is appended to a file the host opens append-only, mode 0600. The agent socket has no command that writes or deletes it. A record lists the checks that ran on that call. It has no boolean field, and it does not contain `policy_file_unchanged` or any other claim that is true by construction. If the log cannot be appended, the tool is not entered.

Unknown keys inside a lab envelope's `invoke` object and its `schema_fields` are now `envelope_invalid` in the library parser as well. They are not dropped.

The frozen receipt schema (v1) is unchanged. The in-process receipt can still carry `policy_file_unchanged`. That field is not an observation. The host log does not copy it.

## How to run it

The operator starts the process as a user the agent does not share. The process does not switch user itself. The README section "Reference host under its own user" is the short procedure.

Grants are minted by the operator, on the host, for one connection. The agent does not send an approval id or a capability token. The stub token for `lab.demo.agent` is not handed to whoever connects.

## What this does not claim

This is a reference prototype. It is not a measured reduction in attack success, and it is not a product. An engineering note on this commit does not carry over to the next commit.

In particular, this host does not:

- Stop an agent that never connects to the socket and calls a tool some other way.
- Stop a process that runs as the host user, or that can write the host's directory. File modes only help when the agent is a different user.
- Prove a kill across a restart if the process can neither write nor delete the halt file, and the old file still says active. The process that failed the write stays halted. A later process that can still read the old active file will not see that kill.
- Keep approvals on disk. A restart forgets grants that were only in memory.
- Add rate limits, argument budgets, or a check that tool results are safe to read. A result is labelled `result_origin: host-registry` so the caller can see where it came from. That label is not a check.
- Seal the decision log with a key held on another machine. The log is append-only from this process. It is not a tamper-evident chain against someone who can write the file.
- Change the in-process library into a boundary. Callers of `evaluate` and `gated_invoke` still supply the callable, the clock, and the principal.

## Consequences

- Tests in `tests/test_reference_host.py` cover a caller-supplied callable, a caller-supplied time, unknown keys, a deleted halt file, a failed kill write, session B acting as session A, and a denial that appears in the host's own log.
- `python -m pep.host` is the way to run the process. `pep-host` is the same entry point.
