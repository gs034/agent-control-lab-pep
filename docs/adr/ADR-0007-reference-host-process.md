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
5. **Halt state.** A missing, unreadable, or ill-formed halt file means the gate is halted. The host does not create an active file to fill the gap, including when the file disappears in the moment the process is opening. `python -m pep.host kill` writes a killed file and raises if that write does not land; the process stays halted either way. A running host reads the file again immediately before the tool runs. If that read is not active, the host calls `runtime.kill()` and returns DENY, and the tool does not run. That is the same in-process fence, reached through the documented command. A tool body that has already started is not unwound. Deleting the file does not make a new process active. A file that already says suspended at startup is denied as suspended and is not latched for the life of the process. The latch is for killed, missing, and corrupt files. The halt file is read once per check. The store writes through a unique temporary name, fsyncs that file before the rename, and fsyncs the directory after the rename. The older `HaltStore` behaviour, where a missing file is active, remains on the in-process library only.
6. **The decision log.** Each decision is appended to a file the host opens append-only, mode 0600, with `O_NOFOLLOW` and `fchmod` on that descriptor. The agent socket has no command that writes or deletes it. A record lists the checks that ran on that call, and it carries a request id. An allow is written with the tool's outcome, after the tool returns. A line written before entry only records that the checks were stored; it is not the allow. It has no boolean field, and it does not contain `policy_file_unchanged` or any other claim that is true by construction. If the log cannot be appended, the tool is not entered. A denial for a call that has not been admitted is coalesced so a flood cannot fill the disk and latch a halt. The host writes at most 30 of those lines per window of one second. The clock is read inside the lock that counts them. A clock that reads 0 does not count as a summary already written. Further denials in that window are not written one by one. When the window closes, one line with reason `rate_limited` is appended, carrying that window's count, and the count is reset. If the host shuts down while a count is still held, that same line is written then. The caller of a counted denial still receives DENY, with the original reason. A denial from the second halt check, a denial because the tool raised after it was entered, and a fence denial after the pre-entry line are each appended on their own and are not part of the count. The directories that hold the log and the halt file must be owned by the host user and mode 0700. Only that immediate directory is checked, not its parents. At startup the host reads the log, up to 1MiB, to continue sequence numbers, and refuses a larger file. The open is checked with `fstat` before `fchmod`.

Unknown keys inside a lab envelope's `invoke` object and its `schema_fields` are now `envelope_invalid` in the library parser as well. They are not dropped.

The frozen receipt schema (v1) is unchanged. The in-process receipt can still carry `policy_file_unchanged`. That field is not an observation. The host log does not copy it.

## How to run it

The operator starts the process as a user the agent does not share. The process does not switch user itself. The README section "Reference host under its own user" is the short procedure. The socket directory is setgid to the agent group (mode 2750) so the socket, mode 0660, is in that group. The host checks the directory owner and mode before it binds, and it does not delete a live socket.

The client checks the socket's owner and the accepting process's user id (`SO_PEERCRED`) against the expected host user. A mismatch, a dead host, or a timeout is a DENY from the client.

Grants are minted by the operator on an admin socket in the private directory (mode 0600). The agent socket cannot mint one. `serve` without `--admin` denies every call. The agent holds the connection; `sessions` and `grant` name that connection. A new connection is a new session.

A request larger than 64KiB, or nested deeper than 32, is DENY and is logged. At most 8 agent connections are open. Each one is a thread. The idle timeout is per read (5 seconds with no bytes). A connection also ends 30 seconds after accept, so a slow drip cannot hold a slot past that deadline. Optional `--allow-uid` and `--allow-gid` restrict the peer credentials. A file descriptor passed to another process keeps the connecting process's credentials.

## What this does not claim

This is a reference prototype. It is not a measured reduction in attack success, and it is not a product. An engineering note on this commit does not carry over to the next commit.

In particular, this host does not:

- Stop an agent that never connects to the socket and calls a tool some other way.
- Stop a process that runs as the host user, or that can write the host's directory. File modes only help when the agent is a different user.
- Prove a kill across a restart if the process can neither write nor delete the halt file, and the old file still says active. The process that failed the write stays halted. A later process that can still read the old active file will not see that kill.
- Keep approvals on disk. A restart forgets grants that were only in memory.
- Add argument budgets, or a check that tool results are safe to read. Denial logging is coalesced per window, as above, and connections are capped. Allows, the pre-entry line, and the admitted-call denials are still written one by one, so a stream of allows can still grow the log. A full disk on append fails closed and latches a halt. A result is labelled `result_origin: host-registry` so the caller can see where it came from. That label is not a check.
- Notice that a connected socket was passed to another process. The peer credentials stay those of the process that connected.
- Seal the decision log with a key held on another machine. The log is append-only from this process. It is not a tamper-evident chain against someone who can write the file.
- Change the in-process library into a boundary. Callers of `evaluate` and `gated_invoke` still supply the callable, the clock, and the principal.

## Consequences

- Tests in `tests/test_reference_host.py` cover a caller-supplied callable, a caller-supplied time, unknown keys, a deleted halt file, a failed kill write, a kill that lands after the first halt check, session B acting as session A, a denial that appears in the host's own log, the socket directory and the client peer check, nested JSON, the connection cap, the idle timeout, the connection deadline, coalesced denials on a fake clock (including a flush on shutdown and admitted-call denials during a flood), a client reply with no decision, the admin grant, and a suspend that is not latched.
- `python -m pep.host` is the way to run the process. `pep-host` is the same entry point.
