# ADR-0011: Grant revocation

Status: Proposed. Built on the owner's Go of 15 October 2026. Work item L3.7, first half. Accepted when merged by the owner.

## Work item

This is **L3.7** in the owner's route-to-production plan, assigned by the owner on 15 October 2026. L3.7 has two halves there: an admin `revoke` operation for unconsumed grants, and an admin-socket authorisation stronger than file mode, since same-host-user processes can open that socket today ([ADR-0007](ADR-0007-reference-host-process.md)). This ADR and its two PRs build the first half. The second half, with its acceptance test that an admin peer uid not on an allowlist is refused, is separate work under the same code and is not changed here.

The owner's Go had named this L3.1; in the threat-model legend L3.1 is host-side state binding, which is also unchanged here.

## Context

A single-use TTL grant is spent on its first ALLOW or dies at its TTL. Until now nothing could end it sooner. An operator who had minted a grant and then changed their mind, or who had cut the agent with a kill, had to wait for the TTL to run out. A kill denies every call as `kill_active` while it is active, so an outstanding grant was moot during the kill; but the grant record itself stayed spendable, which is the wrong state for a record to be in after a kill and would matter to any later path that reads grants without consulting the halt.

The detection half of this project (ADR-0010 and the console's ledger-versus-prose comparison) has a latency. A grant that can be ended at the moment a contradiction is seen shortens the window in which a further mediated action can follow it.

## Decision

1. `ApprovalRecord` gains `revoked_at`. `revoked()` and `outstanding()` (neither consumed nor revoked) read it.
2. `ApprovalStore.revoke(approval_id)` revokes one outstanding grant and returns whether it did. An unknown id, a spent grant and an already revoked grant return False and change nothing. `ApprovalStore.revoke_all` revokes outstanding grants and returns the count. The caller names the scope: `principal` revokes only the grants bound to that principal, and `all=True` revokes every outstanding grant. A call that passes neither, or that passes both, raises `ApprovalError` and changes nothing.
3. `consume` checks `revoked()` straight after the principal check and before the consumed, expiry, binding, implementation and state checks. The result is `APPROVAL_REVOKED`, a new reason code, with the detail "grant revoked before it was spent". The grant is not consumed. A caller who is not the grant's principal still sees `APPROVAL_PRINCIPAL_MISMATCH` first and learns nothing about revocation. The same check runs again after a state or implementation observer returns, so a revocation that landed during the observer is not overwritten by consuming the grant.
4. `PepRuntime.kill()` calls `revoke_all(all=True)` after engaging the fence and setting the mode, and before persisting the halt, so a failed halt write still leaves every grant revoked in memory. The halt write runs even if `revoke_all` raises. When kill runs on the same thread as a state or implementation observer, that thread already holds the store lock. `revoke_all` then revokes without taking the lock a second time, the call returns, and the halt is still written. The grant under observation is revoked and is not consumed.
5. Revocation is not cleared by `resume`. Suspend does not revoke: it is reversible, and its grants deny as `suspend_active` while it holds.

## Consequences

- An operator can end a grant before it is spent, and a kill now ends every grant. Both are visible on the record (`revoked_at`) and in the receipt (`approval_revoked`).
- `revoke_all()` with no scope revokes nothing. It raises. The global form is `all=True`, which is what kill uses.
- The reference host exposes revocation on the admin socket only: `revoke` (one `approval_id`) and `revoke_all` (every outstanding grant, or every grant of one connection, which the host maps to `revoke_all(all=True)` or `revoke_all(principal=...)`). The agent socket cannot revoke; an op body there stays `envelope_invalid`. Grant selection reports a revoked match instead of selecting it, and the held connection's call is `DENY approval_revoked` with the grant unspent and an `approval_match` check of `revoked`. The CLI mirrors this as `revoke` and `revoke-all`.
- Reason codes are additive; `approval_revoked` is new and no string is reused.

## What this is not

Not persistence across a host restart (L3.8): grants and their revocation marks are in memory. Not kill reach into a running tool body (L3.10): a tool already entered under a grant is not interrupted by revoking that grant. Not a change to how grants are minted or bound.
