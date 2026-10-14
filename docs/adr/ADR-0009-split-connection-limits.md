# ADR-0009: split the reference host's connection limits

- Status: Proposed (awaiting owner approval; no limit changes in this ADR)
- Date: 2026-10-14
- Brand: Agent Control Lab
- Licence: Apache-2.0
- Supersedes nothing yet. Amends the limits ADR-0007 set and ADR-0008 recorded.

## Context

ADR-0007 set three limits on the agent socket and ADR-0008 recorded them: an idle timeout of 5 seconds per read (`IDLE_TIMEOUT_SECONDS`), a connection deadline of 30 seconds after accept (`CONNECTION_DEADLINE_SECONDS`), and a cap of 8 connections (`MAX_CONNECTIONS`). A tool call has its own 5 second limit (`TOOL_CALL_TIMEOUT_SECONDS`). ADR-0008 named the consequence: a held session is short, an agent must send a byte at least every 5 seconds, and the operator must grant again after each reconnect.

The owner's decision of 14 October 2026: do not accept 5 seconds idle and 30 seconds deadline as they stand. Split the single limit into separate ones, measure first, then propose numbers with the measurements. This ADR is that proposal. It changes no constant.

## Decision proposed

One limit becomes five, each with its own name, default and reason.

1. **Partial-frame limit.** Once the first byte of a request has arrived, the whole request line must arrive within this bound, or the connection is closed. This is the slow-drip defence that the 5 second idle timeout was really for.
2. **Idle limit between requests, with keep-alive.** A connection with no request in flight may stay open for this long without bytes. A keep-alive request (an envelope the host answers without a decision and without a log line beyond a counter) resets it. This is what an agent waiting on a long model turn needs.
3. **Session lifetime bound by grant time-to-live.** A session ends when its last grant's TTL has passed, not at a fixed 30 seconds after accept. `kill` and (once it exists, L3.7) `revoke` stay instant and are not bounded by this limit.
4. **Gate decision-time budget.** The time the host allows itself to reach a decision, measured and budgeted separately for rules-only decisions (the only kind this host makes) and for any future model-based check (none exists on the decision path; the budget is reserved, not spent). A decision that overruns its budget is DENY, logged as such.
5. **Configurable connection cap.** The cap stays, becomes an operator setting with a bounded range, and the host drops the client that has held a slot longest without a complete request when the cap is reached.

## Measurements

`scripts/bench_decisions.py`, run on 14 October 2026 as a non-root user on this machine (Linux 6.18, x86_64, Python 3.13.16), 2000 iterations per series, in-process `handle_request`. Raw output: `docs/benchmarks/2026-10-14-decision-times.json`.

| Series | What it times | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| `deny_unknown_tool` | rules-only DENY with the log append (most lines coalesced by the denial window) | 0.034 ms | 0.074 ms | 0.381 ms | 3.3 ms |
| `deny_envelope_invalid` | rules-only DENY for a malformed envelope | 0.032 ms | 0.065 ms | 0.116 ms | 2.7 ms |
| `allow_echo` | granted `echo.ping` through the executor worker and back | 2.44 ms | 3.63 ms | 5.07 ms | 8.0 ms |

What is not measured: the Unix-socket round trip (the benchmark is in-process; the client and host must be different users, which one process cannot be), and the gap between an agent's successive tool calls (this tree holds no agent traces; the script accepts one with `--gaps` and reports the distribution when given). The idle-limit number below therefore rests on the owner's starting range, not on data.

## Proposed numbers (for owner approval, not yet applied)

| Limit | Proposed default | Basis |
| --- | --- | --- |
| Partial-frame | 2 s | Owner's starting range 1 to 2 s. A 64 KiB request line arrives in well under that on loopback; the bound is for a drip, not for throughput. Measured decision time plays no part. |
| Idle between requests | 90 s, keep-alive resets | Owner's starting range 60 to 120 s. No trace data; chosen mid-range. To be revisited with a measured gap distribution. |
| Session lifetime | bound by the last grant's TTL; no fixed deadline | Follows the decision. The operator's TTL is the bound. |
| Decision budget, rules-only | 10 ms p99 | Measured p99 is 0.4 ms worst series, so 10 ms gives twenty-five times headroom on this machine and sits well under the owner's starting point of 100 ms. The executor round trip (5 ms p99) is a tool-call budget, not a decision budget, and keeps its own limit. |
| Decision budget, model-based | reserved, not set | No model on the decision path. Set only if one is ever added, with its own measurement. |
| Connection cap | 8, operator-settable 1 to 64 | Current value kept; the range is a proposal. Drop policy: longest slot held without a complete request. |

## Consequences

- Each limit gets a constant, a constructor argument and a README row; the live check gains a row per limit. This is a protocol-visible change for the idle and lifetime limits, so it lands as its own phased change after approval (tests, code, docs, minor version bump per ADR-0003 and ADR-0005 practice).
- A keep-alive envelope is a new request kind. Its shape is decided in the implementing change, not here.
- Nothing in this ADR is a claim of efficacy. The numbers describe one machine on one day.

## Owner decision

Pending. STOP 3 in the production brief.
