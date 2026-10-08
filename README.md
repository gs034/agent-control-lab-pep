# Agent Control Lab — reference host/runtime PEP stub

This repository is a public-goods, Apache-2.0 **reference Policy Enforcement Point (PEP)** from **Agent Control Lab** (Navigators / philanthropic AI-control). Package **v0.7.0** adds a host-side helper, `pep.implementation.open_executable`, that copies the resolved program into a sealed in-memory file, digests that copy and runs it ([ADR-0005](docs/adr/ADR-0005-execute-the-digested-artefact.md)). A host that uses it runs the main program file the PEP checked, even if `PATH`, a symlink or the file on disk changes after the copy. Not covered: anything the program loads by path (libraries, imports, configuration) and a `#!/usr/bin/env` interpreter unless the host pins it. Linux only; the helper fails closed elsewhere (an existence-proof control; not a measured attack-success-rate claim). **v0.6.0** lets an operator bind a single-use approval to a host-computed digest of the implementation the tool name resolves to at mint ([ADR-0004](docs/adr/ADR-0004-approval-implementation-binding.md)). The host re-resolves at consume and again at tool entry; a missing, failing or different observation is **DENY** `approval_implementation_mismatch`, so a `PATH` reorder between mint and consume no longer runs another program under a bound grant (an existence-proof deny; not a measured attack-success-rate claim). The binding is optional per grant, and the observation only ever comes from the host. **v0.5.0** binds every standing capability token to the host-attested principals its policy record lists ([ADR-0003](docs/adr/ADR-0003-capability-token-principal-binding.md)). An attested caller that is not a holder gets one uniform `capability_missing` detail (an unattested caller gets "no attested principal"), and the stub policy is now `0.2.0-stub`. **v0.4.0** binds every single-use approval to a host-attested principal ([ADR-0002](docs/adr/ADR-0002-approval-principal-binding.md)). A second caller that presents the same `approval_id` is **DENY** `approval_principal_mismatch` and cannot spend the grant: an existence-proof deny for the Delegation class ([arXiv:2609.38983v1](https://arxiv.org/abs/2609.38983v1); not a measured attack-success-rate claim). **v0.3.3** lets an operator freeze a host-computed **state digest** at approval mint; a consume whose host-observed digest (read by a host `state_observer` inside the gate, or carried in the envelope) is missing or different is **DENY** `approval_state_mismatch`, so the Loopjacking-class second failure mode (post-approval state substitution, not only args substitution) is an existence-proof deny too ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081); not a measured attack-success-rate claim). **v0.3.2** adds an in-process late-effect fence on `kill()`: a queued or callback invoke admitted before the cut and completed after it is **DENY** `late_effect_fence` (receipt detail `cut+fence`), not a silent success and not only `kill_active`. That is an existence-proof control for the authorization-revocation / quiescence *class* ([arXiv:2609.21284](https://arxiv.org/abs/2609.21284); not a measured attack-success-rate claim). **v0.3.1** patches **v0.3 / EOI M1** so single-use TTL approvals bind `tool_name` plus canonical args (Loopjacking-class representation mismatch as an existence-proof threat pattern; [arXiv:2609.21081](https://arxiv.org/abs/2609.21081); not a measured attack-success-rate claim). v0.3 added an evaluator corpus under `eval/corpus/` plus a durable kill/suspend store, on the **v0.2** foundation (single-use TTL approvals, halt API, frozen receipt schema) and the **0.1 stub** existence-proof deny. It is **not** a production product, **not** an LLM/CoT/transcript judge, and **not** a human-in-the-loop enforcement path.

The official eval row lives under `eval/` (Deep Research artefacts). The PEP loads `eval/structured_envelope.example.json` as the sole policy-relevant input. `eval/malicious_agent_prose.txt` is untrusted data and is never policy.

**Architecture.** Callers (agent, optional monitor, HITL UI, or MCP/tool host) submit a structured invoke envelope to `pep.evaluate` / `pep.gated_invoke`. Those in-process functions decide ALLOW or DENY for tests and corpus rows. They are **not a security boundary**: the caller supplies the function, the clock and the identity. Package **v0.8.0** adds a separate reference host process, `python -m pep.host`, that owns them ([ADR-0007](docs/adr/ADR-0007-reference-host-process.md)). Frozen allowlist, capability tokens, and operator-issued single-use TTL approvals in the `pep` package decide ALLOW or DENY, emit a frozen-schema receipt, and on DENY never enter the tool. Kill and suspend fail closed; `kill()` also fences in-process late effects so a queued or in-flight admission cannot complete as ALLOW. Optional `HaltStore` persists halt mode across process restart. Model output, monitor scores, and agent prose sit outside this plane and cannot rewrite policy. ADR: [`docs/adr/ADR-0001-lab-pep-architecture.md`](docs/adr/ADR-0001-lab-pep-architecture.md). Roadmap (stub → v0.2 → v0.3 / EOI M1 → v0.3.2 late-effect fence → v0.3.3 state digest → v0.4.0 principal binding → v0.5.0 capability holders → v0.6.0 implementation binding → v0.7.0 execute what was digested → v0.8.0 reference host): [`docs/ROADMAP.md`](docs/ROADMAP.md). Public threat model: [`docs/threat-model.md`](docs/threat-model.md). Reporting: [`SECURITY.md`](SECURITY.md). Contributing / Lab-only keep-out: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What this is

- A diligence-hard **reference host/runtime PEP** you can read in one sitting.
- A distinct trust domain (`pep`) from any agent or monitor.
- An existence-proof deny for the monitor-bypass / policy-rewrite-coax *class* inspired by [arXiv:2609.19587](https://arxiv.org/abs/2609.19587). Not a measured reproduction.

## Non-goals

- **Not an LLM / CoT / transcript judge as enforcement.** There is no model call on the evaluate path (see `pep/evaluate.py` and `tests/test_no_llm_path.py`). A monitor “SAFE” coax is not an allow.
- **Not production SaaS.** Not a multi-tenant control plane, shipping product, marketplace adapter, live git host, or production UI.
- **Existence-proof plus v0.3 / M1 corpus (v0.3.1 binding patch).** Demonstrates a host/runtime deny for named attack *classes*, catalog-bound ALLOW fixtures, approval invoke binding, and a file-backed halt store. Not a measured attack-success-rate result, not a vendor-classifier claim, and not a production control plane. This tree does not measure attack success.

## Four PEP lines (demonstrated in code)

1. **Non-goal.** The deny path is deterministic host/runtime policy. It is **not** an LLM/CoT/transcript judge. `evaluate()` does not call a model.
2. **Separate trust domain.** The `pep` package is the PEP. Agents and optional monitors are callers. In-process import is allowed for tests and corpus rows; `evaluate()` / `gated_invoke()` is not a security boundary. The reference host process is the boundary that owns the function, the clock and the identity.
3. **Structured envelopes only.** The PEP consumes the structured envelope. Agent free-text / “please allow” is **untrusted data** and never becomes policy.
4. **Fail-closed.** Missing policy, unknown tool, expired/missing capability, a capability token presented by a principal that is not a listed holder, invalid/expired/consumed/binding-mismatched/state-mismatched/principal-mismatched/implementation-mismatched approval, PEP unavailable, kill, suspend, or a late effect after kill, parse failure → **DENY** + receipt; `gated_invoke` does not enter the tool. Halt mode can persist in a JSON file so a restarted process still denies. A pre-cut admission that completes after `kill()` denies as `late_effect_fence`.

## How to run

Requires Python 3.11+. Stdlib-only runtime; pytest for tests.

```bash
python -m pip install -e ".[dev]"
python -m pep.demo
pytest
```

**Reproduce the exercised deny** (official `eval/` row):

```bash
python -m pep.demo
```

That command loads `eval/structured_envelope.example.json`, ignores `eval/malicious_agent_prose.txt` as policy, and prints a live receipt matching `eval/expected_deny_receipt.example.json` in shape and semantics (`decision: DENY`, `reason_code: TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY`).

**Exercised late-effect deny** (separate from the official row):

```bash
python -m pep.demo --late-effect-fence
```

That admits an allowlisted `echo.ping`, calls `kill()`, then completes the admission as a callback. The live receipt is `decision: DENY`, `reason_code: late_effect_fence`, with `cut+fence` in `reason_detail`. The tool is not entered. A fresh invoke after kill remains `kill_active`.

**Implementation binding, step by step** (Linux only):

```bash
python -m pep.demo --implementation-binding
```

That prints one line per scenario, using two programs both named `labtool` and a search path, passed to `shutil.which`, that changes after the approval. The process `PATH` is not touched.

| Scenario | Since | Outcome |
| --- | --- | --- |
| Unbound grant | before 0.6.0 | ALLOW; program B runs |
| Bound grant, `PATH` changed before the invoke | 0.6.0 (ADR-0004) | DENY `approval_implementation_mismatch`; grant not spent |
| Bound grant, `PATH` changed inside the tool, host runs by path | 0.6.0 residual | ALLOW; program B runs |
| Bound grant, same change, host uses `open_executable` | 0.7.0 (ADR-0005) | ALLOW; program A runs |

It exits non-zero if any decision, reason code, program run or grant state differs from the table. Each line also carries the receipt; on the ALLOW rows its `tool_invoke_executed` is `false` because the receipt is issued at the decision, before the tool runs. The third row is shown on purpose: it is the residual that 0.7.0 closes, and only for hosts that use the helper. Existence proof on fixtures; not live enforcement and not a measured attack-success rate.

## Reference host under its own user

The reference host is a separate process. The agent talks to it through a Unix socket and sends only a tool name and arguments. The host decides. This is a reference prototype. It is not a measured reduction in attack success, and it is not a product.

The in-process calls `pep.evaluate` and `pep.gated_invoke` still work. Use them for the corpus and the unit tests. Do not treat them as the gate in front of a real tool: the caller of those functions picks the function that runs, the clock, and the identity string.

What the host keeps to itself:

- the registry (the functions that actually run)
- the clock
- who the caller is, taken from the connection, not from a name in the message
- the policy
- the halt file (killed, suspended, or active)
- an append-only decision log

Run it as a user the agent does not share. The process does not switch user by itself. You start it as that user.

1. Create a user for the host, for example `acl-pep`, and a group for the agent, for example `acl-agent`. The agent user is in `acl-agent`. It is not `acl-pep`.
2. Create a directory the agent cannot list or write. The halt file and the decision log live here.

```bash
sudo install -d -o acl-pep -g acl-pep -m 0700 /var/lib/acl-pep
```

3. Create a directory the agent can enter, so it can connect to the socket, but cannot replace files in. The host user owns it. The directory is setgid to the agent group, so the socket is created in that group. Mode 2750 is owner `rwx`, group `r-x`, and the setgid bit. Group and other cannot write it.

```bash
sudo install -d -o acl-pep -g acl-agent -m 2750 /run/acl-pep
```

4. Initialise the halt file as the host user. If this file is missing, unreadable, or damaged, the gate stays halted. It does not start active to fill the gap.

```bash
sudo -u acl-pep python -m pep.host init-halt --halt /var/lib/acl-pep/halt.json
```

5. Start the host as that same user. `--admin` is the operator socket. It lives in the private directory, mode 0600. The agent socket has no grant command. `serve` without `--admin` has no way to mint a grant, so every call is denied.

```bash
sudo -u acl-pep python -m pep.host serve \
  --socket /run/acl-pep/pep.sock \
  --admin /var/lib/acl-pep/admin.sock \
  --halt /var/lib/acl-pep/halt.json \
  --log /var/lib/acl-pep/decisions.log
```

The host refuses to listen unless the socket directory is owned by the host user, is not a symlink, and is not writable by group or other. It creates the socket with a umask that leaves the file mode 000, then sets mode 0660 and checks that the socket's group is the directory's group. That is why the directory is setgid: the host user does not have to be a member of `acl-agent`. An existing socket is removed only when nothing is listening on it. A live socket, a symlink, or a file that is not a socket is left in place and the host exits.

The halt file and the log are mode 0600, owned by the host user. Their directories must be mode 0700 and owned by the host user. The log is opened with `O_NOFOLLOW` and the mode is set on the open file. The agent can send bytes to the socket. It cannot rewrite the halt file or the log unless it is the host user or it can write the directory.

Optional `--allow-uid` and `--allow-gid` may be repeated. When either list is set, a peer that is not on it is denied. When both are set, the peer must match both. With neither, the socket mode is the connection check. The admin socket still requires the connecting process to be the host user.

The kernel reports the credentials of the process that called `connect`. If that process passes the connected socket to another process, the host still sees the original process.

6. From the agent, send one JSON object per line. The only keys are `tool_name` and `args`.

```json
{"tool_name": "echo.ping", "args": {"message": "hi"}}
```

Anything else (`now`, `principal`, `session_id`, `tool`, a capability token, an approval id) is denied. The host reads the connecting process's user id, group id and process id from the socket (on Linux, the kernel's peer credentials) and assigns a session to that connection. The agent never sends the session name. A second connection is a different session, so it cannot use a grant that was minted for the first one.

A call is allowed only when the operator has minted a grant for that connection, for that tool and those arguments, and the grant has not expired on the host's clock. The agent holds the connection open. The operator, as the host user, lists it and mints the grant. A new connection is a new session, so a one-shot client that connects and sends in the same breath has no grant and is denied.

```bash
sudo -u acl-pep python -m pep.host sessions --admin /var/lib/acl-pep/admin.sock
sudo -u acl-pep python -m pep.host grant \
  --admin /var/lib/acl-pep/admin.sock \
  --connection 1 \
  --tool echo.ping \
  --args '{"message":"hi"}' \
  --ttl 60
```

The built-in registry runs `echo.ping`. The agent does not supply the function.

The client checks two things before it trusts a reply. The socket file must be owned by the expected host user, and `SO_PEERCRED` on the connection must show that same user id. If the host is down, the peer does not match, or the reply does not arrive before the timeout (5 seconds), the client returns a DENY. It does not raise.

Limits on this reference host: a request over 64KiB, or JSON nested deeper than 32, is DENY and the denial is appended to the log. At most 8 agent connections are handled at once, one thread each; a further connection is DENY `connection_limit`. The idle timeout is per read. A connection with no bytes for 5 seconds is closed with DENY `idle_timeout`, and that session is dropped. A client that keeps sending a byte before that timeout is closed 30 seconds after accept, with DENY `connection_deadline`. Until then it holds one of the 8 slots. The gate still fails closed, and a kill still denies a call that has not entered the tool.

Denial lines for a call that has not been admitted are capped at 30 per window of one second. The clock is read inside the lock that counts them. A clock that reads 0 is not treated as a summary already written. Further denials in that window are not written one by one. When the window closes, one `rate_limited` line is written with that window's count, and the count is reset. The same line is written on shutdown if a count is still held. The caller of a counted denial still receives DENY with the original reason. The second halt check, a tool that raises after entry, and a fence denial after the pre-entry line are each their own log line and are not part of the count. There is no argument-size budget beyond the request cap, and a tool result is still only labelled, not checked.

The halt and log checks cover the immediate directory only, not its parents. At startup the host reads the decision log, up to 1MiB, to continue sequence numbers, and refuses a larger file. The halt store fsyncs the temporary file before the rename and fsyncs the directory after it. The log descriptor is checked with `fstat` before `fchmod`.

To halt the gate:

```bash
sudo -u acl-pep python -m pep.host kill --halt /var/lib/acl-pep/halt.json
```

If that write fails, the command exits non-zero. A host process that was already running and fails to write a kill stays halted. A kill that lands after a call has passed its first halt check is read again immediately before the tool runs. If the file is no longer active, the host engages the in-process fence and returns DENY. The tool does not run. A tool body that has already started is not unwound. Deleting `halt.json` does not turn the gate back on. The next process treats a missing file as halted. A file that says suspended at startup denies with `suspend_active` and is not latched for the life of the process; a later active file can proceed. A missing, killed, or corrupt file is latched. If the file disappears while the process is opening, the host does not replace it with a fresh active file.

The decision log is JSON lines in `/var/lib/acl-pep/decisions.log`. Each line lists the checks that ran for that call. It does not contain a field that is true by construction, such as "policy unchanged". Denials are in this file even when the agent throws away the reply.

Full decision: [`docs/adr/ADR-0007-reference-host-process.md`](docs/adr/ADR-0007-reference-host-process.md).

## Receipt shape

Public receipts match `eval/expected_deny_receipt.example.json` and the frozen v1 schema (`eval/receipt.schema.json`):

- `decision`, `reason_code`, `pep_id` (`acl-pep-stub-host-runtime-001`), `policy_version` (`0.2.0-stub`)
- `judge.path: host_runtime_deterministic`, `llm_cot_transcript_judge: false`, `agent_prose_used_as_policy: false`
- `negative_controls_observed`: policy unchanged, no tool invoke, monitor coax not accepted
- `brand: Agent Control Lab`, `licence: Apache-2.0`

`envelope_hash` is `sha256:` plus hex of the **canonical** envelope bytes: UTF-8 JSON, sorted keys, compact separators (see `pep/canonical.py`). The example file hashes on-disk pretty-printed bytes; the live digest may differ.

## Layout

| Path | Role |
| --- | --- |
| `pep/envelope.py` | Lab + flat envelope parse; prose is not policy |
| `pep/policy.py` | Frozen stub allowlist (`echo.ping` only) |
| `pep/approval.py` | Single-use TTL approval store (operator-issued grants bound to tool + canonical args and to a host-attested principal, optionally to a host state digest) |
| `pep/halt.py` | Durable kill / suspend JSON store (optional; survives restart) |
| `pep/evaluate.py` | PEP trust domain: `evaluate(envelope) -> Decision`; kill/suspend API |
| `pep/gate.py` | Never invoke on DENY; `begin_invoke` / `complete_invoke` fence late effects. The callable argument is not a security boundary |
| `pep/host/` | Reference host process: Unix socket, registry, clock, connection identity, halt file, append-only decision log |
| `pep/receipt.py` | Frozen v1 receipt (`validate_receipt`) |
| `pep/row.py` | Loader for the official `eval/` row |
| `pep/corpus.py` | Loader for M1 `eval/corpus/` rows (same `evaluate()` path) |
| `pep/demo.py` | Prints the live official-row deny receipt |
| `eval/` | Official Deep Research row, envelope, prose, expected receipt, frozen receipt schema |
| `eval/corpus/` | M1 structured envelopes + expected receipts (deny classes + catalog-bound ALLOW + approval binding) |
| `docs/adr/ADR-0001-lab-pep-architecture.md` | Architecture decision: trust domain, grants, fail-closed, halt, receipts |
| `docs/adr/ADR-0007-reference-host-process.md` | The gate runs as its own process under its own user. The in-process library is not a security boundary |
| `docs/ROADMAP.md` | stub → v0.2 → v0.3 / EOI M1 → v0.3.1 approval binding → v0.3.2 late-effect fence → v0.3.3 state digest → v0.4.0 principal binding → v0.5.0 capability holders → v0.6.0 implementation binding → v0.7.0 execute what was digested |
| `docs/threat-model.md` | Public host/runtime PEP threat model and control taxonomy |
| `docs/DILIGENCE-HISTORY.md` | Residual historical PR refs by SHA/ref (tip stays Lab-clean) |
| `SECURITY.md` | Fail-closed default, trust domain, how to report issues |
| `CONTRIBUTING.md` | Lab-only artefacts; reject commercial/bank paths and brand strings |
| `scripts/check_lab_only.sh` | Wrapper for the Lab-only keep-out (job `forbidden-tokens`) |
| `scripts/lab_brand_wall.py` | Packed keep-out scan (stdlib Python; no ripgrep) |

## Trust domain

```
agent / optional monitor / HITL UI
              |  tool_name and args on the Unix socket
              v
     pep.host (separate process)     <-- reference gate
              |  registry function, ALLOW only
              v
          tool invoke
```

`pep.evaluate` and `pep.gated_invoke` stay for tests and corpus rows. In-process, the caller supplies the callable, the clock and the principal.

A hostile reviewer reading `pep/evaluate.py` should not be able to relabel this as a model-graded monitor. Policy is frozen bytes. Envelope `policy_context` cannot rewrite the allowlist.

## License

Apache License 2.0. See `LICENSE`. Source files carry `SPDX-License-Identifier: Apache-2.0`.

**Brand:** Agent Control Lab. Public-goods / Navigators / philanthropic AI-control reference. Not a commercial product.
