# ADR-0005: Execute the artefact that was digested

- **Status:** Proposed, 2026-10-05. Awaiting owner decision; see "Owner decisions" below.
- **Date:** 2026-10-05
- **Depends on:** [ADR-0004](ADR-0004-approval-implementation-binding.md) (implementation digest at mint, consume and entry).
- **Amends:** ADR-0004 "Residuals", the check-to-exec race bullet. Its last remedy sentence ("executing the artefact from the same open file descriptor it digested") is not sufficient on its own; see Context.
- **Origin:** research-loop work package WP-RL-009 (run `acl-rl-2026-10-05-1400`, finding RF-20261005-06).
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

**The residual.** ADR-0004 binds a grant to a host-computed digest of the implementation resolved at mint. The PEP re-checks a host observation at consume and at tool entry. It cannot see what the host's callable does after that. `tests/test_approval_implementation_binding.py::test_swap_after_the_entry_check_is_residual` shows the gap: the entry check passes, then the tool resolves `labtool` again, `PATH` has changed, and program B runs. The window runs from the entry re-observation, through `claim_entry`, to the exec inside `tool()` (`pep/gate.py`).

**Why a path cannot close it.** Any exec by path resolves the name again, and the file at that path can be replaced between the check and the exec. The fix has to make the thing that runs the same object as the thing that was digested.

**What was checked, and how.** The research run cited specifications only: execveat(2), fexecve(3), memfd_create(2) and Python's `os.execve`. Before writing this ADR, each claim was tried in the development container (Linux 6.18, Python 3.11.15, `vm.memfd_noexec = 0`). These are observations in one environment, not tests in this repository:

| Question | Observed |
| --- | --- |
| `os.execve in os.supports_fd` | True |
| `os.memfd_create` and `fcntl.F_ADD_SEALS` available | True, both |
| Does a plain `O_RDONLY` fd protect the contents? | **No.** After an in-place write to the same file, `os.pread` on the fd opened earlier returned the new bytes. |
| Write to a memfd sealed with `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, `F_SEAL_SEAL` | Refused, `EPERM` |
| `python /proc/self/fd/N` on a sealed copy, after the file on disk was replaced | Ran the copied bytes (program A) |
| Direct exec of a shebang script and of an ELF binary from a sealed memfd, fd passed to the child | Both ran |
| The same exec with the fd not passed (close-on-exec) | `ENOENT`, matching fexecve(3) |
| A `#!/usr/bin/env python3` script from a sealed memfd, with `PATH` changed afterwards | Ran the interpreter from the changed `PATH` |
| 50 open-and-close cycles of a `MFD_CLOEXEC` memfd | No fd leak |

Two corrections follow. First, ADR-0004's remedy, "the same open file descriptor", closes a path swap but not an in-place write to the file it points at. Second, a script's interpreter is a second resolution by path, and sealing the script does not pin it.

## Decision

`pep/implementation.py` gains an optional host-side helper. It copies the resolved program into a sealed in-memory file, digests that sealed copy, and runs it. The PEP core does not change: `evaluate`, `gate`, the envelope, the reason codes and receipt schema v1 stay as they are.

1. **Open.** `open_executable(name, path=None)` works as follows:
   1. It resolves `name` with `shutil.which` and takes the real path, exactly as `executable_digest` does.
   2. It opens the file `O_RDONLY | O_CLOEXEC` and copies its bytes into a memfd created with `MFD_ALLOW_SEALING | MFD_CLOEXEC`.
   3. It sets mode `0o500` and adds `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK` and `F_SEAL_SEAL`.
   4. It returns a `ResolvedExecutable`.
2. **Digest.** `ResolvedExecutable.digest` is computed from the real path and the bytes read back from the sealed copy, using the same formula as `executable_digest`. A digest frozen at mint with `executable_digest` therefore matches an unchanged program. A file changed between `which` and the copy gives a different digest, so the PEP denies it.
3. **Run.** `ResolvedExecutable.run(args, *, interpreter=None, **subprocess_kwargs)` runs `/proc/self/fd/<fd>` with the memfd in `pass_fds`, and returns the `subprocess.CompletedProcess`:
   - when `interpreter` is a string, it runs `[interpreter, "/proc/self/fd/<fd>", *args]`;
   - when `interpreter` is another `ResolvedExecutable`, it runs that one's fd as the interpreter, and both fds are passed to the child.

   Caller-supplied `pass_fds` are merged, not replaced. It has no `shell` option.
4. **Host pattern.** The host opens one handle per invoke. The same handle serves the observer and the tool:

   ```python
   with open_executable("labtool") as program:
       decision, result = gated_invoke(
           envelope,
           lambda: program.run([...], capture_output=True),
           runtime=runtime,
           principal=host_principal,
           implementation_observer=lambda: program.digest,
       )
   ```

   The consume and entry observations then report the digest of the exact bytes that will run, and nothing re-resolves after the copy. This narrows ADR-0004's "the host re-resolves at entry": with this helper, the entry observation does not re-resolve. It confirms the pinned artefact that is about to run.
5. **Interpreters.** `combined_digest(*resolved)` gives one `sha256:` digest over several handles, in order. A host that wants the interpreter bound as well as the script does three things:
   - freezes `combined_digest(script, interpreter)` at mint;
   - observes the same value;
   - passes `interpreter=` to `run`.
6. **Fail closed.** On a platform without `os.memfd_create`, sealing support or `/proc/self/fd`, `open_executable` raises `ImplementationUnavailable`, a subclass of `OSError`. It never falls back to exec by path. Raised inside an observer, this is the existing `approval_implementation_mismatch` (ADR-0004 decision 3). Raised before `gated_invoke`, the host gets an exception and no invoke happens. If the exec itself fails (for example under a kernel policy that blocks exec from memfd), `run` raises, after the grant is already spent.
7. **Version.** pep moves to 0.7.0. The helper is new public API; nothing existing changes.

## Options considered

| Option | Runs | Assessment |
| --- | --- | --- |
| **A. Sealed memfd copy, digest after sealing, exec from the copy (proposed)** | The sealed bytes that were digested | Closes path swaps and in-place writes after the copy. Costs one in-memory copy of the program per invoke. Linux only. |
| B. Plain `O_RDONLY` fd, `fexecve` / `os.execve(fd)` | Whatever the inode holds at exec time | Closes path swaps but, as observed above, not an in-place write to the same inode. Rejected as the default; it would also need a fork and exec wrapper in place of `subprocess`. |
| C. Absolute path, re-digest just before exec | The file at that path at exec time | Shrinks the window but leaves it open. Rejected. |
| D. Keep the residual, document a host recipe | Unchanged | Leaves every host to get the primitive right, and the plain-fd mistake is easy to make. Rejected as the only answer; the recipe stays in the docstring. |
| E. Kernel integrity (fs-verity, IMA, an LSM policy) | Verified files only | Stronger, and system-wide. It needs host configuration that a reference PEP cannot assume. Out of scope; noted as the production route. |

## Owner decisions

1. **Sealed memfd only, or also a plain-fd variant?** Recommend memfd only. The plain fd fails the in-place write case. Offering it invites the mistake ADR-0004's own wording made.
2. **Interpreter binding now, through `interpreter=` and `combined_digest`, or later?** Recommend now. It is small, and without it a `#!/usr/bin/env` script stays fully exposed through its interpreter.
3. **Version 0.7.0 or 0.6.1?** Recommend 0.7.0, because the helper is new public API.

## Residuals (what this does not fix)

- **Hosts that do not use the helper.** The PEP cannot tell whether the tool ran the handle. A host that observes `program.digest` but execs by path reopens the race. This is the same trust as ADR-0004's host-honesty residual.
- **What the program loads by path.** Shared libraries, Python imports, configuration files, and any program the child runs by name are not covered. For interpreted programs this is large: a sealed script still imports its modules from `sys.path`.
- **Unpinned interpreters.** A script run directly (`run(args)` with no `interpreter=`) has its shebang interpreter resolved by path. With `#!/usr/bin/env`, that is a `PATH` lookup, as observed above.
- **In-process callables.** Unchanged from ADR-0004: `callable_digest` covers the code object only.
- **The window before the copy.** A swap between `which` and the copy is not a residual. It gives a digest mismatch and a DENY. It also means a benign update in that window denies.
- **Platforms and kernel policy.** The helper is Linux only. macOS and Windows raise `ImplementationUnavailable`. A kernel with `vm.memfd_noexec = 2`, or an LSM that forbids exec from memfd, makes `run` fail after the grant is spent. That case was not observed here, because this container has `memfd_noexec = 0`.
- **Equivalent-access attackers.** A caller that can `ptrace` the child or write the parent's memory is out of scope, as in ADR-0002.
- **Cost.** One full copy of the program into memory per invoke. Large binaries make this visible.

## Consequences and dependent changes

### pep (this repository)

- `pep/implementation.py`: `open_executable`, `ResolvedExecutable`, `combined_digest`, `ImplementationUnavailable`.
- New tests:
  - `tests/test_execute_digested.py`: the acceptance table below.
  - The existing `test_swap_after_the_entry_check_is_residual` stays unchanged, as the case where the host does not use the helper.
- Docs:
  - ADR-0004: annotate the check-to-exec bullet as amended here.
  - `docs/threat-model.md`: narrow the check-to-exec non-goal to hosts that do not use the helper, plus the residuals above.
  - `README.md`, `docs/ROADMAP.md`.
- Version 0.7.0.

No corpus receipt changes, because no fixture runs a program.

### Siblings

Nothing pins this behaviour. joint-eval and console are unaffected until they adopt the helper.

### Phases

| Phase | Scope | Green during transition because |
| --- | --- | --- |
| 1. Helper and tests | `pep/implementation.py` additions and `tests/test_execute_digested.py` | Additive; no existing caller changes |
| 2. Docs and version 0.7.0 | Everything under Docs above | Docs only |

## Comparison experiment and acceptance

All tests are Linux-only and skip elsewhere, as the existing `PATH` tests do. "Before" is pep `406bf60` (0.6.0).

| Case | Before (0.6.0) | Required after |
| --- | --- | --- |
| Bound grant; host uses the helper; `PATH` swapped inside the tool after the entry check | ALLOW, program B (residual) | ALLOW, **program A** |
| Bound grant; helper; symlink retargeted after `open_executable` | n/a | ALLOW, program A |
| Bound grant; helper; in-place write to the original file after `open_executable` | n/a | ALLOW, program A (the sealed copy is unaffected) |
| Bound grant; file changed before `open_executable` (between mint and copy) | n/a | DENY `approval_implementation_mismatch` at consume; not consumed |
| `open_executable(name).digest` on an unchanged program | n/a | Equals `executable_digest(name)` |
| Write, grow or shrink attempted on the handle's fd | n/a | Refused |
| Script with `#!/usr/bin/env python3`, `PATH` swapped, no `interpreter=` | n/a | Named residual test: the swapped interpreter runs |
| Same script with `interpreter=` a `ResolvedExecutable`, grant frozen on `combined_digest` | n/a | The pinned interpreter runs |
| Interpreter changed after mint, grant frozen on `combined_digest` | n/a | DENY `approval_implementation_mismatch`; not consumed |
| `os.memfd_create` unavailable (patched out) inside the observer | n/a | DENY `approval_implementation_mismatch`, "implementation observer failed"; not consumed; no exec by path |
| Same, called before `gated_invoke` | n/a | `ImplementationUnavailable` raised; no invoke |
| Caller passes its own `pass_fds` | n/a | Both its fds and the handle's fd reach the child |
| 100 handles opened and closed | n/a | No fd leak (`/proc/self/fd` count unchanged) |
| Kill between admission and entry, helper in use | DENY `late_effect_fence` | Unchanged |
| Existing `test_swap_after_the_entry_check_is_residual` (helper not used) | ALLOW, program B | Unchanged |
| Corpus receipts | Current | Byte-identical (`regen_corpus_receipts.py --check` clean) |

Further acceptance requirements:
- Measure and report the added cost of `open_executable` plus `run` against ADR-0004's bound path with `executable_digest`. The ceiling stays provisional at 1 ms median for the stub test program; going over it is a finding, not an automatic fail.
- Run mutation checks on the helper (no seal, digest from disk instead of the copy, path fallback on failure, `pass_fds` replaced instead of merged). Each must be caught.
- The full pep suite and the brand-wall checks pass. Each phase gets an independent review.

**Rollback:** revert the helper commits. Nothing else depends on it.

**What success would establish:** on Linux, for these fixtures, a host that uses the helper runs exactly the bytes whose digest the PEP checked, even when the path, a symlink or the original file changes after the copy.

**What it would not establish:**
- protection for hosts that do not use the helper;
- anything about what the program loads by path;
- interpreter pinning unless `interpreter=` is used;
- behaviour on macOS, Windows or kernels that forbid exec from memfd;
- resistance to an equivalent-access attacker;
- any measured attack-success rate;
- live enforcement.
