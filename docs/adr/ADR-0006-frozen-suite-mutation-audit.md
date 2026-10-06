# ADR-0006: Audit the PEP test suite against independently specified mutants

- **Status:** Accepted, 2026-10-06 (owner), with the four recommendations under "Owner decisions".
- **Implementation:** done, all four phases.
  - Phase 1, the harness and self-test, is pep#22, with a scoring fix in pep#24. Phase 1 and its independent review refined decisions 3 to 5 as recorded below:
    - the seal must be committed once and never edited;
    - a patch must edit one file in place and apply exactly where it says;
    - a mutant that breaks the package import counts as killed;
    - activation for a deletion or comment-only change is anchored in the function that held it.
  - Phase 2 is pep#23: ten mutants written by a fresh-context agent, reviewer class `same-family`, approved by the owner and sealed against `5189e13`.
  - Phase 3 is pep#25: audit `2026-10-06-gate`, 8 of 10 killed. M07 and M09 survived as oracle-masked and were filed as pep#26 and pep#27; both were test gaps, not PEP bugs.
  - Phase 4 is the test-only repairs in pep#28 and pep#29, and the repair re-run `2026-10-06-gate-r1` in pep#30: 10 of 10, a repair result on the same set.
  - Two departures from the phase text below:
    - one same-set re-run followed both repairs, not one per repair;
    - the re-run's seal and results arrived in one PR, with the seal commit pushed before the run.
  - A new estimate needs a new, independently specified set.
- **Date:** 2026-10-06
- **Depends on:** nothing. It audits the tests behind ADR-0002 to ADR-0005; it changes no PEP behaviour.
- **Origin:** research-loop work package WP-RL-010 (run `acl-rl-2026-10-05-1400`, finding RF-20261005-07).
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

**What the suite is trusted for.** Every fail-closed claim in this repository is backed by a test that passes on the reference tree. A test that passes on the reference tree shows the code does what the test checks. It does not show the test would fail if the code were wrong.

**What has been done so far.** ADR-0004 and ADR-0005 were each mutation-checked during review: the PR descriptions of pep#16, #19 and #21 record mutants caught and, where some survived, a test strengthened or redundant code removed (pep#16 also records two equivalent mutants left standing). Those checks have three weaknesses as evidence:
- the mutants were written by the same author, in the same session, as the tests they checked, so the author knew what the tests check;
- the test tree was not frozen, and tests were changed in response to survivors within the same PR;
- they covered only the code each PR added.

So they are development practice, not an audit. No file in this repository records a mutation kill rate for the gate as a whole.

**Outside evidence.** Xu and Tao (arXiv:2610.02928v1, NeurIPS 2026 workshop paper, read in full by the research run) froze and hashed a verification suite, then ran it once against 10 first-order mutants specified by an outside reader.
- The suite had passed the usual correct-versus-broken validation, yet killed 5 of the 10.
- The five survivors were classified as never activated (3) or activated but oracle-masked (2).
- After repairs, the authors report 10 of 10, and say that is "a result on the same challenge set, not a second held-out estimate".

It is one synthetic, deterministic system, and the outside reader saw check titles. This ADR takes the method, not the numbers.

**Why it fits here.** The PEP is deterministic and its core is small: `pep/approval.py`, `pep/gate.py` and `pep/evaluate.py` are 1,350 lines at `41cb8cc`. A frozen run against hand-written mutants is cheap at that size.

## Decision

Run a frozen-suite mutation audit of the PEP gate, with mutants specified independently and sealed before the run, using a small harness that adds no dependency.

1. **Scope of the first audit.** `pep/approval.py`, `pep/gate.py` and `pep/evaluate.py` at a stated commit. `pep/implementation.py`, `pep/envelope.py` and `pep/policy.py` are candidates for later rounds.
2. **Mutants.** Ten first-order mutants, each one change to one of the three files. Each is a unified diff, `audits/<id>/mutants/Mnn.patch`, with a one-line intent and the fail-closed property it attacks. The reviewer writes them from the code and the ADRs only, without reading `tests/`, commit messages or PR descriptions. Who the reviewer is is an owner decision.
3. **Seal before running.** `scripts/mutation_audit.py freeze <id>` writes `audits/<id>/freeze.json` with:
   - the PEP commit;
   - the SHA-256 of every git-tracked file under `tests/`, of `pyproject.toml` and of the harness itself;
   - the SHA-256 of every mutant patch;
   - the Python version.

   Hashing tracked files, not everything on disk, means a local `pytest` run that writes `__pycache__` does not break the seal. An untracked file under `tests/` that pytest would collect refuses the run instead. The freeze file and the mutants are committed together before any run, much as joint-eval seals its B7 preregistration notes: a SHA-256 of the frozen bytes, pinned before the result exists. `run` enforces it: `audits/<id>/` must have no uncommitted change, `freeze.json` must appear in exactly one commit, and no mutant may change after that commit. `freeze` and `run` refuse a shallow clone, because that history is incomplete and the one-commit check could pass or fail for the wrong reason.
4. **Run.** `scripts/mutation_audit.py run <id>`:
   - It refuses to start if the seal is not committed as decision 3 requires, if any hash in `freeze.json` differs from the working tree, or if the Python minor version differs.
   - It runs the unmutated suite first. Any failure aborts the audit. So does a baseline that writes no activation record, or that exits non-zero with no failed test: that is a harness fault, not a failing suite.
   - Each mutant runs in a fresh copy of the tree at the frozen commit, extracted with `git archive` into a temporary directory, so no mutant can affect another and the repository's own git metadata is not touched. Each copy is checked against the sealed hashes. The patch is applied with `git apply`, with git kept from finding an enclosing repository and from reading system or global git config, either of which could change the result. A patch that does not apply, or applies away from the lines its hunks state, is recorded as `invalid`, never as killed. A patch that changes anything other than its target's content (a rename, a mode change, a second file) is refused at freeze, and the run aborts if applying changed any other file in the copy, by content or by name.
   - The suite runs in a subprocess from the copy, with `PYTHONDONTWRITEBYTECODE=1`, the pytest cache disabled and a per-mutant timeout. Before any test runs, the plugin checks that `pep` was imported from the copy. CI installs the package in editable mode, and without this check every mutant could silently test the original tree. A mutant that makes the import fail is `killed`: the suite caught it. The harness self-test is left out of these runs, since it cannot observe a PEP mutant. A pytest process that exits 0 and writes no activation record aborts the audit. A non-zero exit that recorded no failed test is not a kill: on a mutant it is `harness-fault` (decision 5).
   - Hashes are checked again after each mutant. Drift aborts the run.
5. **Activation.** A pytest plugin in `scripts/` uses `sys.settrace` and `threading.settrace`, limited to the mutated file, to record whether any test executed a line the patch changed. Several gate tests run the gate in worker threads, so the thread hook is required. The changed lines are the `+` lines in the patch body, not the hunk-header ranges, which include context lines. A `+` line counts only if it can raise a line event (a comment or a bare `else:` cannot), and it counts in whatever frame runs it, so a changed `def` line, default or module constant counts as activated at import. A change block with no such line (a deletion, or a comment-only change) is anchored in the function that held it in the original file, found in the mutated file by its name and its first line shifted by any earlier hunks: activation is the first line after the change in that function, or entry into the function when nothing follows. Each mutant gets exactly one outcome:
   - `killed`: at least one test failed, or collection or the package import failed. The first failing test ids are recorded.
   - `survived-never-activated`: no test executed a changed line.
   - `survived-oracle-masked`: a changed line ran and every test still passed.
   - `timeout`: the suite exceeded the timeout.
   - `invalid`: the target file is not in the frozen commit, the patch does not apply, a hunk applied away from its stated lines, the mutated file does not compile, or the activation target cannot be resolved in the mutated file. Outside the denominator.
   - `harness-fault`: pytest exited non-zero and recorded no failed test (an internal error, an interrupt, or a crash). Not evidence the suite caught the mutant. Outside the denominator. The reason is in the report.
6. **Report.** `audits/<id>/results.json` and `results.md` hold one row per mutant: id, file, activation targets, intent, property, outcome, killing tests, duration. A row's detail (why a patch is invalid, or why a run is a harness fault) is included in the report. The kill rate is reported as measured, with no pass threshold. Any survivor that touches a fail-closed path is filed as a defect.
7. **Repairs.** Fixes for survivors go in separate PRs. A re-run against the same sealed mutants is reported as "repair result on the same set", never as a new estimate. A new estimate needs a new, independently specified set.
8. **Harness self-test.** `tests/test_mutation_audit.py` runs the harness against a toy package in a temporary directory, with three control mutants:
   - one the toy suite kills;
   - one on a line the toy suite never runs;
   - one that runs but that no assertion checks.

   These controls exercise `killed` and the two survival classes. Further controls and cases cover a thread-only line, a deletion, an import-breaking mutant, `invalid` (including an offset hunk), `timeout`, hash drift, an uncommitted or edited seal, baseline failure, the import-location check, refused patch shapes, a non-zero pytest exit with no failed test, a missing activation record, git config isolation, a shallow clone and the report rules. They check the harness, not the PEP, and run in CI with the rest of the suite.
9. **No PEP change.** The harness lives in `scripts/` and the records live in `audits/`. The PEP package, its receipts and its version do not change in this ADR.

## Options considered

| Option | What it measures | Assessment |
| --- | --- | --- |
| **A. Frozen suite, independently specified and sealed mutants, stdlib harness (accepted)** | Whether the suite catches faults a reader who has not seen it would expect | Adapts the cited paper's method: it drops the paper's step of registering predictions about missing input dimensions, and its blindness rule is stricter, since the paper's reader saw check titles. Cheap at this code size; no Python dependency (it uses the `git` command, which CI already has) |
| B. An automatic mutation tool (mutmut, cosmic-ray) | Syntactic mutant coverage over every operator | Many mutants, little intent, and a new dependency. It would measure something different. A possible later complement, not the primary method |
| C. Keep maker-written mutation checks in PRs | What the test author thought to check | Not independent, and not frozen. Kept as development practice, not as evidence |
| D. Line coverage only | Which lines run | Says nothing about whether an assertion would fail. Rejected; activation tracking (decision 5) uses the useful part |

## Owner decisions

Settled on 2026-10-06: the owner accepted all four recommendations.

1. **Who specifies the mutants?** The ADR-0004 and ADR-0005 tests were written by an AI assistant, which also wrote their review mutants. The earlier tests arrived on `cursor/*` agent branches, which suggests AI authorship there too, though the repository does not record it. A reviewer of the same model family is therefore not independent in the sense the paper means. The options, strongest first:
   - the owner, or another person;
   - a model from a different family;
   - a fresh-context agent of the same family that is given only `pep/*.py` and the ADRs, with that limit stated in the report.

   Decided: the owner or another person. If that is not practical, a fresh-context agent with the limit recorded. In every case the owner reviews and seals the list before the run.
2. **Timeouts.** Decided: a separate `timeout` column. The kill rate is reported twice: once counting timeouts as killed, once without.
3. **Equivalent mutants.** A mutant the reviewer later argues is behaviour-identical stays in the raw denominator. Decided: a second rate excludes it only with the owner's written sign-off on the argument.
4. **First-audit scope.** Decided: the three gate files named in decision 1. `pep/implementation.py` waits for a later round.

## Residuals (what this does not fix)

- **Small sample.** Ten mutants give a coarse rate, 10 percentage points per mutant. It describes these mutants at this commit, nothing wider.
- **First-order, hand-written mutants.** They reflect the reviewer's model of likely faults. Combined faults and faults the reviewer does not imagine are not tested.
- **Line-level activation.** A changed line that runs counts as activated even if the changed sub-expression was short-circuited, so some never-activated survivors may be reported as oracle-masked. Lines that run at import (a `def`, a default, a module constant) always count as activated.
- **Python-version dependence.** Which lines can raise a line event differs between Python 3.11 and 3.12 (3.12 reports more of them, mostly in function signatures: 54 more across the three gate files at `41cb8cc`), so the same mutant can be classified differently. The seal pins the minor version, so one audit is consistent, but audits under different versions are not comparable.
- **Untraced execution.** Code a test runs in a child process is not traced, so a mutant reached only that way would be reported as never activated. Three current test files start child processes (fixture tool scripts and the brand-wall script); none of them runs the three gate files. The settrace hook also does not see threads started before the plugin loads, or code that runs before pytest configures plugins (no `conftest.py` imports the PEP today).
- **Escaped children.** The suite's process group is killed when each run ends. A child process that starts its own session escapes that.
- **Blindness depends on discipline.** A reviewer who reads `tests/` or the PR descriptions first invalidates the independence. The harness cannot detect that.
- **Repairs are not held-out.** After survivors are fixed, the same set says little about the suite's discrimination on new faults.
- **No absence of faults.** A 10 of 10 result shows the suite catches these mutants, not that the gate is correct.

## Consequences and dependent changes

### pep (this repository)

- **Phase 1:**
  - `scripts/mutation_audit.py` (freeze, run, report) and `scripts/mutation_activation.py` (the pytest plugin);
  - `tests/test_mutation_audit.py` with the toy package and controls;
  - an `audits/README.md` that states the method and the reporting rules.
- **Phase 2:** the reviewer writes the mutants. The owner reviews them, then `freeze`. The mutants and `freeze.json` are committed together, before any run commit.
- **Phase 3:** `run`, then the results are committed and defects filed.
- **Phase 4:** repairs, in their own PRs, each followed by a same-set re-run labelled as a repair result.

### Siblings

None in this ADR. The research work package names supply-gate as a later target for the same method.

### Phases

| Phase | Scope | Green during transition because |
| --- | --- | --- |
| 1. Harness and self-test | Scripts, toy-package tests, `audits/README.md` | Additive; the PEP package does not change |
| 2. Mutant specification and seal | `audits/<id>/mutants/` and `freeze.json` | Data only |
| 3. Frozen run and report | `audits/<id>/results.*`, defect issues | Data only; the run does not modify the tree |
| 4. Repairs | Separate PRs per defect | Each repair is ordinary test or code work |

## Acceptance

**Phase 1, the harness:**

| Case | Required |
| --- | --- |
| Toy control mutant that the toy suite catches | `killed`, with the failing test id |
| Toy control mutant on a line no toy test runs | `survived-never-activated` |
| Toy control mutant that runs but no assertion checks | `survived-oracle-masked` |
| Mutant that loops forever | `timeout` within the configured limit; the run continues |
| Patch that does not apply | `invalid`; not counted as killed |
| Patch that applies only at an offset from its stated lines | `invalid` |
| Patch with a rename or mode change, or a second file | Refused at `freeze`; if one reaches `run`, the run aborts after applying |
| Mutant that breaks the package import | `killed` |
| Deletion of the last statement of a function no test calls | `survived-never-activated` (entry into the function is the target) |
| A test file edited after `freeze` | `run` refuses to start |
| `freeze.json` or a mutant not committed, or changed in a later commit | `run` refuses to start |
| A test file edited during a run (simulated) | The run aborts at the next hash check |
| Unmutated suite failing | The audit aborts before any mutant |
| Two mutants on the same file | Independent results; the second does not see the first |
| Plugin imports `pep` from outside the mutant copy (simulated) | The run aborts; no outcome is recorded |
| A test that reaches the mutated line only in a worker thread | Counted as activated |
| An extracted copy whose tests differ from the seal | The run aborts |
| Pytest exits non-zero and records no failed test | `harness-fault`, not killed; the reason is in `results.md`; outside the kill rate |
| Pytest exits 0 and writes no activation record | The audit aborts with `AuditAborted`; no traceback |
| System or global git config sets `apply.whitespace` | The patch still applies as written |
| Shallow clone | `freeze` and `run` refuse |
| The PEP working tree after a run | No tracked file changed; the only new files are `audits/<id>/results.json` and `results.md` |

Phase 1 also requires that the full PEP suite and the brand-wall checks pass, and gets an independent review.

**Phases 2 and 3:**
- The mutant list and `freeze.json` are committed before the run commit, and the run commit's hashes match them.
- `results.md` reports every mutant with exactly one outcome, the kill rate as measured with no threshold, and the reviewer's identity class (person, other model family, or same family) as decided above.

**What success would establish:** for these mutants, at this commit, how many the frozen suite catches, and where it is blind.

**What it would not establish:**
- that the gate is correct;
- anything about faults outside the mutant set;
- discrimination after repairs;
- live enforcement;
- any measured attack-success rate.
