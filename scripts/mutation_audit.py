#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Frozen-suite mutation audit (ADR-0006). Stdlib only, plus the ``git`` command.

    mutation_audit.py freeze <id> --reviewer person    seal tests, harness and mutants
    mutation_audit.py run <id>                         run the sealed suite once per mutant
    mutation_audit.py report <id>                      rewrite results.md, with signed equivalents

Mutants live in ``audits/<id>/mutants/Mnn.patch``: an ``Intent:`` line, a
``Property:`` line, then a unified diff of one in-scope file. See
``audits/README.md`` for the method and the reporting rules.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS_DIR = Path(__file__).resolve().parent
HARNESS_FILES = ("mutation_audit.py", "mutation_activation.py")
# The harness self-test cannot observe a PEP mutant; leaving it in would only add time and timing noise.
HARNESS_SELF_TEST = "tests/test_mutation_audit.py"
DEFAULT_SCOPE = ("pep/approval.py", "pep/gate.py", "pep/evaluate.py")
REVIEWER_CLASSES = ("person", "other-family", "same-family")
OUTCOMES = (
    "killed", "survived-never-activated", "survived-oracle-masked", "timeout", "invalid", "harness-fault",
)
MAX_KILLING_TESTS = 5
MODULE = "<module>"
ANY_CODE = "*"
_MUTANT_NAME = re.compile(r"M\d{2}\.patch")
_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_NOT_IN_PLACE = (
    "rename ", "copy ", "old mode ", "new mode ", "new file mode ", "deleted file mode ",
    "similarity index ", "dissimilarity index ", "Binary files ", "GIT binary patch",
)


class AuditError(Exception):
    """The audit cannot proceed. Nothing is recorded."""


class FreezeMismatch(AuditError):
    """The working tree no longer matches what was sealed."""


class AuditAborted(AuditError):
    """The run stopped before every mutant had an outcome."""


@dataclass(frozen=True)
class Block:
    """One run of ``-``/``+`` lines: where it sits in each file, and its line numbers."""

    old_start: int
    new_start: int
    minus: tuple[int, ...]
    plus: tuple[int, ...]


@dataclass(frozen=True)
class Mutant:
    """One sealed mutant. ``hunks`` holds each hunk as (its first line in the
    mutated file, the lines that must be found there after applying)."""

    mutant_id: str
    intent: str
    property: str
    target: str
    blocks: tuple[Block, ...]
    hunks: tuple[tuple[int, tuple[str, ...]], ...]


@dataclass(frozen=True)
class Code:
    key: tuple[str, int]
    first: int
    last: int
    lines: frozenset[int]


def parse_mutant(mutant_id: str, text: str) -> Mutant:
    meta: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].startswith(("--- ", "diff --git ")):
        key, sep, value = lines[i].partition(":")
        if sep and key.strip() in ("Intent", "Property"):
            meta[key.strip()] = value.strip()
        i += 1
    for key in ("Intent", "Property"):
        if not meta.get(key):
            raise AuditError(f"{mutant_id}: missing {key}: line")

    olds: list[str] = []
    news: list[str] = []
    gits: list[str] = []
    blocks: list[Block] = []
    hunks: list[tuple[int, tuple[str, ...]]] = []
    body = lines[i:]
    j = 0
    while j < len(body):
        line = body[j]
        hunk = _HUNK.match(line)
        if not hunk:
            if line.startswith("--- "):
                olds.append(line[4:])
            elif line.startswith("+++ "):
                news.append(line[4:])
            elif line.startswith("diff --git "):
                gits.append(line)
            elif line.startswith(_NOT_IN_PLACE):
                raise AuditError(f"{mutant_id}: a mutant edits file content in place, nothing else")
            j += 1
            continue
        old_line, new_line = int(hunk.group(1)), int(hunk.group(3))
        old_left = int(hunk.group(2) or 1)
        new_left = int(hunk.group(4) or 1)
        new_start = new_line
        expected: list[str] = []
        block: Block | None = None
        j += 1
        while j < len(body) and (old_left or new_left):
            line = body[j]
            tag, rest = line[:1], line[1:]
            if tag == "\\":
                j += 1
                continue
            if tag in ("-", "+"):
                if block is None:
                    block = Block(old_line, new_line, (), ())
                if tag == "-":
                    block = Block(block.old_start, block.new_start, (*block.minus, old_line), block.plus)
                    old_line, old_left = old_line + 1, old_left - 1
                else:
                    block = Block(block.old_start, block.new_start, block.minus, (*block.plus, new_line))
                    expected.append(rest)
                    new_line, new_left = new_line + 1, new_left - 1
            elif tag in (" ", ""):
                if block is not None:
                    blocks.append(block)
                    block = None
                expected.append(rest)
                old_line, new_line = old_line + 1, new_line + 1
                old_left, new_left = old_left - 1, new_left - 1
            else:
                raise AuditError(f"{mutant_id}: malformed hunk line: {line!r}")
            j += 1
        if old_left or new_left:
            raise AuditError(f"{mutant_id}: a hunk is shorter than its header says")
        if block is not None:
            blocks.append(block)
        hunks.append((new_start, tuple(expected)))

    if len(olds) != 1 or len(news) != 1 or len(gits) > 1:
        raise AuditError(f"{mutant_id}: a mutant changes exactly one file")
    old, new = (_strip_tab(p) for p in (olds[0], news[0]))
    if not (old.startswith("a/") and new.startswith("b/")):
        raise AuditError(f"{mutant_id}: file headers need a/ and b/ prefixes")
    target = new[2:]
    if old[2:] != target or (gits and gits[0] != f"diff --git a/{target} b/{target}"):
        raise AuditError(f"{mutant_id}: a mutant edits an existing file in place")
    if not blocks:
        raise AuditError(f"{mutant_id}: the patch changes nothing")
    return Mutant(mutant_id, meta["Intent"], meta["Property"], target, tuple(blocks), tuple(hunks))


def _strip_tab(path: str) -> str:
    return path.split("\t", 1)[0].strip()


def code_map(source: str, filename: str) -> list[Code]:
    """Every code object in a module, with the line range it spans and the lines it can run."""
    pending = [(compile(source, filename, "exec"), True)]
    codes = []
    while pending:
        code, is_module = pending.pop()
        lines = frozenset(ln for _, _, ln in code.co_lines() if ln)
        if is_module:
            codes.append(Code((MODULE, 0), 0, sys.maxsize, lines))
        else:
            first = code.co_firstlineno
            codes.append(Code((code.co_qualname, first), first, max(lines, default=first), lines))
        pending.extend((c, False) for c in code.co_consts if hasattr(c, "co_lines"))
    return codes


def _owner(codes: list[Code], *lines: int) -> Code:
    # The def or decorator line belongs to the enclosing code, which runs it.
    return max((c for c in codes for ln in lines if c.first < ln <= c.last), key=lambda c: c.first)


def _new_line(mutant: Mutant, old: int) -> int:
    """Where an unchanged line of the original sits in the mutated file."""
    return old + sum(len(b.plus) - len(b.minus) for b in mutant.blocks if b.old_start + len(b.minus) <= old)


def activation_targets(mutant: Mutant, original: str, mutated: str, filename: str) -> list[tuple[str, int, int | None]]:
    """What counts as running the mutation, as (qualname, first line, line or None for entry).

    A ``+`` line that can raise a line event counts in any frame, so a line run
    at import (a ``def``, a default, a module constant) counts at import. A
    block with no such line (a deletion, a comment) is anchored in the code
    object that held it in the original: the first line after the change in
    that code object, or entry into it when nothing follows. An insertion is
    anchored in the innermost code around either side of it. Raises
    ``ValueError`` when that code object cannot be found in the mutated file.
    """
    before = code_map(original, filename)
    after = code_map(mutated, filename)
    runnable = frozenset().union(*(c.lines for c in after))
    targets: set[tuple[str, int, int | None]] = set()
    for block in mutant.blocks:
        hits = [ln for ln in block.plus if ln in runnable]
        if hits:
            targets.update((ANY_CODE, 0, ln) for ln in hits)
            continue
        if block.minus:
            owner = _owner(before, block.minus[0])
        else:
            owner = _owner(before, block.old_start, max(block.old_start - 1, 1))
        if owner.key[0] == MODULE:
            key = owner.key
        else:
            key = (owner.key[0], _new_line(mutant, owner.first))
        code = next((c for c in after if c.key == key), None)
        if code is None:
            raise ValueError(f"cannot find {owner.key[0]}, which held a change, in the mutated file")
        following = sorted(ln for ln in code.lines if ln >= block.new_start)
        targets.add((*code.key, following[0] if following else None))
    return sorted(targets, key=lambda t: (t[2] or 0, t[0], t[1]))


def describe_target(target: tuple[str, int, int | None]) -> str:
    name, _, line = target
    if name == ANY_CODE:
        return str(line)
    return f"{name}:{line}" if line is not None else f"{name} (entry)"


def freeze(
    audit_id: str,
    *,
    reviewer: str,
    root: Path = ROOT,
    commit: str = "HEAD",
    scope: tuple[str, ...] = DEFAULT_SCOPE,
    package: str = "pep",
    timeout: float = 300.0,
    repair_of: str | None = None,
) -> dict:
    _refuse_shallow(root)
    if reviewer not in REVIEWER_CLASSES:
        raise AuditError(f"reviewer must be one of {', '.join(REVIEWER_CLASSES)}")
    audit = _audit_dir(root, audit_id)
    if (audit / "freeze.json").exists():
        raise AuditError(f"{audit_id} is already frozen")
    sha = _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    drift = _git(root, "diff", "--name-only", sha, "--", "tests", "pyproject.toml").split()
    if drift:
        raise AuditError(f"tests differ from {sha[:7]}: {', '.join(drift)}")
    _refuse_untracked_tests(root)
    mutants = _load_mutants(audit, scope)
    mutant_hashes = {f"mutants/{m}.patch": _sha256(audit / "mutants" / f"{m}.patch") for m in mutants}
    if repair_of is not None:
        original = _read_json(_audit_dir(root, repair_of) / "freeze.json")
        if original["mutants"] != mutant_hashes:
            raise AuditError(f"a repair re-run uses the same sealed mutants as {repair_of}")
    record = {
        "audit_id": audit_id,
        "commit": sha,
        "files": _sealed_hashes(root),
        "mutants": mutant_hashes,
        "package": package,
        "python": _python_version(),
        "repair_of": repair_of,
        "reviewer": reviewer,
        "scope": list(scope),
        "timeout_seconds": timeout,
    }
    _write_json(audit / "freeze.json", record)
    return record


def verify(root: Path, sealed: dict) -> None:
    """Refuse unless the seal is committed once, and everything it names still matches."""
    _refuse_shallow(root, FreezeMismatch)
    if _python_version().rsplit(".", 1)[0] != sealed["python"].rsplit(".", 1)[0]:
        raise FreezeMismatch(f"sealed under Python {sealed['python']}, running {_python_version()}")
    rel = f"audits/{sealed['audit_id']}"
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--", rel).strip():
        raise FreezeMismatch(f"{rel} has uncommitted changes; commit the mutants and freeze.json first")
    history = _git(root, "log", "--format=%H", "--", f"{rel}/freeze.json").split()
    if len(history) != 1:
        raise FreezeMismatch(f"{rel}/freeze.json must be committed once and never edited")
    if _git(root, "log", "--format=%H", f"{history[0]}..HEAD", "--", f"{rel}/mutants").split():
        raise FreezeMismatch(f"{rel}/mutants changed after the freeze commit")
    _refuse_untracked_tests(root, FreezeMismatch)
    audit = _audit_dir(root, sealed["audit_id"])
    current = {
        "files": _sealed_hashes(root),
        "mutants": {f"mutants/{p.name}": _sha256(p) for p in sorted((audit / "mutants").glob("*.patch"))},
    }
    drifted = sorted(
        path
        for key in ("files", "mutants")
        for path in set(sealed[key]) | set(current[key])
        if sealed[key].get(path) != current[key].get(path)
    )
    if drifted:
        raise FreezeMismatch(f"changed since freeze: {', '.join(drifted)}")


def run(
    audit_id: str,
    *,
    root: Path = ROOT,
    after_each: Callable[[str], None] | None = None,
) -> dict:
    audit = _audit_dir(root, audit_id)
    if not (audit / "freeze.json").exists():
        raise AuditError(f"{audit_id} is not frozen")
    if (audit / "results.json").exists():
        raise AuditError(f"{audit_id} has already run; a re-run needs its own freeze")
    sealed = _read_json(audit / "freeze.json")
    verify(root, sealed)
    archive = subprocess.run(
        ["git", "archive", "--format=tar", sealed["commit"]], cwd=root, check=True, capture_output=True
    ).stdout
    mutants = _load_mutants(audit, tuple(sealed["scope"]))

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="mutation-audit-") as tmp:
        work = Path(tmp)
        copy = _extract(work, archive, sealed)
        try:
            baseline = _run_suite(work, copy, sealed, [])
        except AuditAborted as exc:
            raise AuditAborted(f"the unmutated suite: {exc}") from exc
    if baseline["outcome"] == "timeout":
        raise AuditAborted("the unmutated suite exceeded the timeout")
    if baseline["outcome"] == "harness-fault":
        raise AuditAborted(f"the unmutated suite did not finish: {baseline['detail']}")
    if baseline["outcome"] != "passed":
        raise AuditAborted(f"the unmutated suite fails: {', '.join(baseline['failed']) or baseline['detail']}")
    baseline_seconds = round(time.monotonic() - started, 2)

    rows = []
    for mutant_id, mutant in mutants.items():
        began = time.monotonic()
        with tempfile.TemporaryDirectory(prefix=f"mutation-audit-{mutant_id}-") as tmp:
            row = _run_mutant(Path(tmp), archive, sealed, mutant, audit / "mutants" / f"{mutant_id}.patch")
        row["duration_seconds"] = round(time.monotonic() - began, 2)
        rows.append(row)
        if after_each is not None:
            after_each(mutant_id)
        try:
            verify(root, sealed)
        except FreezeMismatch as exc:
            raise AuditAborted(f"aborted after {mutant_id}: {exc}") from exc

    results = {
        "audit_id": audit_id,
        "baseline_seconds": baseline_seconds,
        "commit": sealed["commit"],
        "mutants": rows,
        "python": _python_version(),
        "repair_of": sealed["repair_of"],
        "reviewer": sealed["reviewer"],
        "summary": summarise(rows),
        "timeout_seconds": sealed["timeout_seconds"],
    }
    _write_json(audit / "results.json", results)
    (audit / "results.md").write_text(render(results, _equivalents(audit)), encoding="utf-8")
    return results


def report(audit_id: str, *, root: Path = ROOT) -> str:
    audit = _audit_dir(root, audit_id)
    text = render(_read_json(audit / "results.json"), _equivalents(audit))
    (audit / "results.md").write_text(text, encoding="utf-8")
    return text


def summarise(rows: list[dict], equivalent: set[str] | frozenset[str] = frozenset()) -> dict:
    counts = {outcome: sum(r["outcome"] == outcome for r in rows) for outcome in OUTCOMES}
    # Invalid patches and harness faults are not measurements, so they stay out of the rate.
    valid = len(rows) - counts["invalid"] - counts["harness-fault"]
    summary = {
        "counts": counts,
        "valid": valid,
        "kill_rate_timeouts_as_killed": _rate(counts["killed"] + counts["timeout"], valid),
        "kill_rate_timeouts_not_killed": _rate(counts["killed"], valid),
    }
    if equivalent:
        summary["equivalent_excluded"] = sorted(equivalent)
        summary["kill_rate_excluding_equivalents"] = _rate(counts["killed"], valid - len(equivalent))
    return summary


def render(results: dict, equivalents: dict[str, dict]) -> str:
    rows = results["mutants"]
    by_id = {r["id"]: r for r in rows}
    signed = {m for m, e in equivalents.items() if str(e.get("signed_off_by", "")).strip()}
    for mutant_id in signed:
        if by_id.get(mutant_id, {}).get("outcome") not in ("survived-never-activated", "survived-oracle-masked"):
            raise AuditError(f"{mutant_id} is listed as equivalent but did not survive")
    summary = summarise(rows, signed)
    counts = summary["counts"]
    out = [f"# Mutation audit {results['audit_id']}", ""]
    if results.get("repair_of"):
        out += [f"Repair result on the same set as `{results['repair_of']}`. This is not a new estimate.", ""]
    out += [
        f"- PEP commit: `{results['commit']}`",
        f"- Python: {results['python']}",
        f"- Mutants specified by: {results['reviewer']}",
        f"- Timeout per run: {results['timeout_seconds']} s",
        "",
        "The kill rate is reported as measured. There is no pass threshold.",
        "",
        "## Kill rate",
        "",
        f"- Timeouts counted as killed: {summary['kill_rate_timeouts_as_killed']}",
        f"- Timeouts not counted as killed: {summary['kill_rate_timeouts_not_killed']}",
    ]
    if signed:
        out.append(
            f"- Excluding owner-signed equivalent mutants ({', '.join(sorted(signed))}): "
            f"{summary['kill_rate_excluding_equivalents']}"
        )
    out += [
        "",
        "Outcomes: " + ", ".join(f"{o} {counts[o]}" for o in OUTCOMES) + ". "
        f"Invalid patches ({counts['invalid']}) and harness faults ({counts['harness-fault']}) "
        "are outside the denominator.",
        "",
        "## Mutants",
        "",
        "| Mutant | File | Activation | Intent | Property attacked | Outcome | Killing tests | Seconds |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        activation = ", ".join(f"`{a}`" for a in r["activation"]) or "-"
        killers = "<br>".join(f"`{t}`" for t in r["killing_tests"]) or "-"
        out.append(
            f"| {r['id']} | `{r['file']}` | {activation} | {_cell(r['intent'])} | {_cell(r['property'])} "
            f"| {r['outcome']} | {killers} | {r['duration_seconds']} |"
        )
    reasons = [line for r in rows for line in _reason_lines(r)]
    if reasons:
        out += ["", "## Reasons", ""]
        out.extend(reasons)
    survivors = [r for r in rows if r["outcome"].startswith("survived")]
    out += ["", "## Survivors", ""]
    if survivors:
        out.append("Each survivor that touches a fail-closed path is filed as a defect.")
        out.append("")
        for r in survivors:
            line = f"- {r['id']} ({r['outcome']}): {r['property']}"
            if r["id"] in signed:
                note = equivalents[r["id"]]
                line += f" Equivalent, signed off by {note['signed_off_by']}: {note.get('argument', '')}"
            out.append(line)
    else:
        out.append("None.")
    return "\n".join(out) + "\n"


def _run_mutant(work: Path, archive: bytes, sealed: dict, mutant: Mutant, patch: Path) -> dict:
    row = {
        "id": mutant.mutant_id,
        "file": mutant.target,
        "activation": [],
        "intent": mutant.intent,
        "property": mutant.property,
        "killing_tests": [],
        "detail": "",
    }
    copy = _extract(work, archive, sealed)
    target = copy / mutant.target
    if not target.is_file():
        return {**row, "outcome": "invalid", "detail": "the target file is not in the frozen commit"}
    original = target.read_text(encoding="utf-8")
    files_before = _tree_digests(copy, mutant.target)
    applied = subprocess.run(
        ["git", "apply", str(patch)], cwd=copy, env=_git_apply_env(work), capture_output=True, text=True
    )
    if applied.returncode != 0:
        return {**row, "outcome": "invalid", "detail": applied.stderr.strip()}
    mutated = target.read_text(encoding="utf-8")
    if not _applied_where_stated(mutant, mutated):
        return {**row, "outcome": "invalid", "detail": "a hunk applied away from its stated lines"}
    if _tree_digests(copy, mutant.target) != files_before or _sealed_drift(copy, sealed):
        raise AuditAborted(f"{mutant.mutant_id} changed files other than {mutant.target}")
    try:
        targets = activation_targets(mutant, original, mutated, str(target))
    except SyntaxError as exc:
        return {**row, "outcome": "invalid", "detail": f"the mutated file does not compile: {exc.msg}"}
    except ValueError as exc:
        return {**row, "outcome": "invalid", "detail": str(exc)}
    row["activation"] = [describe_target(t) for t in targets]
    try:
        result = _run_suite(work, copy, sealed, targets, target=target)
    except AuditAborted as exc:
        raise AuditAborted(f"{mutant.mutant_id}: {exc}") from exc
    outcome = result["outcome"]
    if outcome == "passed":
        outcome = "survived-oracle-masked" if result["activated"] else "survived-never-activated"
    return {**row, "outcome": outcome, "killing_tests": result["failed"][:MAX_KILLING_TESTS], "detail": result["detail"]}


def _run_suite(
    work: Path, copy: Path, sealed: dict, targets: list[tuple[str, int, int | None]], *, target: Path | None = None
) -> dict:
    """Run pytest in ``copy``.

    Outcomes are passed, killed, harness-fault or timeout. A zero exit with no
    activation record aborts: there is nothing to score. A non-zero exit that
    recorded no failed test is harness-fault, not a kill.
    """
    out = work / "activation.json"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTEST_", "MUTATION_AUDIT_"))}
    env.update(
        PYTHONPATH=str(HARNESS_DIR),
        PYTHONDONTWRITEBYTECODE="1",
        MUTATION_AUDIT_OUT=str(out),
        MUTATION_AUDIT_ROOT=str(copy),
        MUTATION_AUDIT_PACKAGE=sealed["package"],
    )
    if target is not None:
        env.update(MUTATION_AUDIT_TARGET=str(target), MUTATION_AUDIT_TARGETS=json.dumps(targets))
    cmd = [
        sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "mutation_activation",
        f"--ignore={HARNESS_SELF_TEST}",
    ]
    proc = subprocess.Popen(
        cmd, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True
    )
    try:
        output, _ = proc.communicate(timeout=sealed["timeout_seconds"])
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        return {"outcome": "timeout", "activated": False, "failed": [], "detail": "timeout"}
    except BaseException:
        _kill_group(proc)
        raise
    _kill_group(proc)
    record = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    if record is not None and record["error"]:
        raise AuditAborted(record["error"])
    if record is None and proc.returncode == 0:
        raise AuditAborted(f"pytest exited 0 without an activation record:\n{_tail(output)}")
    failed = record["failed"] if record else []
    if failed:
        # Collection errors, package-import errors and failed setup, teardown or call
        # reports are recorded by the activation plugin and count as kills.
        return {"outcome": "killed", "activated": bool(record["activated"]), "failed": failed, "detail": ""}
    if proc.returncode != 0:
        # Not evidence the suite caught the mutant: an internal error, interrupt or crash.
        where = "" if record else " without a record"
        detail = f"pytest exited {proc.returncode}{where} and recorded no failed test:\n{_tail(output)}"
        return {
            "outcome": "harness-fault",
            "activated": bool(record and record["activated"]),
            "failed": [],
            "detail": detail,
        }
    return {"outcome": "passed", "activated": record["activated"], "failed": [], "detail": ""}


def _applied_where_stated(mutant: Mutant, mutated: str) -> bool:
    lines = mutated.splitlines()
    for start, expected in mutant.hunks:
        if expected and lines[start - 1 : start - 1 + len(expected)] != list(expected):
            return False
    return True


def _extract(work: Path, archive: bytes, sealed: dict) -> Path:
    copy = work / "tree"
    copy.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(copy, filter="data")
        else:
            tar.extractall(copy)
    drift = _sealed_drift(copy, sealed)
    if drift:
        raise AuditAborted(f"{', '.join(drift)} at {sealed['commit'][:7]} does not match the seal")
    return copy


def _sealed_drift(copy: Path, sealed: dict) -> list[str]:
    return [
        path
        for path, digest in sealed["files"].items()
        if not path.startswith("harness/") and (not (copy / path).is_file() or _sha256(copy / path) != digest)
    ]


def _tree_digests(copy: Path, target: str) -> dict[str, str]:
    """Every file in the copy except the target, by digest, so any other change shows."""
    return {
        rel: _sha256(path) if path.is_file() and not path.is_symlink() else f"link:{os.readlink(path)}"
        for path in copy.rglob("*")
        if (path.is_file() or path.is_symlink()) and (rel := str(path.relative_to(copy))) != target
    }


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the suite's process group, including children a test left running."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError, PermissionError):
        if proc.poll() is None:
            proc.kill()
    try:
        proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def _load_mutants(audit: Path, scope: tuple[str, ...]) -> dict[str, Mutant]:
    paths = sorted((audit / "mutants").glob("*.patch"))
    if not paths:
        raise AuditError(f"no mutants in {audit / 'mutants'}")
    mutants = {}
    for path in paths:
        if not _MUTANT_NAME.fullmatch(path.name):
            raise AuditError(f"mutant files are named Mnn.patch: {path.name}")
        mutant = parse_mutant(path.stem, path.read_text(encoding="utf-8"))
        if mutant.target not in scope:
            raise AuditError(f"{path.stem} mutates {mutant.target}, outside the scope {', '.join(scope)}")
        mutants[path.stem] = mutant
    return mutants


def _sealed_hashes(root: Path) -> dict[str, str]:
    tracked = _git(root, "ls-files", "-z", "--", "tests", "pyproject.toml").split("\0")
    hashes = {path: _sha256(root / path) for path in tracked if path and (root / path).is_file()}
    hashes.update({f"harness/{name}": _sha256(HARNESS_DIR / name) for name in HARNESS_FILES})
    return dict(sorted(hashes.items()))


def _refuse_untracked_tests(root: Path, error: type[AuditError] = AuditError) -> None:
    untracked = [p for p in _git(root, "ls-files", "-z", "--others", "--exclude-standard", "--", "tests").split("\0") if p]
    if untracked:
        raise error(f"untracked files under tests/ would be collected: {', '.join(untracked)}")


def _equivalents(audit: Path) -> dict[str, dict]:
    path = audit / "equivalent.json"
    return _read_json(path) if path.exists() else {}


def _audit_dir(root: Path, audit_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", audit_id):
        raise AuditError(f"bad audit id: {audit_id!r}")
    return root / "audits" / audit_id


def _rate(killed: int, total: int) -> str:
    return f"{killed} of {total} ({100 * killed / total:.0f}%)" if total > 0 else "n/a"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _tail(output: bytes, lines: int = 20) -> str:
    return "\n".join(output.decode("utf-8", "replace").splitlines()[-lines:])


def _git_apply_env(work: Path) -> dict[str, str]:
    """Environment for ``git apply`` that cannot see ambient git config.

    The ceiling stops git finding an enclosing repository. The empty config files
    and ``GIT_CONFIG_COUNT=0`` stop system, global and environment config (for
    example ``apply.whitespace``) from changing whether the patch applies.
    """
    empty = work / "empty-gitconfig"
    empty.write_text("")
    env = dict(os.environ)
    env.update(
        GIT_CEILING_DIRECTORIES=str(work),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=str(empty),
        GIT_CONFIG_SYSTEM=str(empty),
        GIT_CONFIG_COUNT="0",
    )
    return env


def _refuse_shallow(root: Path, error: type[AuditError] = AuditError) -> None:
    if _git(root, "rev-parse", "--is-shallow-repository").strip() == "true":
        raise error(
            "this repository is a shallow clone; freeze and verify need the full history, "
            "and a partial history can make that check pass or fail for the wrong reason"
        )


def _reason_lines(row: dict) -> list[str]:
    """Lines for ``results.md``. ``render`` used to drop ``detail``, so a harness fault looked like a bare outcome."""
    detail = str(row.get("detail") or "").strip()
    if not detail or detail == "timeout":
        return []
    lines = detail.splitlines()
    head = f"- {row['id']} ({row['outcome']}): {lines[0]}"
    if len(lines) == 1:
        return [head]
    return [head, "", *[f"      {line}" for line in lines[1:]], ""]


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _python_version() -> str:
    return ".".join(map(str, sys.version_info[:3]))


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_freeze = sub.add_parser("freeze", help="seal tests, harness and mutants before any run")
    p_freeze.add_argument("--reviewer", required=True, choices=REVIEWER_CLASSES)
    p_freeze.add_argument("--commit", default="HEAD")
    p_freeze.add_argument("--timeout", type=float, default=300.0)
    p_freeze.add_argument("--repair-of")
    p_freeze.add_argument("--scope", action="append", help="in-scope file; repeat for several (default: the gate files)")
    p_run = sub.add_parser("run", help="run the sealed suite once per mutant")
    p_report = sub.add_parser("report", help="rewrite results.md")
    for p in (p_freeze, p_run, p_report):
        p.add_argument("audit_id")
        p.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            record = freeze(
                args.audit_id,
                reviewer=args.reviewer,
                root=args.root,
                commit=args.commit,
                timeout=args.timeout,
                repair_of=args.repair_of,
                scope=tuple(args.scope) if args.scope else DEFAULT_SCOPE,
            )
            print(f"froze {args.audit_id} at {record['commit'][:7]}: {len(record['mutants'])} mutants")
            print(f"commit audits/{args.audit_id}/ before running it")
        elif args.command == "run":
            summary = run(args.audit_id, root=args.root)["summary"]
            print(f"{args.audit_id}: {summary['kill_rate_timeouts_not_killed']} killed; see results.md")
        else:
            report(args.audit_id, root=args.root)
    except AuditError as exc:
        print(f"mutation audit: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
