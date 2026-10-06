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
DEFAULT_SCOPE = ("pep/approval.py", "pep/gate.py", "pep/evaluate.py")
REVIEWER_CLASSES = ("person", "other-family", "same-family")
OUTCOMES = ("killed", "survived-never-activated", "survived-oracle-masked", "timeout", "invalid")
MAX_KILLING_TESTS = 5
_MUTANT_NAME = re.compile(r"M\d{2}\.patch")
_HUNK = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class AuditError(Exception):
    """The audit cannot proceed. Nothing is recorded."""


class FreezeMismatch(AuditError):
    """The working tree no longer matches what was sealed."""


class AuditAborted(AuditError):
    """The run stopped before every mutant had an outcome."""


@dataclass(frozen=True)
class Mutant:
    """One sealed mutant. ``blocks`` holds each change block as (its first
    line in the mutated file, the ``+`` line numbers in it)."""

    mutant_id: str
    intent: str
    property: str
    target: str
    blocks: tuple[tuple[int, tuple[int, ...]], ...]


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
    olds = [ln[4:].strip() for ln in lines[i:] if ln.startswith("--- ")]
    news = [ln[4:].strip() for ln in lines[i:] if ln.startswith("+++ ")]
    if len(olds) != 1 or len(news) != 1:
        raise AuditError(f"{mutant_id}: a mutant changes exactly one file")
    old, new = (_strip_prefix(p) for p in (olds[0], news[0]))
    if old != new or new == "/dev/null":
        raise AuditError(f"{mutant_id}: a mutant edits an existing file in place")
    blocks: list[tuple[int, tuple[int, ...]]] = []
    new_line = 0
    in_block = False
    for line in lines[i:]:
        hunk = _HUNK.match(line)
        if hunk:
            new_line, in_block = int(hunk.group(1)), False
            continue
        if not new_line or line.startswith(("--- ", "+++ ", "\\")):
            continue
        tag = line[:1]
        if tag in ("-", "+"):
            if not in_block:
                blocks.append((new_line, ()))
                in_block = True
            if tag == "+":
                start, plus = blocks[-1]
                blocks[-1] = (start, (*plus, new_line))
                new_line += 1
        else:
            in_block = False
            new_line += 1
    if not blocks:
        raise AuditError(f"{mutant_id}: the patch changes nothing")
    return Mutant(mutant_id, meta["Intent"], meta["Property"], new, tuple(blocks))


def _strip_prefix(path: str) -> str:
    path = path.split("\t", 1)[0]
    return path[2:] if path.startswith(("a/", "b/")) else path


def executable_lines(source: str, filename: str) -> set[int]:
    pending = [compile(source, filename, "exec")]
    lines: set[int] = set()
    while pending:
        code = pending.pop()
        lines.update(ln for _, _, ln in code.co_lines() if ln is not None)
        pending.extend(c for c in code.co_consts if hasattr(c, "co_lines"))
    lines.discard(0)
    return lines


def activation_lines(mutant: Mutant, executable: set[int]) -> list[int]:
    """The ``+`` lines that can raise a line event; for a block with none, the next one that can."""
    ordered = sorted(executable)
    chosen: set[int] = set()
    for start, plus in mutant.blocks:
        hits = [ln for ln in plus if ln in executable]
        if not hits:
            after = [ln for ln in ordered if ln >= start]
            hits = after[:1] or ordered[-1:]
        chosen.update(hits)
    return sorted(chosen)


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
    """Refuse unless tests, pyproject, harness, mutants and Python all match the seal."""
    if _python_version().rsplit(".", 1)[0] != sealed["python"].rsplit(".", 1)[0]:
        raise FreezeMismatch(f"sealed under Python {sealed['python']}, running {_python_version()}")
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
        baseline = _run_suite(Path(tmp), archive, sealed, None, [])
    if baseline["outcome"] == "timeout":
        raise AuditAborted("the unmutated suite exceeded the timeout")
    if baseline["outcome"] != "passed":
        raise AuditAborted(f"the unmutated suite fails: {', '.join(baseline['failed']) or 'see pytest output'}")
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
    valid = len(rows) - counts["invalid"]
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
        "Outcomes: " + ", ".join(f"{o} {counts[o]}" for o in OUTCOMES) + f". Invalid patches ({counts['invalid']}) "
        "are outside the denominator.",
        "",
        "## Mutants",
        "",
        "| Mutant | File and lines | Intent | Property attacked | Outcome | Killing tests | Seconds |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        where = f"`{r['file']}`:{','.join(map(str, r['lines']))}" if r["lines"] else f"`{r['file']}`"
        killers = "<br>".join(f"`{t}`" for t in r["killing_tests"]) or "-"
        out.append(
            f"| {r['id']} | {where} | {_cell(r['intent'])} | {_cell(r['property'])} | {r['outcome']} "
            f"| {killers} | {r['duration_seconds']} |"
        )
    survivors = [r for r in rows if r["outcome"].startswith("survived")]
    out += ["", "## Survivors", ""]
    if survivors:
        out.append("Each survivor that touches a fail-closed path is filed as a defect.")
        out.append("")
        for r in survivors:
            note = equivalents.get(r["id"]) if r["id"] in signed else None
            line = f"- {r['id']} ({r['outcome']}): {r['property']}"
            if note:
                line += f" Equivalent, signed off by {note['signed_off_by']}: {note.get('argument', '')}"
            out.append(line)
    else:
        out.append("None.")
    return "\n".join(out) + "\n"


def _run_mutant(work: Path, archive: bytes, sealed: dict, mutant: Mutant, patch: Path) -> dict:
    row = {
        "id": mutant.mutant_id,
        "file": mutant.target,
        "lines": [],
        "intent": mutant.intent,
        "property": mutant.property,
        "killing_tests": [],
        "detail": "",
    }
    copy = _extract(work, archive, sealed)
    # The ceiling stops git from finding an enclosing repository, so paths stay relative to the copy.
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(work)}
    applied = subprocess.run(["git", "apply", str(patch)], cwd=copy, env=env, capture_output=True, text=True)
    if applied.returncode != 0:
        return {**row, "outcome": "invalid", "detail": applied.stderr.strip()}
    target = copy / mutant.target
    try:
        lines = activation_lines(mutant, executable_lines(target.read_text(encoding="utf-8"), str(target)))
    except SyntaxError as exc:
        return {**row, "outcome": "invalid", "detail": f"mutated file does not compile: {exc.msg}"}
    result = _run_suite(work, archive, sealed, mutant.target, lines, copy=copy)
    outcome = result["outcome"]
    if outcome == "passed":
        outcome = "survived-oracle-masked" if result["activated"] else "survived-never-activated"
    return {**row, "lines": lines, "outcome": outcome, "killing_tests": result["failed"][:MAX_KILLING_TESTS]}


def _run_suite(
    work: Path, archive: bytes, sealed: dict, target: str | None, lines: list[int], *, copy: Path | None = None
) -> dict:
    copy = copy or _extract(work, archive, sealed)
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
        env.update(MUTATION_AUDIT_TARGET=str(copy / target), MUTATION_AUDIT_LINES=",".join(map(str, lines)))
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "mutation_activation"]
    proc = subprocess.Popen(
        cmd, cwd=copy, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True
    )
    try:
        output, _ = proc.communicate(timeout=sealed["timeout_seconds"])
    except subprocess.TimeoutExpired:
        _kill(proc)
        return {"outcome": "timeout", "activated": False, "failed": []}
    if not out.exists():
        raise AuditAborted(f"pytest exited {proc.returncode} without a record:\n{_tail(output)}")
    record = json.loads(out.read_text(encoding="utf-8"))
    if record["error"]:
        raise AuditAborted(record["error"])
    if proc.returncode == 0:
        outcome = "passed"
    elif proc.returncode in (1, 2):
        outcome = "killed"
    else:
        raise AuditAborted(f"pytest exited {proc.returncode}:\n{_tail(output)}")
    return {"outcome": outcome, "activated": record["activated"], "failed": record["failed"]}


def _extract(work: Path, archive: bytes, sealed: dict) -> Path:
    copy = work / "tree"
    copy.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(copy, filter="data")
        else:
            tar.extractall(copy)
    for path, digest in sealed["files"].items():
        if path.startswith("harness/"):
            continue
        if not (copy / path).is_file() or _sha256(copy / path) != digest:
            raise AuditAborted(f"{path} at {sealed['commit'][:7]} does not match the seal")
    return copy


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError):
        proc.kill()
    proc.communicate()


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
    p_freeze.add_argument("audit_id")
    p_freeze.add_argument("--reviewer", required=True, choices=REVIEWER_CLASSES)
    p_freeze.add_argument("--commit", default="HEAD")
    p_freeze.add_argument("--timeout", type=float, default=300.0)
    p_freeze.add_argument("--repair-of")
    for name in ("run", "report"):
        sub.add_parser(name).add_argument("audit_id")
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            record = freeze(
                args.audit_id,
                reviewer=args.reviewer,
                commit=args.commit,
                timeout=args.timeout,
                repair_of=args.repair_of,
            )
            print(f"froze {args.audit_id} at {record['commit'][:7]}: {len(record['mutants'])} mutants")
        elif args.command == "run":
            summary = run(args.audit_id)["summary"]
            print(f"{args.audit_id}: {summary['kill_rate_timeouts_not_killed']} killed; see results.md")
        else:
            report(args.audit_id)
    except AuditError as exc:
        print(f"mutation audit: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
