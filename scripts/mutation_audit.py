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
import math
import os
import re
import secrets
import signal
import stat
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
# Everything committed under audits/<id>/ is input from a pull request. These
# are the names the harness writes there, and the files it reads.
_OUTPUTS = ("freeze.json", "results.json", "results.md")
_INPUTS = ("equivalent.json",)
_AUDIT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_PYTHON = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# C0, DEL, C1 and the Unicode line and paragraph separators.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
MAX_SEAL_TEXT = 256
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
    _check_audit_tree(audit)
    if os.path.lexists(audit / "freeze.json"):
        raise AuditError(f"{audit_id} is already frozen")
    sha = _git(root, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    drift = _git(root, "diff", "--name-only", sha, "--", "tests", "pyproject.toml").split()
    if drift:
        raise AuditError(f"tests differ from {sha[:7]}: {', '.join(drift)}")
    _refuse_untracked_tests(root)
    mutants = _load_mutants(audit, scope)
    mutant_hashes = {f"mutants/{m}.patch": _sha256_of(_read_regular(audit / "mutants" / f"{m}.patch")) for m in mutants}
    if repair_of is not None:
        original_dir = _audit_dir(root, repair_of)
        _check_audit_tree(original_dir)
        original = _read_json(original_dir / "freeze.json")
        _check_seal(original, AuditError)
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
    # The seal run reads back must pass the same checks, so freeze never writes one run would refuse.
    _check_seal(record, AuditError)
    _write_json(audit, "freeze.json", record)
    return record


_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Every git subprocess is bounded. A git that hangs (a remote helper, a
# credential prompt, an offline host) fails the audit closed with a clear error.
_GIT_TIMEOUT_SECONDS = 60.0


def _git_timed_out(exc: subprocess.TimeoutExpired) -> AuditError:
    argv = exc.cmd if isinstance(exc.cmd, (list, tuple)) else [str(exc.cmd)]
    verb = next((part for part in argv[1:] if not str(part).startswith("-")), "git")
    return AuditError(
        f"git {verb} did not finish within {_GIT_TIMEOUT_SECONDS:g} s; "
        "the audit stops here because git state could not be read (offline or hung git)"
    )


def _sealed_commit(root: Path, sealed: dict) -> str:
    """The seal is input. Its commit must be a full object id that names a local commit."""
    commit = sealed.get("commit")
    if not isinstance(commit, str) or not _OBJECT_ID.fullmatch(commit):
        raise FreezeMismatch("the seal's commit is not a full hexadecimal object id")
    try:
        resolved = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{commit}^{{commit}}").strip()
    except subprocess.CalledProcessError as exc:
        raise FreezeMismatch(f"the seal's commit {commit[:12]} is not a commit in this repository") from exc
    if resolved != commit:
        raise FreezeMismatch(f"the seal's commit {commit[:12]} does not resolve to itself")
    return commit


def _require_reviewed_commit(root: Path, commit: str, freeze_commit: str, audit_id: str) -> None:
    """The archived tree must be the tree a reviewer sees, outside this audit's own folder.

    A seal is input, so naming some local commit is not enough: a branch can
    add code, revert it, and seal the commit that still has it, or add code,
    freeze, and remove it again after the freeze. The sealed commit must be an
    ancestor of the commit that added ``freeze.json``, and nothing outside
    ``audits/<audit_id>/`` may differ between it and the freeze commit or
    between it and HEAD. That folder is left out of the archive, and
    ``_refuse_unsafe_tree`` limits what the sealed commit may hold there, so
    what runs is what the freeze commit and the branch tip both show.
    """
    try:
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", "--end-of-options", commit, freeze_commit],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise _git_timed_out(exc) from exc
    if ancestor.returncode != 0:
        raise FreezeMismatch(f"the seal's commit {commit[:12]} is not an ancestor of the freeze commit")
    own = f"audits/{audit_id}"
    for other, label in ((freeze_commit, "the freeze commit"), ("HEAD", "HEAD")):
        changed = _git(
            root, "diff", "--name-only", "-z", "--no-renames", "--end-of-options", commit, other,
            "--", ".", f":(exclude){own}",
        ).split("\0")
        changed = [name for name in changed if name]
        if changed:
            raise FreezeMismatch(
                f"the seal's commit {commit[:12]} differs from {label} outside {own}/: {', '.join(changed)}"
            )


# Files pytest or Python load before any test runs. Only tests/ may carry a conftest.py.
_STARTUP_NAMES = ("sitecustomize.py", "usercustomize.py")


def _refuse_startup_hooks(root: Path, commit: str) -> None:
    """Refuse a sealed tree with a conftest.py outside tests/ or a Python startup hook."""
    names = [n for n in _git(root, "ls-tree", "-r", "-z", "--name-only", "--end-of-options", commit).split("\0") if n]
    bad = [
        name
        for name in names
        if (name.rsplit("/", 1)[-1] == "conftest.py" and not name.startswith("tests/"))
        or name.rsplit("/", 1)[-1] in _STARTUP_NAMES
        or name.endswith(".pth")
    ]
    if bad:
        raise FreezeMismatch(f"the sealed tree carries files that run before the tests: {', '.join(bad)}")


# The audit folders are input from a pull request and are never part of what runs.
_AUDITS = "audits"
_REGULAR_MODES = ("100644", "100755")
# Run git so that no attributes file outside the repository can change what it writes.
_ATTRIBUTE_NEUTRAL = {
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "core.attributesFile",
    "GIT_CONFIG_VALUE_0": os.devnull,
}


def _ls_tree(root: Path, treeish: str, *paths: str) -> list[tuple[str, str, str, str]]:
    """Every non-tree entry under ``treeish`` as (mode, type, object id, path from the top)."""
    out = _git(root, "ls-tree", "-r", "-z", "--full-tree", "--end-of-options", treeish, *paths)
    entries = []
    for record in out.split("\0"):
        if record:
            meta, _, path = record.partition("\t")
            mode, kind, oid = meta.split(" ")
            entries.append((mode, kind, oid, path))
    return entries


def _in_audits(path: str) -> bool:
    return path == _AUDITS or path.startswith(f"{_AUDITS}/")


def _refuse_unsafe_tree(root: Path, commit: str, freeze_commit: str, audit_id: str) -> None:
    """Refuse a sealed tree whose archive could differ from the blobs a reviewer reads.

    Every entry must be a regular file: no symlink, which could point into an
    audit folder or out of its directory, and no submodule. No
    ``.gitattributes`` file may appear anywhere, because ``git archive``
    honours ``export-subst`` and ``export-ignore`` from the tree it writes.
    The audit's own folder may hold only the mutants, unchanged at the freeze
    commit, since the diff check does not cover that folder.
    """
    own = f"{_AUDITS}/{audit_id}/"
    frozen = {(m, o, p) for m, _, o, p in _ls_tree(root, freeze_commit, f"{own}mutants")}
    bad = []
    for mode, _, oid, path in _ls_tree(root, commit):
        if path.rsplit("/", 1)[-1] == ".gitattributes":
            bad.append(f"{path} (attributes change what git archive writes)")
        elif mode not in _REGULAR_MODES:
            bad.append(f"{path} (mode {mode}, not a regular file)")
        elif path.startswith(own) and not (
            path.startswith(f"{own}mutants/")
            and _MUTANT_NAME.fullmatch(path[len(own) + len("mutants/"):])
            and (mode, oid, path) in frozen
        ):
            bad.append(f"{path} (inside {own} at the sealed commit)")
    if bad:
        raise FreezeMismatch(f"the sealed tree at {commit[:12]} is refused: {', '.join(bad)}")


def _archived_tree(root: Path, commit: str) -> dict[str, tuple[str, str]]:
    """What the archive must hold: every path outside audits/, with its mode and blob id."""
    return {path: (mode, oid) for mode, _, oid, path in _ls_tree(root, commit) if not _in_audits(path)}


def _archive(root: Path, commit: str) -> bytes:
    """The sealed commit as a tar, without audits/ and with no attributes from outside the repository.

    Pathspec settings from the environment are dropped so the exclusion is
    read as magic. The extracted copy is still checked blob by blob, because
    the repository's own ``info/attributes`` can rewrite what this writes.
    """
    try:
        return subprocess.run(
            ["git", "archive", "--format=tar", "--end-of-options", commit, ".", f":(exclude){_AUDITS}"],
            cwd=root,
            env={**{k: v for k, v in os.environ.items() if not k.endswith("_PATHSPECS")}, **_ATTRIBUTE_NEUTRAL},
            check=True,
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).stdout
    except subprocess.TimeoutExpired as exc:
        raise _git_timed_out(exc) from exc


def _blob_id(data: bytes, oid_length: int) -> str:
    algorithm = hashlib.sha1 if oid_length == 40 else hashlib.sha256
    return algorithm(b"blob %d\0" % len(data) + data).hexdigest()


def _materialised_drift(copy: Path, tree: dict[str, tuple[str, str]]) -> list[str]:
    """Every path where the extracted copy is not exactly the sealed blobs: extra, missing or different."""
    found: dict[str, Path] = {}
    drift = []
    for dirpath, dirnames, filenames in os.walk(copy):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(copy).as_posix()
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                found[rel] = path
            elif not stat.S_ISDIR(info.st_mode):
                drift.append(f"{rel} (not a regular file)")
    for rel in sorted(set(found) | set(tree)):
        if rel not in tree:
            drift.append(f"{rel} (not in the sealed tree)")
        elif rel not in found:
            drift.append(f"{rel} (missing)")
        else:
            mode, oid = tree[rel]
            path = found[rel]
            if _blob_id(path.read_bytes(), len(oid)) != oid:
                drift.append(f"{rel} (content differs from blob {oid[:12]})")
            elif bool(path.stat().st_mode & stat.S_IXUSR) != (mode == "100755"):
                drift.append(f"{rel} (mode differs from {mode})")
    return drift


def verify(root: Path, sealed: dict, audit_id: str | None = None) -> None:
    """Refuse unless the seal is committed once, and everything it names still matches.

    Every path comes from ``audit_id``, the directory being run. A seal that
    names another audit is refused, so its checks cannot point elsewhere.
    """
    audit_id = sealed.get("audit_id") if audit_id is None else audit_id
    if not isinstance(audit_id, str) or sealed.get("audit_id") != audit_id:
        raise FreezeMismatch(f"the seal names audit {sealed.get('audit_id')!r}, not {audit_id!r}")
    _check_seal(sealed)
    _refuse_shallow(root, FreezeMismatch)
    _sealed_commit(root, sealed)
    if _python_version().rsplit(".", 1)[0] != sealed["python"].rsplit(".", 1)[0]:
        raise FreezeMismatch(f"sealed under Python {sealed['python']}, running {_python_version()}")
    rel = f"audits/{audit_id}"
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--", rel).strip():
        raise FreezeMismatch(f"{rel} has uncommitted changes; commit the mutants and freeze.json first")
    history = _git(root, "log", "--format=%H", "--", f"{rel}/freeze.json").split()
    if len(history) != 1:
        raise FreezeMismatch(f"{rel}/freeze.json must be committed once and never edited")
    if _git(root, "log", "--format=%H", f"{history[0]}..HEAD", "--", f"{rel}/mutants").split():
        raise FreezeMismatch(f"{rel}/mutants changed after the freeze commit")
    _require_reviewed_commit(root, sealed["commit"], history[0], audit_id)
    _refuse_unsafe_tree(root, sealed["commit"], history[0], audit_id)
    _refuse_untracked_tests(root, FreezeMismatch)
    audit = _audit_dir(root, audit_id)
    _check_audit_tree(audit, FreezeMismatch)
    current = {
        "files": _sealed_hashes(root),
        "mutants": {
            f"mutants/{p.name}": _sha256_of(_read_regular(p, FreezeMismatch))
            for p in sorted((audit / "mutants").glob("*.patch"))
        },
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
    _check_audit_tree(audit)
    if not os.path.lexists(audit / "freeze.json"):
        raise AuditError(f"{audit_id} is not frozen")
    if os.path.lexists(audit / "results.json"):
        raise AuditError(f"{audit_id} has already run; a re-run needs its own freeze")
    sealed = _read_json(audit / "freeze.json")
    verify(root, sealed, audit_id)
    commit = _sealed_commit(root, sealed)
    _refuse_startup_hooks(root, commit)
    tree = _archived_tree(root, commit)
    archive = _archive(root, commit)
    mutants = _load_mutants(audit, tuple(sealed["scope"]))

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="mutation-audit-") as tmp:
        work = Path(tmp)
        copy = _extract(work, archive, sealed, tree)
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
            row = _run_mutant(Path(tmp), archive, tree, sealed, mutant, audit / "mutants" / f"{mutant_id}.patch")
        row["duration_seconds"] = round(time.monotonic() - began, 2)
        rows.append(row)
        if after_each is not None:
            after_each(mutant_id)
        try:
            verify(root, sealed, audit_id)
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
    text = render(results, _equivalents(audit))
    _write_json(audit, "results.json", results)
    _write_in_audit(audit, "results.md", text)
    return results


def report(audit_id: str, *, root: Path = ROOT) -> str:
    audit = _audit_dir(root, audit_id)
    _check_audit_tree(audit)
    text = render(_read_json(audit / "results.json"), _equivalents(audit))
    _write_in_audit(audit, "results.md", text)
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
    _check_rendered(results, equivalents)
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


def _run_mutant(
    work: Path, archive: bytes, tree: dict[str, tuple[str, str]], sealed: dict, mutant: Mutant, patch: Path
) -> dict:
    row = {
        "id": mutant.mutant_id,
        "file": mutant.target,
        "activation": [],
        "intent": mutant.intent,
        "property": mutant.property,
        "killing_tests": [],
        "detail": "",
    }
    copy = _extract(work, archive, sealed, tree)
    target = copy / mutant.target
    if not target.is_file():
        return {**row, "outcome": "invalid", "detail": "the target file is not in the frozen commit"}
    original = target.read_text(encoding="utf-8")
    files_before = _tree_digests(copy, mutant.target)
    try:
        applied = subprocess.run(
            ["git", "apply", str(patch)],
            cwd=copy,
            env=_git_apply_env(work),
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise _git_timed_out(exc) from exc
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
        # -P keeps the archive root off sys.path at interpreter start, so a
        # root sitecustomize.py or usercustomize.py is never imported.
        sys.executable, "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "mutation_activation",
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


def _extract(work: Path, archive: bytes, sealed: dict, tree: dict[str, tuple[str, str]]) -> Path:
    """Extract the archive and check it is exactly ``tree``, the sealed blobs outside audits/."""
    copy = work / "tree"
    copy.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(copy, filter="data")
        else:
            tar.extractall(copy)
    materialised = _materialised_drift(copy, tree)
    if materialised:
        raise AuditAborted(
            f"the archive of {sealed['commit'][:7]} is not the sealed tree: {', '.join(materialised)}"
        )
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
        mutant = parse_mutant(path.stem, _read_regular(path).decode("utf-8"))
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
    return _read_json(path) if os.path.lexists(path) else {}


def _audit_dir(root: Path, audit_id: str) -> Path:
    if not _AUDIT_ID.fullmatch(audit_id):
        raise AuditError(f"bad audit id: {audit_id!r}")
    return root / "audits" / audit_id


def _check_audit_tree(audit: Path, error: type[AuditError] = AuditError) -> None:
    """Refuse ``audits/<id>/`` unless it, and every entry the harness reads or writes there, is plain.

    A pull request can commit a symlink, and a local checkout can hold a FIFO
    or a hard link. ``audits/``, the audit directory and ``mutants/`` must be
    real directories. Each output and input name, when present, and each file
    in ``mutants/`` must be a regular file with one link. A missing directory
    is not refused here; the caller reports what is missing.
    """
    rel = f"audits/{audit.name}"
    mutants = audit / "mutants"
    for directory, label in ((audit.parent, "audits"), (audit, rel), (mutants, f"{rel}/mutants")):
        try:
            info = os.lstat(directory)
        except FileNotFoundError:
            break
        if not stat.S_ISDIR(info.st_mode):
            raise error(f"{label} is not a directory (a symlink or special file is refused)")
    for name in (*_OUTPUTS, *_INPUTS):
        _check_entry(audit / name, f"{rel}/{name}", error)
    try:
        entries = sorted(os.listdir(mutants))
    except (FileNotFoundError, NotADirectoryError):
        entries = []
    for entry in entries:
        _check_entry(mutants / entry, f"{rel}/mutants/{entry}", error)


def _check_entry(path: Path, label: str, error: type[AuditError]) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode):
        raise error(f"{label} is not a regular file (a symlink or special file is refused)")
    if info.st_nlink > 1:
        raise error(f"{label} has {info.st_nlink} hard links; the harness reads and replaces only single-link files")


def _seal_text(value: object, limit: int = MAX_SEAL_TEXT) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit and not _CONTROL.search(value)


def _check_seal(sealed: object, error: type[AuditError] = FreezeMismatch) -> None:
    """A committed seal is input. Refuse any field the harness uses or renders that freeze would not write.

    ``commit`` is checked by ``_sealed_commit``. Messages name the field, not
    its value, so a crafted value is not echoed.
    """
    if not isinstance(sealed, dict):
        raise error("the seal is not a JSON object")
    if sealed.get("reviewer") not in REVIEWER_CLASSES:
        raise error(f"the seal's reviewer must be one of {', '.join(REVIEWER_CLASSES)}")
    if not isinstance(sealed.get("audit_id"), str) or not _AUDIT_ID.fullmatch(sealed["audit_id"]):
        raise error("the seal's audit_id is not an audit id")
    repair_of = sealed.get("repair_of")
    if repair_of is not None and (not isinstance(repair_of, str) or not _AUDIT_ID.fullmatch(repair_of)):
        raise error("the seal's repair_of is not an audit id")
    if not isinstance(sealed.get("python"), str) or not _PYTHON.fullmatch(sealed["python"]):
        raise error("the seal's python is not a version like 3.12.1")
    if not isinstance(sealed.get("package"), str) or not _PACKAGE.fullmatch(sealed["package"]):
        raise error("the seal's package is not a dotted Python name")
    timeout = sealed.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise error("the seal's timeout_seconds is not a positive number")
    scope = sealed.get("scope")
    if not isinstance(scope, list) or not scope or not all(_seal_text(path) for path in scope):
        raise error(f"the seal's scope must list single-line paths of at most {MAX_SEAL_TEXT} characters")
    for key in ("files", "mutants"):
        table = sealed.get(key)
        if not isinstance(table, dict) or not all(
            _seal_text(path) and isinstance(digest, str) and _DIGEST.fullmatch(digest) for path, digest in table.items()
        ):
            raise error(f"the seal's {key} must map single-line paths to sha256 digests")


def _check_rendered(results: dict, equivalents: dict[str, dict]) -> None:
    """``results.json`` and ``equivalent.json`` can be committed too. Refuse a header or note that is not one line."""
    if results.get("reviewer") not in REVIEWER_CLASSES:
        raise AuditError(f"the results' reviewer must be one of {', '.join(REVIEWER_CLASSES)}")
    for key in ("audit_id", "commit", "python"):
        if not _seal_text(results.get(key)):
            raise AuditError(f"the results' {key} is not a single line of at most {MAX_SEAL_TEXT} characters")
    if results.get("repair_of") is not None and not _seal_text(results["repair_of"]):
        raise AuditError(f"the results' repair_of is not a single line of at most {MAX_SEAL_TEXT} characters")
    timeout = results.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise AuditError("the results' timeout_seconds is not a number")
    for row in results.get("mutants", []):
        for key in ("id", "file", "intent", "property", "outcome"):
            if not isinstance(row.get(key), str) or _CONTROL.search(row[key]):
                raise AuditError(f"a result row's {key} is not a single line")
    for mutant_id, note in equivalents.items():
        if not isinstance(note, dict):
            raise AuditError(f"equivalent.json: {mutant_id!r} is not an object")
        for key in ("signed_off_by", "argument"):
            value = note.get(key, "")
            if not isinstance(value, str) or _CONTROL.search(value):
                raise AuditError(f"equivalent.json: {mutant_id!r} {key} is not a single line")


def _read_regular(path: Path, error: type[AuditError] = AuditError) -> bytes:
    """Read a committed file without following a link, and only if it is a regular file.

    ``O_NONBLOCK`` keeps a FIFO from blocking the open; the ``fstat`` then refuses it.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise error(f"cannot read {path.name} as a regular file: {exc.strerror}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise error(f"{path.name} is not a regular file")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_in_audit(audit: Path, name: str, text: str) -> None:
    """Replace ``audit/name`` through descriptors, so a link at either path cannot redirect the write.

    The audit directory is opened with ``O_NOFOLLOW`` relative to an
    ``audits/`` opened the same way. A fresh temporary name is created with
    ``O_EXCL | O_NOFOLLOW`` in that directory, written and synced, then
    renamed over ``name``. A rename replaces a link; it never writes through it.
    """
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        parent = os.open(audit.parent, dir_flags)
        try:
            dir_fd = os.open(audit.name, dir_flags, dir_fd=parent)
        finally:
            os.close(parent)
    except OSError as exc:
        raise AuditError(f"audits/{audit.name} is not a directory the harness can write: {exc.strerror}") from exc
    try:
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_nlink > 1):
            raise AuditError(f"audits/{audit.name}/{name} is not a single-link regular file; refusing to replace it")
        tmp = f".{name}.{secrets.token_hex(8)}.tmp"
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o666,
            dir_fd=dir_fd,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(text.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            raise
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


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
    try:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, text=True, timeout=_GIT_TIMEOUT_SECONDS
        ).stdout
    except subprocess.TimeoutExpired as exc:
        raise _git_timed_out(exc) from exc


def _sha256(path: Path) -> str:
    return _sha256_of(path.read_bytes())


def _sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _python_version() -> str:
    return ".".join(map(str, sys.version_info[:3]))


def _read_json(path: Path) -> dict:
    return json.loads(_read_regular(path).decode("utf-8"))


def _write_json(audit: Path, name: str, data: dict) -> None:
    _write_in_audit(audit, name, json.dumps(data, indent=2, sort_keys=True) + "\n")


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
