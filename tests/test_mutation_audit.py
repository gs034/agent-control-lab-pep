# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0006 phase 1: the mutation-audit harness, checked against a toy package.

These tests check the harness, not the PEP.
"""

from __future__ import annotations

import difflib
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("mutation_audit", ROOT / "scripts" / "mutation_audit.py")
ma = importlib.util.module_from_spec(_spec)
sys.modules["mutation_audit"] = ma
_spec.loader.exec_module(ma)

CALC = '''\
def add(a, b):
    return a + b


def checked_sqrt(x):
    if x < 0:
        raise ValueError("negative")
    return x ** 0.5


def unused(x):
    return x * 2


def describe(x):
    return f"value {x}"


def background(x):
    return x - 1


def spin(n):
    total = 0
    for i in range(n):
        total += i
    return total
'''

TESTS = '''\
import threading

import pytest

from toy import calc


def test_add():
    assert calc.add(2, 3) == 5


def test_negative_refused():
    with pytest.raises(ValueError):
        calc.checked_sqrt(-1)


def test_describe_runs():
    calc.describe(1)


def test_background_in_thread():
    worker = threading.Thread(target=calc.background, args=(1,))
    worker.start()
    worker.join()


def test_spin():
    assert calc.spin(4) == 6
'''

PYPROJECT = '''\
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
'''

SCOPE = ("toy/calc.py",)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=lab", "-c", "user.email=lab@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _toy(tmp_path: Path, tests: str = TESTS) -> Path:
    root = tmp_path / "toy-repo"
    (root / "toy").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "toy" / "__init__.py").write_text("")
    (root / "toy" / "calc.py").write_text(CALC)
    (root / "tests" / "test_calc.py").write_text(tests)
    (root / "pyproject.toml").write_text(PYPROJECT)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "toy")
    return root


def _diff(old: str, new: str, path: str = "toy/calc.py") -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}"))


def _mutant(root: Path, audit_id: str, mutant_id: str, old: str, new: str, *, path: str = "toy/calc.py") -> None:
    mutants = root / "audits" / audit_id / "mutants"
    mutants.mkdir(parents=True, exist_ok=True)
    header = f"Intent: control {mutant_id}\nProperty: toy property {mutant_id}\n"
    (mutants / f"{mutant_id}.patch").write_text(header + _diff(old, new, path))


def _freeze(root: Path, audit_id: str, **kwargs) -> dict:
    kwargs.setdefault("timeout", 4.0)
    return ma.freeze(audit_id, reviewer="person", root=root, scope=SCOPE, package="toy", **kwargs)


def _status(root: Path) -> set[str]:
    return set(_git(root, "status", "--porcelain", "--untracked-files=all").splitlines())


def test_controls_get_one_outcome_each(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A1", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _mutant(root, "A1", "M02", CALC, CALC.replace("return x * 2", "return x * 3"))
    _mutant(root, "A1", "M03", CALC, CALC.replace('f"value {x}"', 'f"VALUE {x}"'))
    _mutant(root, "A1", "M04", CALC, CALC.replace("return x - 1", "return x + 1"))
    _mutant(root, "A1", "M05", CALC, CALC.replace("    for i in range(n):\n", "    while True:\n        pass\n    for i in range(n):\n"))
    _mutant(root, "A1", "M06", CALC, CALC.replace("return a + b", "return a * b"))
    stale = CALC.replace("def unused(x):", "def unused(y):")
    _mutant(root, "A1", "M07", stale, stale.replace("return x * 2", "return x * 4"))
    _mutant(root, "A1", "M08", CALC, CALC.replace('    if x < 0:\n        raise ValueError("negative")\n', ""))
    _freeze(root, "A1")
    before = _status(root)

    results = ma.run("A1", root=root)

    rows = {r["id"]: r for r in results["mutants"]}
    assert {m: r["outcome"] for m, r in rows.items()} == {
        "M01": "killed",
        "M02": "survived-never-activated",
        "M03": "survived-oracle-masked",
        "M04": "survived-oracle-masked",
        "M05": "timeout",
        "M06": "killed",
        "M07": "invalid",
        "M08": "killed",
    }
    assert rows["M01"]["killing_tests"] == ["tests/test_calc.py::test_add"]
    assert rows["M08"]["killing_tests"] == ["tests/test_calc.py::test_negative_refused"]
    assert rows["M08"]["lines"] == [6]
    assert rows["M05"]["duration_seconds"] < 4.0 + 3.0
    summary = results["summary"]
    assert summary["valid"] == 7
    assert summary["kill_rate_timeouts_as_killed"] == "4 of 7 (57%)"
    assert summary["kill_rate_timeouts_not_killed"] == "3 of 7 (43%)"

    assert _git(root, "diff", "--name-only") == ""
    assert _status(root) - before == {"?? audits/A1/results.json", "?? audits/A1/results.md"}
    markdown = (root / "audits" / "A1" / "results.md").read_text()
    assert "There is no pass threshold." in markdown
    assert "Mutants specified by: person" in markdown
    with pytest.raises(ma.AuditError, match="already run"):
        ma.run("A1", root=root)


@pytest.mark.parametrize(
    "edit",
    [
        lambda root: (root / "tests" / "test_calc.py").write_text(TESTS + "\n"),
        lambda root: (root / "tests" / "test_extra.py").write_text("def test_x():\n    pass\n"),
        lambda root: (root / "audits" / "A2" / "mutants" / "M01.patch").write_text("Intent: x\n"),
    ],
    ids=["test-edited", "untracked-test", "mutant-edited"],
)
def test_run_refuses_after_post_freeze_edit(tmp_path, edit):
    root = _toy(tmp_path)
    _mutant(root, "A2", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A2")
    edit(root)
    with pytest.raises(ma.FreezeMismatch):
        ma.run("A2", root=root)
    assert not (root / "audits" / "A2" / "results.json").exists()


def test_copy_that_differs_from_the_seal_aborts(tmp_path):
    root = _toy(tmp_path)
    first = _git(root, "rev-parse", "HEAD").strip()
    (root / "tests" / "test_calc.py").write_text(TESTS + "\n")
    _git(root, "commit", "-q", "-am", "edit tests")
    _mutant(root, "A6", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A6")
    sealed = root / "audits" / "A6" / "freeze.json"
    sealed.write_text(sealed.read_text().replace(_git(root, "rev-parse", "HEAD").strip(), first))
    with pytest.raises(ma.AuditAborted, match="does not match the seal"):
        ma.run("A6", root=root)


def test_edit_during_run_aborts_at_next_hash_check(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A3", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _mutant(root, "A3", "M02", CALC, CALC.replace("return x * 2", "return x * 3"))
    _freeze(root, "A3")
    seen = []

    def tamper(mutant_id):
        seen.append(mutant_id)
        (root / "tests" / "test_calc.py").write_text(TESTS.replace("== 5", "== 5  # edited"))

    with pytest.raises(ma.AuditAborted, match="aborted after M01"):
        ma.run("A3", root=root, after_each=tamper)
    assert seen == ["M01"]
    assert not (root / "audits" / "A3" / "results.json").exists()


def test_failing_baseline_aborts_before_any_mutant(tmp_path):
    root = _toy(tmp_path, tests=TESTS.replace("== 5", "== 6"))
    _mutant(root, "A4", "M01", CALC, CALC.replace("return x * 2", "return x * 3"))
    _freeze(root, "A4")
    seen = []
    with pytest.raises(ma.AuditAborted, match="unmutated suite fails: tests/test_calc.py::test_add"):
        ma.run("A4", root=root, after_each=seen.append)
    assert seen == []
    assert not (root / "audits" / "A4" / "results.json").exists()


def test_package_imported_outside_the_copy_aborts(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A5", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    ma.freeze("A5", reviewer="person", root=root, scope=SCOPE, package="json", timeout=4.0)
    with pytest.raises(ma.AuditAborted, match="outside the mutant copy"):
        ma.run("A5", root=root)
    assert not (root / "audits" / "A5" / "results.json").exists()


def test_freeze_refusals(tmp_path):
    root = _toy(tmp_path)
    with pytest.raises(ma.AuditError, match="no mutants"):
        _freeze(root, "B1")
    _mutant(root, "B1", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    with pytest.raises(ma.AuditError, match="reviewer"):
        ma.freeze("B1", reviewer="robot", root=root, scope=SCOPE, package="toy")
    _freeze(root, "B1")
    with pytest.raises(ma.AuditError, match="already frozen"):
        _freeze(root, "B1")

    _mutant(root, "B2", "M01", "x = 1\n", "x = 2\n", path="toy/other.py")
    with pytest.raises(ma.AuditError, match="outside the scope"):
        _freeze(root, "B2")

    bare = root / "audits" / "B3" / "mutants"
    bare.mkdir(parents=True)
    (bare / "M01.patch").write_text(_diff(CALC, CALC.replace("a + b", "a - b")))
    with pytest.raises(ma.AuditError, match="missing Intent"):
        _freeze(root, "B3")

    _mutant(root, "B4", "M01", CALC, CALC.replace("return x * 2", "return x * 3"))
    with pytest.raises(ma.AuditError, match="same sealed mutants as B1"):
        _freeze(root, "B4", repair_of="B1")
    _mutant(root, "B5", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    assert _freeze(root, "B5", repair_of="B1")["repair_of"] == "B1"

    (root / "tests" / "test_calc.py").write_text(TESTS + "\n")
    _mutant(root, "B6", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    with pytest.raises(ma.AuditError, match="tests differ"):
        _freeze(root, "B6")


def test_parse_rejects_a_patch_that_is_not_first_order():
    two_files = _diff("a = 1\n", "a = 2\n", "toy/one.py") + _diff("b = 1\n", "b = 2\n", "toy/two.py")
    with pytest.raises(ma.AuditError, match="exactly one file"):
        ma.parse_mutant("M01", "Intent: i\nProperty: p\n" + two_files)


def test_activation_lines_skip_lines_that_cannot_run():
    source = "def f(x):\n    # guard\n    if x:\n        return 1\n    return 2\n"
    executable = ma.executable_lines(source, "f.py")
    deleted = ma.parse_mutant("M01", "Intent: i\nProperty: p\n" + _diff(source, source.replace("    if x:\n        return 1\n", "")))
    assert ma.activation_lines(deleted, ma.executable_lines(source.replace("    if x:\n        return 1\n", ""), "f.py")) == [3]
    commented = ma.parse_mutant("M02", "Intent: i\nProperty: p\n" + _diff(source, source.replace("# guard", "# no guard")))
    assert ma.activation_lines(commented, executable) == [3]
    changed = ma.parse_mutant("M03", "Intent: i\nProperty: p\n" + _diff(source, source.replace("return 2", "return 3")))
    assert ma.activation_lines(changed, executable) == [5]


def _results(**overrides) -> dict:
    rows = [
        {"id": "M01", "file": "f.py", "lines": [1], "intent": "i", "property": "p", "outcome": "killed",
         "killing_tests": ["t::a"], "duration_seconds": 1.0},
        {"id": "M02", "file": "f.py", "lines": [2], "intent": "i", "property": "p | q", "outcome": "survived-oracle-masked",
         "killing_tests": [], "duration_seconds": 1.0},
    ]
    results = {"audit_id": "R1", "commit": "c" * 40, "python": "3.12.0", "reviewer": "person",
               "timeout_seconds": 300.0, "repair_of": None, "mutants": rows}
    return {**results, **overrides}


def test_report_adds_a_rate_only_for_owner_signed_equivalents():
    raw = ma.render(_results(), {})
    assert "Timeouts not counted as killed: 1 of 2 (50%)" in raw
    assert "Excluding owner-signed" not in raw
    assert "p \\| q" in raw
    assert ma.render(_results(), {"M02": {"argument": "same behaviour", "signed_off_by": ""}}) == raw

    signed = ma.render(_results(), {"M02": {"argument": "same behaviour", "signed_off_by": "owner"}})
    assert "Timeouts not counted as killed: 1 of 2 (50%)" in signed
    assert "Excluding owner-signed equivalent mutants (M02): 1 of 1 (100%)" in signed
    assert "signed off by owner: same behaviour" in signed

    with pytest.raises(ma.AuditError, match="did not survive"):
        ma.render(_results(), {"M01": {"signed_off_by": "owner"}})


def test_repair_results_are_labelled_as_the_same_set():
    text = ma.render(_results(repair_of="A1"), {})
    assert "Repair result on the same set as `A1`. This is not a new estimate." in text
