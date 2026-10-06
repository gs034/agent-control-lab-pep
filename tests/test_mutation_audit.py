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
import tempfile
import uuid
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
    y = x * 2
    return y


def describe(x):
    return f"value {x}"


def background(x):
    return x - 1


def spin(n):
    total = 0
    for i in range(n):
        total += i
    return total


def record(x):
    note = x
    return note
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


def test_record_runs():
    calc.record(1)
'''

# Named like the harness self-test, which mutant runs leave out; it would fail every run otherwise.
SELF_TEST = "def test_harness_only():\n    assert False\n"

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
    (root / "toy" / "__init__.py").write_text("from toy import calc\n")
    (root / "toy" / "calc.py").write_text(CALC)
    (root / "tests" / "test_calc.py").write_text(tests)
    (root / "tests" / "test_mutation_audit.py").write_text(SELF_TEST)
    (root / "pyproject.toml").write_text(PYPROJECT)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "toy")
    return root


def _diff(old: str, new: str, path: str = "toy/calc.py") -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}"))


def _write_mutant(root: Path, audit_id: str, mutant_id: str, patch: str) -> None:
    mutants = root / "audits" / audit_id / "mutants"
    mutants.mkdir(parents=True, exist_ok=True)
    (mutants / f"{mutant_id}.patch").write_text(f"Intent: control {mutant_id}\nProperty: toy property {mutant_id}\n" + patch)


def _mutant(root: Path, audit_id: str, mutant_id: str, old: str, new: str, *, path: str = "toy/calc.py") -> None:
    _write_mutant(root, audit_id, mutant_id, _diff(old, new, path))


def _freeze(root: Path, audit_id: str, *, commit_seal: bool = True, **kwargs) -> dict:
    kwargs.setdefault("timeout", 4.0)
    kwargs.setdefault("package", "toy")
    record = ma.freeze(audit_id, reviewer="person", root=root, scope=SCOPE, **kwargs)
    if commit_seal:
        _git(root, "add", f"audits/{audit_id}")
        _git(root, "commit", "-q", "-m", f"freeze {audit_id}")
    return record


def _status(root: Path) -> set[str]:
    return set(_git(root, "status", "--porcelain", "--untracked-files=all").splitlines())


def test_controls_get_one_outcome_each(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A1", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _mutant(root, "A1", "M02", CALC, CALC.replace("y = x * 2", "y = x * 3"))
    _mutant(root, "A1", "M03", CALC, CALC.replace('f"value {x}"', 'f"VALUE {x}"'))
    _mutant(root, "A1", "M04", CALC, CALC.replace("return x - 1", "return x + 1"))
    _mutant(root, "A1", "M05", CALC, CALC.replace("    for i in range(n):\n", "    while True:\n        pass\n    for i in range(n):\n"))
    _mutant(root, "A1", "M06", CALC, CALC.replace("return a + b", "return a * b"))
    stale = CALC.replace("def unused(x):", "def unused(z):")
    _mutant(root, "A1", "M07", stale, stale.replace("y = x * 2", "y = x * 4"))
    _mutant(root, "A1", "M08", CALC, CALC.replace('    if x < 0:\n        raise ValueError("negative")\n', ""))
    _mutant(root, "A1", "M09", CALC, CALC + "\n_BROKEN = undefined_name\n")
    _mutant(root, "A1", "M10", CALC, CALC.replace("    y = x * 2\n    return y\n", "    y = x * 2\n"))
    _mutant(root, "A1", "M11", CALC, CALC.replace("def unused(x):", "def unused(x=0):"))
    pad = "# pad\n" * 4
    _mutant(root, "A1", "M12", pad + CALC, pad + CALC.replace("y = x * 2", "y = x * 5"))
    _mutant(root, "A1", "M13", CALC, CALC.replace("    note = x\n    return note\n", "    note = x\n"))
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
        "M09": "killed",
        "M10": "survived-never-activated",
        "M11": "survived-oracle-masked",
        "M12": "invalid",
        "M13": "survived-oracle-masked",
    }
    assert rows["M01"]["killing_tests"] == ["tests/test_calc.py::test_add"]
    assert rows["M08"]["killing_tests"] == ["tests/test_calc.py::test_negative_refused"]
    assert rows["M08"]["activation"] == ["checked_sqrt:6"]
    assert rows["M09"]["killing_tests"][0] == "tests/test_calc.py"
    assert rows["M10"]["activation"] == ["unused (entry)"]
    assert rows["M11"]["activation"] == ["11"]
    assert rows["M12"]["detail"] == "a hunk applied away from its stated lines"
    assert rows["M13"]["activation"] == ["record (entry)"]
    assert rows["M05"]["duration_seconds"] < 4.0 + 3.0
    summary = results["summary"]
    assert summary["valid"] == 11
    assert summary["kill_rate_timeouts_as_killed"] == "5 of 11 (45%)"
    assert summary["kill_rate_timeouts_not_killed"] == "4 of 11 (36%)"

    assert _git(root, "diff", "--name-only") == ""
    assert _status(root) - before == {"?? audits/A1/results.json", "?? audits/A1/results.md"}
    markdown = (root / "audits" / "A1" / "results.md").read_text()
    assert "There is no pass threshold." in markdown
    assert "Mutants specified by: person" in markdown
    assert "a hunk applied away from its stated lines" in markdown
    with pytest.raises(ma.AuditError, match="already run"):
        ma.run("A1", root=root)
    assert ma.main(["report", "A1", "--root", str(root)]) == 0


@pytest.mark.parametrize(
    "edit",
    [
        lambda root: (root / "tests" / "test_calc.py").write_text(TESTS + "\n"),
        lambda root: (root / "tests" / "test_extra.py").write_text("def test_x():\n    pass\n"),
        lambda root: (root / "audits" / "A2" / "mutants" / "M01.patch").write_text("Intent: x\n"),
        lambda root: (root / "audits" / "A2" / "mutants" / "M02.patch").write_text("Intent: x\n"),
    ],
    ids=["test-edited", "untracked-test", "mutant-edited", "mutant-added"],
)
def test_run_refuses_after_post_freeze_edit(tmp_path, edit):
    root = _toy(tmp_path)
    _mutant(root, "A2", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A2")
    edit(root)
    with pytest.raises(ma.FreezeMismatch):
        ma.run("A2", root=root)
    assert not (root / "audits" / "A2" / "results.json").exists()


def test_run_refuses_a_seal_that_is_not_committed_once(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A6", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A6", commit_seal=False)
    with pytest.raises(ma.FreezeMismatch, match="uncommitted"):
        ma.run("A6", root=root)

    _git(root, "add", "audits/A6")
    _git(root, "commit", "-q", "-m", "freeze")
    sealed = root / "audits" / "A6" / "freeze.json"
    sealed.write_text(sealed.read_text().replace('"timeout_seconds": 4.0', '"timeout_seconds": 999.0'))
    _git(root, "commit", "-q", "-am", "edit the seal")
    with pytest.raises(ma.FreezeMismatch, match="committed once and never edited"):
        ma.run("A6", root=root)


def test_run_refuses_mutants_changed_after_the_freeze_commit(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A7", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A7")
    _mutant(root, "A7", "M01", CALC, CALC.replace("return a + b", "return b - a"))
    _git(root, "commit", "-q", "-am", "swap a mutant")
    with pytest.raises(ma.FreezeMismatch, match="mutants changed after the freeze commit"):
        ma.run("A7", root=root)


def test_run_refuses_another_python_minor_version(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A8", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    sealed = _freeze(root, "A8")
    with pytest.raises(ma.FreezeMismatch, match="sealed under Python 2.7.0"):
        ma.verify(root, {**sealed, "python": "2.7.0"})


def test_copy_that_differs_from_the_seal_aborts(tmp_path):
    root = _toy(tmp_path)
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=root, check=True, capture_output=True).stdout
    (root / "tests" / "test_calc.py").write_text(TESTS + "\n")
    _git(root, "commit", "-q", "-am", "edit tests")
    _mutant(root, "A9", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    sealed = _freeze(root, "A9")
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ma.AuditAborted, match="tests/test_calc.py .* does not match the seal"):
        ma._extract(work, archive, sealed)


@pytest.mark.parametrize(
    "extra",
    [
        lambda: RENAME_TESTS,
        lambda: _diff("from toy import calc\n", "from toy import calc\nX = 1\n", "toy/__init__.py"),
    ],
    ids=["rename", "content"],
)
def test_patch_that_touches_another_file_aborts_after_apply(tmp_path, extra):
    root = _toy(tmp_path)
    good = _diff(CALC, CALC.replace("return a + b", "return a - b"))
    _write_mutant(root, "A10", "M01", good)
    sealed = _freeze(root, "A10")
    mutant = ma.parse_mutant("M01", (root / "audits" / "A10" / "mutants" / "M01.patch").read_text())
    smuggled = tmp_path / "smuggled.patch"
    smuggled.write_text("diff --git a/toy/calc.py b/toy/calc.py\n" + good + extra())
    archive = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=root, check=True, capture_output=True).stdout
    work = tmp_path / "work"
    work.mkdir()
    with pytest.raises(ma.AuditAborted, match="changed files other than toy/calc.py"):
        ma._run_mutant(work, archive, sealed, mutant, smuggled)


def test_an_enclosing_repository_cannot_change_how_a_patch_applies(tmp_path, monkeypatch):
    root = _toy(tmp_path)
    _git(root, "config", "apply.whitespace", "error")
    _mutant(root, "A11", "M01", CALC, CALC.replace("return a + b", "return a - b  "))
    _freeze(root, "A11")
    scratch = root / "toy" / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    assert ma.run("A11", root=root)["mutants"][0]["outcome"] == "killed"


def test_namespace_package_aborts_the_run(tmp_path):
    root = _toy(tmp_path)
    _git(root, "rm", "-q", "toy/__init__.py")
    _git(root, "commit", "-q", "-m", "namespace package")
    _mutant(root, "A12", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A12")
    with pytest.raises(ma.AuditAborted, match="has no __file__"):
        ma.run("A12", root=root)


@pytest.mark.skipif(not Path("/proc/self/cmdline").exists(), reason="needs /proc")
def test_children_a_test_leaves_running_are_killed(tmp_path):
    marker = f"mutation-audit-leftover-{uuid.uuid4().hex}"
    spawn = (
        "\n\ndef test_leaves_a_child():\n"
        "    import subprocess, sys\n"
        f"    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)', {marker!r}],\n"
        "                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    )
    root = _toy(tmp_path, tests=TESTS + spawn)
    _mutant(root, "A13", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A13")
    ma.run("A13", root=root)
    left = [p for p in Path("/proc").glob("[0-9]*") if marker.encode() in _cmdline(p)]
    assert left == []


def _cmdline(proc: Path) -> bytes:
    try:
        return (proc / "cmdline").read_bytes()
    except OSError:
        return b""


def test_edit_during_run_aborts_at_next_hash_check(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A3", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _mutant(root, "A3", "M02", CALC, CALC.replace("y = x * 2", "y = x * 3"))
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
    _mutant(root, "A4", "M01", CALC, CALC.replace("y = x * 2", "y = x * 3"))
    _freeze(root, "A4")
    seen = []
    with pytest.raises(ma.AuditAborted, match="unmutated suite fails: tests/test_calc.py::test_add"):
        ma.run("A4", root=root, after_each=seen.append)
    assert seen == []
    assert not (root / "audits" / "A4" / "results.json").exists()


def test_package_imported_outside_the_copy_aborts(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "A5", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "A5", package="json")
    with pytest.raises(ma.AuditAborted, match="outside the mutant copy"):
        ma.run("A5", root=root)
    assert not (root / "audits" / "A5" / "results.json").exists()
    assert ma.main(["run", "A5", "--root", str(root)]) == 1


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

    _mutant(root, "B4", "M01", CALC, CALC.replace("y = x * 2", "y = x * 3"))
    with pytest.raises(ma.AuditError, match="same sealed mutants as B1"):
        _freeze(root, "B4", repair_of="B1")
    _mutant(root, "B5", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    assert _freeze(root, "B5", repair_of="B1")["repair_of"] == "B1"

    (root / "tests" / "test_calc.py").write_text(TESTS + "\n")
    _mutant(root, "B6", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    with pytest.raises(ma.AuditError, match="tests differ"):
        _freeze(root, "B6")


RENAME_TESTS = """\
diff --git a/tests/test_calc.py b/tests/disabled.txt
similarity index 100%
rename from tests/test_calc.py
rename to tests/disabled.txt
"""


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        (_diff("a = 1\n", "a = 2\n", "toy/one.py") + _diff("b = 1\n", "b = 2\n", "toy/two.py"), "exactly one file"),
        ("diff --git a/toy/calc.py b/toy/calc.py\n" + _diff(CALC, CALC.replace("a + b", "a - b")) + RENAME_TESTS,
         "in place, nothing else"),
        ("diff --git a/toy/calc.py b/toy/calc.py\nold mode 100644\nnew mode 100755\n", "in place, nothing else"),
        (_diff(CALC, CALC.replace("a + b", "a - b")).replace("a/toy", "toy").replace("b/toy", "toy"), "a/ and b/"),
        (_diff(CALC, CALC.replace("a + b", "a - b")).replace("@@ -1,5 +1,5 @@", "@@ -1,9 +1,9 @@"), "shorter than its header"),
    ],
    ids=["two-files", "rename-alongside", "mode-change", "no-prefix", "truncated"],
)
def test_parse_refuses_anything_but_one_in_place_edit(patch, message):
    with pytest.raises(ma.AuditError, match=message):
        ma.parse_mutant("M01", "Intent: i\nProperty: p\n" + patch)


def test_parse_handles_git_format_patches():
    diff = _diff(CALC, CALC.replace("return a + b", "return a - b"))
    git_style = "From 0 Mon Sep 17 00:00:00 2001\nSubject: x\n---\ndiff --git a/toy/calc.py b/toy/calc.py\nindex 1..2 100644\n"
    mutant = ma.parse_mutant("M01", "Intent: i\nProperty: p\n" + git_style + diff + "-- \n2.43.0\n")
    assert mutant.blocks == (ma.Block(old_start=2, new_start=2, minus=(2,), plus=(2,)),)

    no_newline = _diff("x = 1\n", "x = 2", "toy/calc.py")
    assert "\\ No newline at end of file" not in no_newline
    marked = no_newline.replace("+x = 2", "+x = 2\n\\ No newline at end of file")
    assert ma.parse_mutant("M02", "Intent: i\nProperty: p\n" + marked).blocks[0].plus == (1,)


def _targets(source: str, mutated: str) -> list[str]:
    mutant = ma.parse_mutant("M01", "Intent: i\nProperty: p\n" + _diff(source, mutated))
    return [ma.describe_target(t) for t in ma.activation_targets(mutant, source, mutated, "f.py")]


def test_activation_targets():
    source = "def f(x):\n    # guard\n    if x:\n        return 1\n    return 2\n\n\ndef g(x):\n    y = x\n    return y\n\n\ndef h():\n    pass\n"
    assert _targets(source, source.replace("    if x:\n        return 1\n", "")) == ["f:3"]
    assert _targets(source, source.replace("# guard", "# no guard")) == ["f:3"]
    assert _targets(source, source.replace("return 2", "return 3")) == ["5"]
    assert _targets(source, source.replace("    return y\n", "")) == ["g (entry)"]
    assert _targets(source, source.replace("def h():", "def h(z=1):")) == ["13"]
    assert _targets(source, source.replace("def h():\n", "def h():\n    global Y\n")) == ["h:15"]


def test_activation_targets_follow_earlier_hunks_that_shift_lines():
    source = "X = 1\n" + "\n" * 8 + "def g(x):\n    y = x\n    return y\n\n\ndef h():\n    pass\n"
    mutated = source.replace("X = 1\n", "").replace("    return y\n", "")
    assert set(_targets(source, mutated)) == {"<module>:9", "g (entry)"}


def _results(**overrides) -> dict:
    rows = [
        {"id": "M01", "file": "f.py", "activation": ["1"], "intent": "i", "property": "p", "outcome": "killed",
         "killing_tests": ["t::a"], "duration_seconds": 1.0},
        {"id": "M02", "file": "f.py", "activation": ["2"], "intent": "i", "property": "p | q",
         "outcome": "survived-oracle-masked", "killing_tests": [], "duration_seconds": 1.0},
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


def _exit_zero_without_record(real_popen, *, skip_first: int = 0):
    """Stand in for pytest: exit 0 and write no activation record."""
    seen = {"n": 0}

    def popen(cmd, **kwargs):
        if isinstance(cmd, list) and "pytest" in cmd:
            seen["n"] += 1
            if seen["n"] > skip_first:
                return real_popen(
                    ["true"],
                    stdout=kwargs.get("stdout"),
                    stderr=kwargs.get("stderr"),
                    start_new_session=kwargs.get("start_new_session", False),
                )
        return real_popen(cmd, **kwargs)

    return popen


def test_nonzero_pytest_without_a_failed_test_is_not_killed(tmp_path):
    """An internal error, interrupt or crash with no failed test is not a kill."""
    tests = TESTS.replace(
        "def test_add():\n    assert calc.add(2, 3) == 5\n",
        "def test_add():\n"
        "    if calc.add(2, 3) == 999:\n"
        "        pytest.exit('stop the session', returncode=3)\n"
        "    assert calc.add(2, 3) == 5\n",
    )
    root = _toy(tmp_path, tests=tests)
    _mutant(
        root, "H1", "M01", CALC,
        CALC.replace("def add(a, b):\n    return a + b\n", "def add(a, b):\n    import os\n    os._exit(1)\n"),
    )
    _mutant(root, "H1", "M02", CALC, CALC.replace("return a + b", "return 999"))
    _mutant(root, "H1", "M03", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "H1")

    results = ma.run("H1", root=root)

    rows = {r["id"]: r for r in results["mutants"]}
    assert rows["M01"]["outcome"] == "harness-fault"
    assert rows["M02"]["outcome"] == "harness-fault"
    assert rows["M01"]["killing_tests"] == []
    assert rows["M02"]["killing_tests"] == []
    assert "recorded no failed test" in rows["M01"]["detail"]
    assert "without a record" in rows["M01"]["detail"]
    assert "recorded no failed test" in rows["M02"]["detail"]
    assert "without a record" not in rows["M02"]["detail"]
    assert rows["M03"]["outcome"] == "killed"
    assert rows["M03"]["killing_tests"] == ["tests/test_calc.py::test_add"]
    summary = results["summary"]
    assert summary["counts"]["killed"] == 1
    assert summary["counts"]["harness-fault"] == 2
    assert summary["valid"] == 1
    assert summary["kill_rate_timeouts_not_killed"] == "1 of 1 (100%)"
    assert summary["kill_rate_timeouts_as_killed"] == "1 of 1 (100%)"
    markdown = (root / "audits" / "H1" / "results.md").read_text()
    assert "pytest exited" in markdown
    assert "recorded no failed test" in markdown
    assert "harness-fault" in markdown


def test_a_failed_setup_is_still_killed(tmp_path):
    tests = TESTS + (
        "\n\n@pytest.fixture\n"
        "def armed():\n"
        "    if calc.describe(1) == 'boom':\n"
        "        raise RuntimeError('setup failed')\n"
        "\n\n"
        "def test_armed(armed):\n"
        "    pass\n"
    )
    root = _toy(tmp_path, tests=tests)
    _mutant(root, "H4", "M01", CALC, CALC.replace('f"value {x}"', '"boom"'))
    _freeze(root, "H4")
    row = ma.run("H4", root=root)["mutants"][0]
    assert row["outcome"] == "killed"
    assert row["killing_tests"] == ["tests/test_calc.py::test_armed"]


def test_success_without_an_activation_record_aborts(tmp_path, monkeypatch, capsys):
    root = _toy(tmp_path)
    _mutant(root, "H2", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "H2")
    real = subprocess.Popen
    monkeypatch.setattr(subprocess, "Popen", _exit_zero_without_record(real))
    with pytest.raises(ma.AuditAborted, match="the unmutated suite: pytest exited 0 without an activation record"):
        ma.run("H2", root=root)
    assert not (root / "audits" / "H2" / "results.json").exists()

    assert ma.main(["run", "H2", "--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "without an activation record" in err
    assert err.startswith("mutation audit:")


def test_mutant_success_without_an_activation_record_aborts(tmp_path, monkeypatch):
    root = _toy(tmp_path)
    _mutant(root, "H3", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "H3")
    real = subprocess.Popen
    monkeypatch.setattr(subprocess, "Popen", _exit_zero_without_record(real, skip_first=1))
    with pytest.raises(ma.AuditAborted, match="M01: pytest exited 0 without an activation record"):
        ma.run("H3", root=root)
    assert not (root / "audits" / "H3" / "results.json").exists()


def test_system_and_global_git_config_cannot_change_how_a_patch_applies(tmp_path, monkeypatch):
    root = _toy(tmp_path)
    _mutant(root, "G1", "M01", CALC, CALC.replace("return a + b", "return a - b  "))
    _freeze(root, "G1")
    config = tmp_path / "gitconfig"
    config.write_text("[apply]\n\twhitespace = error\n")
    xdg = tmp_path / "xdg" / "git"
    xdg.mkdir(parents=True)
    (xdg / "config").write_text("[apply]\n\twhitespace = error\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "0")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "apply.whitespace")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "error")
    assert ma.run("G1", root=root)["mutants"][0]["outcome"] == "killed"


def test_shallow_clone_is_refused(tmp_path, capsys):
    root = _toy(tmp_path)
    _mutant(root, "S1", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    _freeze(root, "S1")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "--depth", "1", f"file://{root}", str(shallow)],
        check=True,
        capture_output=True,
        text=True,
    )
    history = _git(shallow, "log", "--format=%H", "--", "audits/S1/freeze.json").split()
    assert history, "the shallow clone should still see the freeze commit"
    with pytest.raises(ma.AuditError, match="shallow clone"):
        ma.freeze("S2", reviewer="person", root=shallow, scope=SCOPE, package="toy")
    sealed = ma._read_json(shallow / "audits" / "S1" / "freeze.json")
    with pytest.raises(ma.FreezeMismatch, match="shallow clone"):
        ma.verify(shallow, sealed)
    with pytest.raises(ma.FreezeMismatch, match="shallow clone"):
        ma.run("S1", root=shallow)
    assert not (shallow / "audits" / "S1" / "results.json").exists()
    assert ma.main(["freeze", "S2", "--reviewer", "person", "--root", str(shallow)]) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "shallow clone" in err


def test_cli_freeze_takes_the_scope(tmp_path):
    root = _toy(tmp_path)
    _mutant(root, "C1", "M01", CALC, CALC.replace("return a + b", "return a - b"))
    assert ma.main(["freeze", "C1", "--reviewer", "person", "--root", str(root)]) == 1
    assert not (root / "audits" / "C1" / "freeze.json").exists()
    assert ma.main(["freeze", "C1", "--reviewer", "person", "--scope", "toy/calc.py", "--root", str(root)]) == 0
    assert ma._read_json(root / "audits" / "C1" / "freeze.json")["scope"] == ["toy/calc.py"]
