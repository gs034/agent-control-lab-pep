# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""pytest plugin for ``mutation_audit.py`` (ADR-0006): did any test run the mutation?

Inert unless ``MUTATION_AUDIT_OUT`` is set. The harness sets:

- ``MUTATION_AUDIT_OUT``: where to write the JSON record;
- ``MUTATION_AUDIT_ROOT``: the mutant copy the suite must import from;
- ``MUTATION_AUDIT_PACKAGE``: the package whose import location is checked;
- ``MUTATION_AUDIT_TARGET`` and ``MUTATION_AUDIT_TARGETS``: the mutated file
  and its activation targets, ``[qualname, first line, line or null]``, where
  qualname ``*`` matches any code and a null line means entry into the code
  (absent for the baseline run).

Tracing covers the main thread and threads started after configure. Code
that runs before configure and code in child processes are not traced.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest

_MODULE = ("<module>", 0)


class _Recorder:
    def __init__(self, target: str | None, targets: list[list]) -> None:
        self.target = os.path.realpath(target) if target else None
        self.any_code = frozenset(line for name, _, line in targets if name == "*")
        self.by_code: dict[tuple[str, int], tuple[frozenset[int], bool]] = {}
        for name, first, line in targets:
            if name == "*":
                continue
            lines, entry = self.by_code.get((name, first), (frozenset(), False))
            self.by_code[(name, first)] = (lines | {line}, entry) if line is not None else (lines, True)
        self.activated = False
        self.failed: list[str] = []
        self.error: str | None = None
        self.package_file: str | None = None
        self._is_target: dict[str, bool] = {}

    def trace(self, frame, event, arg):
        if self.activated:
            return None
        code = frame.f_code
        hit = self._is_target.get(code.co_filename)
        if hit is None:
            hit = self._is_target[code.co_filename] = os.path.realpath(code.co_filename) == self.target
        if not hit:
            return None
        key = _MODULE if code.co_name == "<module>" else (code.co_qualname, code.co_firstlineno)
        lines, entry = self.by_code.get(key, (frozenset(), False))
        if entry:
            self.activated = True
            return None
        lines |= self.any_code
        if not lines:
            return None

        def trace_lines(frame, event, arg):
            if self.activated:
                return None
            if event == "line" and frame.f_lineno in lines:
                self.activated = True
                return None
            return trace_lines

        return trace_lines

    def record_failure(self, nodeid: str) -> None:
        if nodeid not in self.failed:
            self.failed.append(nodeid)


_recorder: _Recorder | None = None


def pytest_configure(config: pytest.Config) -> None:
    global _recorder
    if not os.environ.get("MUTATION_AUDIT_OUT"):
        return
    _recorder = _Recorder(
        os.environ.get("MUTATION_AUDIT_TARGET"),
        json.loads(os.environ.get("MUTATION_AUDIT_TARGETS", "[]")),
    )
    if _recorder.target:
        threading.settrace(_recorder.trace)
        sys.settrace(_recorder.trace)


def pytest_collectreport(report: pytest.CollectReport) -> None:
    if _recorder is not None and report.failed:
        _recorder.record_failure(report.nodeid or "<collection>")


def pytest_collection_finish(session: pytest.Session) -> None:
    if _recorder is None:
        return
    root = Path(os.environ["MUTATION_AUDIT_ROOT"]).resolve()
    package = os.environ["MUTATION_AUDIT_PACKAGE"]
    try:
        module = importlib.import_module(package)
    except Exception as exc:
        # A mutant that breaks the import is caught by the suite, not a harness fault.
        _recorder.record_failure(f"<import {package}: {exc!r}>")
        return
    if module.__file__ is None:
        _recorder.error = f"{package} has no __file__, so its import location cannot be checked"
    else:
        found = Path(module.__file__).resolve()
        _recorder.package_file = str(found)
        if not found.is_relative_to(root):
            _recorder.error = f"{package} imported from {found}, outside the mutant copy {root}"
    if _recorder.error:
        pytest.exit(_recorder.error, returncode=3)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if _recorder is not None and report.failed:
        _recorder.record_failure(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if _recorder is None:
        return
    sys.settrace(None)
    threading.settrace(None)
    record = {
        "activated": _recorder.activated,
        "error": _recorder.error,
        "exitstatus": int(exitstatus),
        "failed": _recorder.failed,
        "package_file": _recorder.package_file,
    }
    Path(os.environ["MUTATION_AUDIT_OUT"]).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
