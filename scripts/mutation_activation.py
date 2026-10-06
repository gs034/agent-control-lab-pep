# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""pytest plugin for ``mutation_audit.py`` (ADR-0006): did any test run a mutated line?

Inert unless ``MUTATION_AUDIT_OUT`` is set. The harness sets:

- ``MUTATION_AUDIT_OUT``: where to write the JSON record;
- ``MUTATION_AUDIT_ROOT``: the mutant copy the suite must import from;
- ``MUTATION_AUDIT_PACKAGE``: the package whose import location is checked;
- ``MUTATION_AUDIT_TARGET`` and ``MUTATION_AUDIT_LINES``: the mutated file and
  its activation lines (absent for the baseline run).

Tracing covers the main thread and threads started after configure; child
processes are not traced.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import threading
from pathlib import Path

import pytest


class _Recorder:
    def __init__(self, target: str | None, lines: frozenset[int]) -> None:
        self.target = os.path.realpath(target) if target else None
        self.lines = lines
        self.activated = False
        self.failed: list[str] = []
        self.error: str | None = None
        self.package_file: str | None = None
        self._is_target: dict[str, bool] = {}

    def trace(self, frame, event, arg):
        if self.activated:
            return None
        name = frame.f_code.co_filename
        hit = self._is_target.get(name)
        if hit is None:
            hit = self._is_target[name] = os.path.realpath(name) == self.target
        return self._trace_line if hit else None

    def _trace_line(self, frame, event, arg):
        if self.activated:
            return None
        if event == "line" and frame.f_lineno in self.lines:
            self.activated = True
            return None
        return self._trace_line

    def record_failure(self, nodeid: str) -> None:
        if nodeid not in self.failed:
            self.failed.append(nodeid)


_recorder: _Recorder | None = None


def pytest_configure(config: pytest.Config) -> None:
    global _recorder
    if not os.environ.get("MUTATION_AUDIT_OUT"):
        return
    lines = os.environ.get("MUTATION_AUDIT_LINES", "")
    _recorder = _Recorder(
        os.environ.get("MUTATION_AUDIT_TARGET"),
        frozenset(int(n) for n in lines.split(",") if n),
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
        _recorder.error = f"cannot import {package}: {exc!r}"
    else:
        found = Path(module.__file__ or "").resolve()
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
