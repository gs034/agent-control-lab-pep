# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors

from __future__ import annotations

import json
import sys

import pytest

from pep.demo import main
from pep.policy import POLICY_VERSION


def test_demo_prints_official_deny_receipt(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert '"decision":"DENY"' in out
    assert "TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY" in out
    assert "host_runtime_deterministic" in out
    assert '"agent_prose_used_as_policy":false' in out
    assert '"llm_cot_transcript_judge":false' in out
    assert "acl-pep-stub-host-runtime-001" in out
    assert POLICY_VERSION in out
    assert "Agent Control Lab" in out
    assert "79%" not in out
    assert "ASR" not in out


@pytest.mark.skipif(sys.platform != "linux", reason="the implementation-binding demo is Linux only (ADR-0005)")
def test_implementation_binding_demo_shows_each_step(capsys):
    assert main(["--implementation-binding"]) == 0
    out = capsys.readouterr().out
    rows = [json.loads(line) for line in out.splitlines()]
    assert [r["since"] for r in rows] == ["before 0.6.0", "0.6.0 (ADR-0004)", "0.6.0 residual", "0.7.0 (ADR-0005)"]
    assert [r["program_ran"] for r in rows] == ["program-b", None, "program-b", "program-a"]
    assert [r["reason_code"] for r in rows] == ["allowed", "approval_implementation_mismatch", "allowed", "allowed"]
    assert [r["grant_consumed"] for r in rows] == [True, False, True, True]
    assert all(r["as_expected"] for r in rows)
    assert "ASR" not in out


def test_implementation_binding_demo_refuses_other_platforms(capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert main(["--implementation-binding"]) == 1
    assert "Linux" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "linux", reason="the implementation-binding demo is Linux only (ADR-0005)")
def test_implementation_binding_demo_fails_on_an_unexpected_outcome(capsys, monkeypatch):
    import pep.demo as demo

    wrong = {"scenario": "forced", "since": "test", "as_expected": False}
    monkeypatch.setattr(demo, "exercise_implementation_binding", lambda: [wrong])
    assert main(["--implementation-binding"]) == 1
    assert "DEMO FAIL" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "linux", reason="the implementation-binding demo is Linux only (ADR-0005)")
def test_implementation_binding_demo_reports_an_unavailable_helper_cleanly(capsys, monkeypatch):
    import pep.demo as demo
    from pep.implementation import ImplementationUnavailable

    def unavailable():
        raise ImplementationUnavailable("kernel policy refuses an executable memfd")

    monkeypatch.setattr(demo, "exercise_implementation_binding", unavailable)
    assert main(["--implementation-binding"]) == 1
    assert "DEMO FAIL" in capsys.readouterr().err
