# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors

from __future__ import annotations

from pep.demo import main


def test_demo_prints_two_deny_receipts(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "=== (a) structured forbidden invoke ===" in out
    assert "=== (b) prose/injection rewrite attempt ===" in out
    assert '"verdict":"DENY"' in out
    assert "unknown_tool" in out
    assert "agent_prose_rejected" in out
    assert "prose_consulted_as_policy" in out
    assert "invoked=False" in out
    assert out.count("invoked=False") >= 2
    assert "79%" not in out
