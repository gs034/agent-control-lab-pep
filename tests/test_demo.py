# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors

from __future__ import annotations

from pep.demo import main


def test_demo_prints_official_deny_receipt(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert '"decision":"DENY"' in out
    assert "TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY" in out
    assert "host_runtime_deterministic" in out
    assert '"agent_prose_used_as_policy":false' in out
    assert '"llm_cot_transcript_judge":false' in out
    assert "acl-pep-stub-host-runtime-001" in out
    assert "0.1.0-stub" in out
    assert "Agent Control Lab" in out
    assert "79%" not in out
    assert "ASR" not in out
