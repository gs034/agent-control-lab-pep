# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Durable kill/suspend store survives process restart (new PepRuntime)."""

from __future__ import annotations

from pathlib import Path

from pep.evaluate import PepRuntime, evaluate
from pep.halt import HaltMode, HaltState, HaltStore
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode


def _allowable():
    return {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-halt-store",
    }


def test_kill_survives_new_runtime_on_same_file(tmp_path: Path):
    store = HaltStore(tmp_path / "halt.json")
    first = PepRuntime(policy=DEMO_POLICY, halt_store=store)
    first.kill()
    assert first.kill_active is True

    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(tmp_path / "halt.json"))
    decision = evaluate(_allowable(), runtime=restarted)
    assert restarted.kill_active is True
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert decision.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False


def test_resume_cannot_clear_persisted_kill(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.kill()
    first.resume()
    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    restarted.resume()
    decision = evaluate(_allowable(), runtime=restarted)
    assert restarted.kill_active is True
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_suspend_survives_restart_and_resume_restores(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.suspend()
    mid = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    denied = evaluate(_allowable(), runtime=mid)
    assert denied.verdict == "DENY"
    assert denied.receipt.reason_code == ReasonCode.SUSPEND_ACTIVE
    mid.resume()
    after = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    allowed = evaluate(_allowable(), runtime=after)
    assert after.mode.value == "active"
    assert allowed.verdict == "ALLOW"
    assert allowed.receipt.reason_code == ReasonCode.ALLOWED


def test_unavailable_survives_restart(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.mark_unavailable()
    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    decision = evaluate(_allowable(), runtime=restarted)
    assert restarted.available is False
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_corrupt_halt_file_fails_closed(tmp_path: Path):
    path = tmp_path / "halt.json"
    path.write_text("{not-json", encoding="utf-8")
    runtime = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    decision = evaluate(_allowable(), runtime=runtime)
    assert runtime.kill_active or runtime.available is False
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_missing_halt_file_is_active(tmp_path: Path):
    store = HaltStore(tmp_path / "missing.json")
    assert store.read().mode is HaltMode.ACTIVE
    runtime = PepRuntime(policy=DEMO_POLICY, halt_store=store)
    decision = evaluate(_allowable(), runtime=runtime)
    assert decision.verdict == "ALLOW"


def test_store_write_cannot_clear_kill(tmp_path: Path):
    store = HaltStore(tmp_path / "halt.json")
    store.write(HaltState(mode=HaltMode.KILLED))
    written = store.write(HaltState(mode=HaltMode.ACTIVE))
    assert written.mode is HaltMode.KILLED
