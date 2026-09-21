# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Post-kill late invoke fails closed with a cut+fence receipt, not ALLOW."""

from __future__ import annotations

import threading

from pep.demo import exercise_late_effect_fence, main
from pep.evaluate import PepRuntime, evaluate
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import LATE_EFFECT_FENCE_DETAIL, ReasonCode
from pep.receipt import FROZEN_RECEIPT_KEYS, validate_receipt


def _valid():
    return {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-late-effect-fence",
    }


def _boom_factory():
    called = {"n": 0}

    def boom():
        called["n"] += 1
        return "entered"

    return called, boom


def test_queued_invoke_after_kill_is_fence_deny_not_allow():
    runtime = PepRuntime(policy=DEMO_POLICY)
    assert runtime.fence_engaged is False
    queued = begin_invoke(_valid(), runtime=runtime)
    assert queued.decision.verdict == "ALLOW"
    assert queued.admitted_epoch == 0
    called, boom = _boom_factory()
    runtime.kill()
    assert runtime.fence_engaged is True
    assert runtime.fence_epoch == 1
    decision, result = complete_invoke(queued, boom)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert decision.receipt.reason_code != ReasonCode.KILL_ACTIVE
    assert decision.receipt.reason_detail == LATE_EFFECT_FENCE_DETAIL
    assert "cut+fence" in decision.receipt.reason_detail
    assert result is None
    assert called["n"] == 0
    payload = decision.to_dict()
    validate_receipt(payload)
    assert set(payload) == FROZEN_RECEIPT_KEYS
    assert payload["negative_controls_observed"]["tool_invoke_executed"] is False


def test_provider_callback_after_kill_is_fence_deny():
    runtime = PepRuntime(policy=DEMO_POLICY)
    pending = begin_invoke(_valid(), runtime=runtime)
    called, boom = _boom_factory()
    runtime.kill()

    def provider_callback():
        return complete_invoke(pending, boom)

    decision, result = provider_callback()
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert result is None
    assert called["n"] == 0


def test_post_cut_invoke_stays_kill_active_and_pre_cut_stays_fence():
    runtime = PepRuntime(policy=DEMO_POLICY)
    queued = begin_invoke(_valid(), runtime=runtime)
    called, boom = _boom_factory()
    runtime.kill()
    late, late_result = complete_invoke(queued, boom)
    fresh, fresh_result = gated_invoke(_valid(), boom, runtime=runtime)
    assert late.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert fresh.verdict == "DENY"
    assert fresh.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert late_result is None
    assert fresh_result is None
    assert called["n"] == 0
    direct = evaluate(_valid(), runtime=runtime)
    assert direct.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_complete_without_kill_still_invokes():
    runtime = PepRuntime(policy=DEMO_POLICY)
    pending = begin_invoke(_valid(), runtime=runtime)
    called, boom = _boom_factory()
    decision, result = complete_invoke(pending, boom)
    assert decision.verdict == "ALLOW"
    assert result == "entered"
    assert called["n"] == 1
    assert runtime.fence_engaged is False


def test_second_kill_does_not_move_the_cut_epoch():
    runtime = PepRuntime(policy=DEMO_POLICY)
    runtime.kill()
    epoch = runtime.fence_epoch
    runtime.kill()
    runtime.resume()
    assert runtime.fence_epoch == epoch == 1
    assert runtime.fence_engaged is True
    assert runtime.kill_active is True


def test_suspend_between_admit_and_complete_does_not_invoke():
    runtime = PepRuntime(policy=DEMO_POLICY)
    pending = begin_invoke(_valid(), runtime=runtime)
    called, boom = _boom_factory()
    runtime.suspend()
    decision, result = complete_invoke(pending, boom)
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.SUSPEND_ACTIVE
    assert result is None
    assert called["n"] == 0


def test_cross_thread_callback_after_kill_is_fenced():
    runtime = PepRuntime(policy=DEMO_POLICY)
    admitted = threading.Event()
    release = threading.Event()
    outcome: dict[str, object] = {}
    called, boom = _boom_factory()

    def worker():
        pending = begin_invoke(_valid(), runtime=runtime)
        outcome["admitted"] = pending.decision.verdict
        admitted.set()
        assert release.wait(2)
        decision, result = complete_invoke(pending, boom)
        outcome["decision"] = decision
        outcome["result"] = result

    thread = threading.Thread(target=worker)
    thread.start()
    assert admitted.wait(2)
    assert outcome["admitted"] == "ALLOW"
    runtime.kill()
    release.set()
    thread.join(2)
    assert thread.is_alive() is False
    decision = outcome["decision"]
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert outcome["result"] is None
    assert called["n"] == 0


def test_exercised_demo_prints_fence_deny(capsys):
    decision, invoked = exercise_late_effect_fence()
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert invoked is False
    assert main(["--late-effect-fence"]) == 0
    out = capsys.readouterr().out
    assert '"decision":"DENY"' in out
    assert "late_effect_fence" in out
    assert "cut+fence" in out
    assert "kill_active" not in out
    assert "ASR" not in out
    assert main([]) == 0
    official = capsys.readouterr().out
    assert "TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY" in official
    assert "late_effect_fence" not in official
