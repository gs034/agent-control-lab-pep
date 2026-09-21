# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Print the live deny receipt for the official eval/ row.

``--late-effect-fence`` prints a separate exercised deny: admit an allowlisted
invoke, ``kill()``, then complete the admission. That receipt is
``late_effect_fence`` (cut+fence), not the official row and not ``kill_active``.
"""

from __future__ import annotations

import sys

from pep.canonical import canonical_dumps
from pep.evaluate import Decision, PepRuntime
from pep.gate import begin_invoke, complete_invoke
from pep.policy import DEMO_POLICY
from pep.reasons import LATE_EFFECT_FENCE_DETAIL, ReasonCode
from pep.receipt import validate_receipt
from pep.row import evaluate_official_row, read_untrusted_prose


def _allowlisted_probe() -> dict[str, str | dict[str, str]]:
    return {
        "tool_name": "echo.ping",
        "args": {"message": "late-effect-fence"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "demo-late-effect-fence",
    }


def exercise_late_effect_fence() -> tuple[Decision, bool]:
    """Queue an allowlisted invoke, kill, then complete. Tool must not run."""
    runtime = PepRuntime(policy=DEMO_POLICY)
    entered = {"n": 0}

    def tool() -> str:
        entered["n"] += 1
        return "entered"

    pending = begin_invoke(_allowlisted_probe(), runtime=runtime)
    if pending.decision.verdict != "ALLOW":
        return pending.decision, entered["n"] > 0
    runtime.kill()

    def provider_callback():
        return complete_invoke(pending, tool)

    decision, _result = provider_callback()
    return decision, entered["n"] > 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--late-effect-fence" in args:
        return _late_effect_fence_main()
    policy_before = DEMO_POLICY.digest
    prose_before = read_untrusted_prose()
    decision, invoked = evaluate_official_row()
    receipt = decision.to_dict()
    print(canonical_dumps(receipt))
    if decision.verdict != "DENY":
        print("DEMO FAIL: expected DENY", file=sys.stderr)
        return 1
    if receipt.get("reason_code") != ReasonCode.TOOL_NOT_ALLOWLISTED_AND_NO_CAPABILITY:
        print("DEMO FAIL: unexpected reason_code", file=sys.stderr)
        return 1
    if invoked or receipt["negative_controls_observed"]["tool_invoke_executed"]:
        print("DEMO FAIL: tool invoked", file=sys.stderr)
        return 1
    if DEMO_POLICY.current_digest() != policy_before:
        print("DEMO FAIL: policy bytes changed", file=sys.stderr)
        return 1
    if read_untrusted_prose() != prose_before:
        print("DEMO FAIL: prose file changed", file=sys.stderr)
        return 1
    if receipt["judge"]["agent_prose_used_as_policy"]:
        print("DEMO FAIL: prose used as policy", file=sys.stderr)
        return 1
    return 0


def _late_effect_fence_main() -> int:
    decision, invoked = exercise_late_effect_fence()
    receipt = decision.to_dict()
    validate_receipt(receipt)
    print(canonical_dumps(receipt))
    if decision.verdict != "DENY":
        print("DEMO FAIL: late-effect fence expected DENY", file=sys.stderr)
        return 1
    if receipt.get("reason_code") != ReasonCode.LATE_EFFECT_FENCE:
        print("DEMO FAIL: late-effect fence reason_code", file=sys.stderr)
        return 1
    if receipt.get("reason_detail") != LATE_EFFECT_FENCE_DETAIL:
        print("DEMO FAIL: late-effect fence detail", file=sys.stderr)
        return 1
    if "cut+fence" not in str(receipt.get("reason_detail")):
        print("DEMO FAIL: late-effect fence detail missing cut+fence", file=sys.stderr)
        return 1
    if invoked or receipt["negative_controls_observed"]["tool_invoke_executed"]:
        print("DEMO FAIL: late-effect fence entered the tool", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
