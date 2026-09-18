# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Print the live deny receipt for the official eval/ row."""

from __future__ import annotations

import sys

from pep.canonical import canonical_dumps
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode
from pep.row import evaluate_official_row, read_untrusted_prose


def main(argv: list[str] | None = None) -> int:
    del argv
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


if __name__ == "__main__":
    raise SystemExit(main())
