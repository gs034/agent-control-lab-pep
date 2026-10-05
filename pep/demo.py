# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Print the live deny receipt for the official eval/ row.

``--late-effect-fence`` prints a separate exercised deny: admit an allowlisted
invoke, ``kill()``, then complete the admission. That receipt is
``late_effect_fence`` (cut+fence), not the official row and not ``kill_active``.

``--implementation-binding`` (Linux only) prints four scenarios, one line each,
with two programs both named ``labtool`` and a ``PATH`` that changes after the
approval: an unbound grant, a bound grant (ADR-0004), a bound grant whose host
runs the program by path after the entry check, and a bound grant whose host
uses ``open_executable`` (ADR-0005). Existence proof on fixtures only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from pep.canonical import canonical_dumps
from pep.evaluate import Decision, PepRuntime
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.implementation import executable_digest, open_executable
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

    # The demo host attests the probe caller, a listed holder (ADR-0003).
    pending = begin_invoke(_allowlisted_probe(), runtime=runtime, principal="lab.demo.agent")
    if pending.decision.verdict != "ALLOW":
        return pending.decision, entered["n"] > 0
    runtime.kill()

    def provider_callback():
        return complete_invoke(pending, tool)

    decision, _result = provider_callback()
    return decision, entered["n"] > 0


_HOST = "lab.demo.agent"
_BINDING_ARGS = {"message": "implementation-binding"}

# scenario, version that introduced the behaviour, then the expected outcome.
_BINDING_SCENARIOS = (
    ("unbound grant, PATH changed after approval", "before 0.6.0", "ALLOW", "allowed", "program-b", True),
    (
        "bound grant, PATH changed after approval",
        "0.6.0 (ADR-0004)",
        "DENY",
        ReasonCode.APPROVAL_IMPLEMENTATION_MISMATCH,
        None,
        False,
    ),
    ("bound grant, PATH changed inside the tool, host runs by path", "0.6.0 residual", "ALLOW", "allowed", "program-b", True),
    (
        "bound grant, PATH changed inside the tool, host uses open_executable",
        "0.7.0 (ADR-0005)",
        "ALLOW",
        "allowed",
        "program-a",
        True,
    ),
)


def exercise_implementation_binding() -> list[dict[str, Any]]:
    """Run the four implementation-binding scenarios and report each outcome."""
    with tempfile.TemporaryDirectory(prefix="pep-demo-") as tmp:
        dirs = []
        for label in ("program-a", "program-b"):
            bin_dir = Path(tmp) / label
            bin_dir.mkdir()
            program = bin_dir / "labtool"
            program.write_text(f"#!/bin/sh\necho {label}\n", encoding="utf-8")
            program.chmod(0o755)
            dirs.append(str(bin_dir))
        a_first = os.pathsep.join(dirs)
        b_first = os.pathsep.join(reversed(dirs))
        return [
            _binding_scenario(0, a_first, b_first, bound=False, swap_in_tool=False, helper=False),
            _binding_scenario(1, a_first, b_first, bound=True, swap_in_tool=False, helper=False),
            _binding_scenario(2, a_first, b_first, bound=True, swap_in_tool=True, helper=False),
            _binding_scenario(3, a_first, b_first, bound=True, swap_in_tool=True, helper=True),
        ]


def _binding_scenario(index: int, a_first: str, b_first: str, *, bound: bool, swap_in_tool: bool, helper: bool) -> dict[str, Any]:
    name, since, verdict, reason, ran, consumed = _BINDING_SCENARIOS[index]
    search = {"path": a_first}
    runtime = PepRuntime(policy=DEMO_POLICY)
    grant = runtime.issue_approval(
        tool_name="echo.ping",
        args=dict(_BINDING_ARGS),
        ttl_seconds=60,
        principal=_HOST,
        implementation_digest=executable_digest("labtool", path=a_first) if bound else None,
    )
    envelope = {
        "tool_name": "echo.ping",
        "args": dict(_BINDING_ARGS),
        "capability_token": None,
        "caller_identity": _HOST,
        "request_id": f"demo-implementation-binding-{index}",
        "approval_id": grant.approval_id,
    }

    def by_path() -> str:
        if swap_in_tool:
            search["path"] = b_first
        resolved = shutil.which("labtool", path=search["path"])
        return subprocess.run([resolved], capture_output=True, text=True, check=True).stdout.strip()

    if not swap_in_tool:
        search["path"] = b_first
    if helper:
        with open_executable("labtool", path=search["path"]) as program:

            def pinned() -> str:
                search["path"] = b_first
                return program.run(capture_output=True, text=True, check=True).stdout.strip()

            decision, result = gated_invoke(
                envelope, pinned, runtime=runtime, principal=_HOST, implementation_observer=lambda: program.digest
            )
    else:
        decision, result = gated_invoke(
            envelope,
            by_path,
            runtime=runtime,
            principal=_HOST,
            implementation_observer=(lambda: executable_digest("labtool", path=search["path"])) if bound else None,
        )
    receipt = decision.to_dict()
    validate_receipt(receipt)
    observed = {
        "decision": receipt["decision"],
        "reason_code": receipt["reason_code"],
        "program_ran": result,
        "grant_consumed": runtime.approvals.lookup(grant.approval_id).consumed(),
    }
    expected = {"decision": verdict, "reason_code": str(reason), "program_ran": ran, "grant_consumed": consumed}
    return {"scenario": name, "since": since, **observed, "as_expected": observed == expected, "receipt": receipt}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--late-effect-fence" in args:
        return _late_effect_fence_main()
    if "--implementation-binding" in args:
        return _implementation_binding_main()
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


def _implementation_binding_main() -> int:
    if sys.platform != "linux":
        print("DEMO FAIL: --implementation-binding needs Linux (sealed memfd exec, ADR-0005)", file=sys.stderr)
        return 1
    try:
        results = exercise_implementation_binding()
    except OSError as exc:
        # ImplementationUnavailable (for example vm.memfd_noexec = 2) or a temp dir mounted noexec.
        print(f"DEMO FAIL: cannot run the implementation-binding demo here: {exc}", file=sys.stderr)
        return 1
    for result in results:
        print(canonical_dumps(result))
    failed = [r["scenario"] for r in results if not r["as_expected"]]
    if failed:
        print(f"DEMO FAIL: unexpected outcome in {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
