# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""M1 evaluator corpus under eval/corpus/.

Rows are structured envelopes plus expected receipts. The PEP trust
domain is still ``pep.evaluate`` / ``pep.gated_invoke``. This module
only loads fixtures and applies runtime setup (policy, halt mode,
single-use approvals). It is not a second judge.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, Mapping

from pep.approval import ApprovalStore
from pep.evaluate import Decision, PepRuntime, evaluate
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.policy import DEMO_POLICY, PolicyStore
from pep.row import eval_dir

CORPUS_INDEX = "corpus/index.json"

REQUIRED_DENY_CLASSES = frozenset(
    {
        "prose_as_policy",
        "capability_spoof",
        "monitor_coax",
        "missing_policy",
        "kill_suspend",
        "approval_replay_ttl",
        "approval_binding",
        "approval_state_substitution",
        "late_effect_fence",
        # Threat-model classes named in the joint-eval measured-corpus v0 seed
        # (docs/measured-corpus-v0.md in that repo). Rows only; no new mechanism.
        "multi_session_plant",
        "deferred_tool",
        # Eval taxonomy only. Noul labels are not allow or deny authority.
        "noul_taxonomy_coax",
    }
)


@dataclass(frozen=True, slots=True)
class CorpusRow:
    row_id: str
    deny_class: str
    expected_decision: Literal["ALLOW", "DENY"]
    envelope: dict[str, Any]
    expected_receipt: dict[str, Any]
    runtime_spec: dict[str, Any]
    envelope_path: Path
    receipt_path: Path


def corpus_index_path() -> Path:
    return eval_dir() / "corpus" / "index.json"


def load_corpus_index() -> dict[str, Any]:
    data = json.loads(corpus_index_path().read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("corpus index must be a JSON object")
    return data


def iter_corpus_rows() -> Iterator[CorpusRow]:
    index = load_corpus_index()
    rows = index.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("corpus index.rows must be a non-empty array")
    root = eval_dir()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise ValueError("corpus row descriptor must be a JSON object")
        yield _load_row(root, raw)


def list_corpus_rows() -> list[CorpusRow]:
    return list(iter_corpus_rows())


def corpus_deny_classes() -> set[str]:
    return {row.deny_class for row in list_corpus_rows() if row.expected_decision == "DENY"}


def runtime_for_spec(spec: Mapping[str, Any]) -> tuple[PepRuntime, datetime | None]:
    """Build a process-local runtime from a corpus runtime fixture."""
    policy_name = spec.get("policy", "demo")
    if policy_name == "empty":
        policy = PolicyStore.empty()
    elif policy_name == "demo":
        policy = DEMO_POLICY
    else:
        raise ValueError(f"unknown corpus policy fixture: {policy_name}")

    clock = _optional_clock(spec.get("now"))
    approvals = ApprovalStore()
    for grant in spec.get("approvals") or []:
        if not isinstance(grant, Mapping):
            raise ValueError("corpus approval fixture must be a JSON object")
        issued_at = _optional_clock(grant.get("issued_at")) or clock
        frozen_args = grant.get("args")
        if not isinstance(frozen_args, Mapping):
            raise ValueError("corpus approval fixture must freeze args as a JSON object")
        record = approvals.issue(
            tools=tuple(grant.get("tools") or (grant.get("tool_name"),)),
            args=frozen_args,
            ttl_seconds=int(grant["ttl_seconds"]),
            approval_id=str(grant["approval_id"]),
            now=issued_at,
            catalog=None if policy_name == "empty" else policy.allowed_tools(),
            state_digest=grant.get("state_digest"),
        )
        if grant.get("consumed"):
            reason = approvals.try_consume(
                record.approval_id,
                record.tools[0],
                now=issued_at,
                args=record.frozen_args,
            )
            if reason is not None:
                raise ValueError(f"could not pre-consume fixture approval: {reason}")

    runtime = PepRuntime(policy=policy, approvals=approvals)
    mode = spec.get("mode", "active")
    if mode == "killed":
        runtime.kill()
    elif mode == "suspended":
        runtime.suspend()
    elif mode == "active":
        pass
    else:
        raise ValueError(f"unknown corpus runtime mode: {mode}")
    if spec.get("available") is False:
        runtime.mark_unavailable()
    return runtime, clock


def evaluate_corpus_row(row: CorpusRow) -> Decision:
    runtime, now = runtime_for_spec(row.runtime_spec)
    finished = _finish_after_kill(row, runtime, now, _refuse_tool)
    if finished is not None:
        decision, _result = finished
        return decision
    return evaluate(row.envelope, runtime=runtime, now=now)


def gated_corpus_row(row: CorpusRow, tool) -> tuple[Decision, Any]:
    runtime, now = runtime_for_spec(row.runtime_spec)
    finished = _finish_after_kill(row, runtime, now, tool)
    if finished is not None:
        return finished
    return gated_invoke(row.envelope, tool, runtime=runtime, now=now)


def _finish_after_kill(row: CorpusRow, runtime, now, tool):
    """Admit, then kill, then complete. Models a queued invoke finishing after the cut."""
    marker = row.runtime_spec.get("complete_after")
    if marker is None:
        return None
    if marker != "kill":
        raise ValueError(f"unknown corpus complete_after: {marker}")
    pending = begin_invoke(row.envelope, runtime=runtime, now=now)
    runtime.kill()
    return complete_invoke(pending, tool)


def _refuse_tool() -> None:
    raise AssertionError("late-effect fence entered the tool")


def _load_row(root: Path, raw: Mapping[str, Any]) -> CorpusRow:
    row_id = str(raw["id"])
    deny_class = str(raw["class"])
    decision = raw["expected_decision"]
    if decision not in ("ALLOW", "DENY"):
        raise ValueError(f"{row_id}: expected_decision must be ALLOW or DENY")
    envelope_path = root / str(raw["envelope"])
    receipt_path = root / str(raw["expected_receipt"])
    runtime_path = root / str(raw["runtime"])
    envelope = _load_object(envelope_path, "envelope")
    expected = _load_object(receipt_path, "expected receipt")
    runtime_spec = _load_object(runtime_path, "runtime")
    return CorpusRow(
        row_id=row_id,
        deny_class=deny_class,
        expected_decision=decision,  # type: ignore[arg-type]
        envelope=envelope,
        expected_receipt=expected,
        runtime_spec=runtime_spec,
        envelope_path=envelope_path,
        receipt_path=receipt_path,
    )


def _load_object(path: Path, label: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return data


def _optional_clock(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("corpus clock must be an ISO-8601 string")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
