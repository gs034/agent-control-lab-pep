# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Load Deep Research artefacts from eval/ and run the official deny row.

Artefacts on main (do not invent a parallel layout):

- eval/ACL_PEP_Eval_Row_2609_19587_class_2026-09-18.md
- eval/structured_envelope.example.json   (official-row policy-relevant input)
- eval/malicious_agent_prose.txt          (untrusted data only; never policy)
- eval/expected_deny_receipt.example.json
- eval/corpus/                            (M1 rows; same evaluate() path)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pep.evaluate import Decision, evaluate
from pep.gate import gated_invoke
from pep.policy import DEMO_POLICY

ENVELOPE_FILE = "structured_envelope.example.json"
PROSE_FILE = "malicious_agent_prose.txt"
EXPECTED_RECEIPT_FILE = "expected_deny_receipt.example.json"
ROW_DOC = "ACL_PEP_Eval_Row_2609_19587_class_2026-09-18.md"


def repo_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [here.parents[1], Path.cwd()]
    for parent in here.parents:
        candidates.append(parent)
    for candidate in candidates:
        if (candidate / "eval" / ENVELOPE_FILE).is_file():
            return candidate
    raise FileNotFoundError("eval/structured_envelope.example.json not found")


def eval_dir() -> Path:
    return repo_root() / "eval"


def load_structured_envelope() -> dict[str, Any]:
    path = eval_dir() / ENVELOPE_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("structured envelope must be a JSON object")
    return data


def load_expected_deny_receipt() -> dict[str, Any]:
    path = eval_dir() / EXPECTED_RECEIPT_FILE
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("expected deny receipt must be a JSON object")
    return data


def read_untrusted_prose() -> str:
    """Sidecar only. Callers must not pass this string into evaluate() as policy."""
    return (eval_dir() / PROSE_FILE).read_text(encoding="utf-8")


def evaluate_official_row() -> tuple[Decision, bool]:
    """Evaluate the official envelope. Prose file is not an evaluate() input."""
    envelope = load_structured_envelope()
    invoked = {"n": 0}

    def _should_never_run() -> str:
        invoked["n"] += 1
        return "INVOKED"  # pragma: no cover

    decision, result = gated_invoke(envelope, _should_never_run)
    del result
    return decision, invoked["n"] > 0


def evaluate_envelope_only() -> Decision:
    return evaluate(load_structured_envelope())
