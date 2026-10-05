# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Rewrite expected receipts from live evaluation, for reviewed fixture changes.

Only the compared receipt fields and ``envelope_hash`` are rewritten;
``timestamp`` is kept as it is in the file, because most runtime fixtures
have no frozen clock and the tests do not compare it. Review the diff: it
should change only the fields the fixture change was meant to change.

    python scripts/regen_corpus_receipts.py          # write
    python scripts/regen_corpus_receipts.py --check  # exit 1 if any file would change

A change to ``decision`` or ``reason_code`` is reported per file and refused
unless ``--allow-outcome-change`` is given, so a fixture slip cannot silently
rewrite an expected outcome.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pep.corpus import gated_corpus_row, list_corpus_rows  # noqa: E402
from pep.row import EXPECTED_RECEIPT_FILE, eval_dir, evaluate_official_row  # noqa: E402

REWRITTEN_KEYS = (
    "brand",
    "decision",
    "envelope_hash",
    "eval_ref",
    "fail_closed",
    "judge",
    "licence",
    "negative_controls_observed",
    "pep_id",
    "policy_version",
    "reason_code",
    "reason_detail",
    "receipt_type",
    "trust_domain",
)


OUTCOME_KEYS = ("decision", "reason_code")


def _merged(path: Path, live: dict) -> tuple[str, str, list[str]]:
    before = path.read_text(encoding="utf-8")
    current = json.loads(before)
    outcome = [f"{key}: {current.get(key)} -> {live[key]}" for key in OUTCOME_KEYS if current.get(key) != live[key]]
    for key in REWRITTEN_KEYS:
        current[key] = live[key]
    return before, json.dumps(current, indent=2, sort_keys=True) + "\n", outcome


def _targets() -> list[tuple[Path, dict]]:
    targets = []
    for row in list_corpus_rows():
        decision, _result = gated_corpus_row(row, lambda: "ok")
        targets.append((row.receipt_path, decision.to_dict()))
    decision, _invoked = evaluate_official_row()
    targets.append((eval_dir() / EXPECTED_RECEIPT_FILE, decision.to_dict()))
    return targets


def main(argv: list[str]) -> int:
    check = "--check" in argv
    allow_outcome = "--allow-outcome-change" in argv
    changed = []
    refused = []
    for path, live in _targets():
        before, after, outcome = _merged(path, live)
        if before == after:
            continue
        rel = path.relative_to(ROOT)
        for line in outcome:
            print(f"outcome change {rel}: {line}")
        if outcome and not allow_outcome and not check:
            refused.append(rel)
            continue
        changed.append(rel)
        if not check:
            path.write_text(after, encoding="utf-8")
    for rel in changed:
        print(("would change " if check else "rewrote ") + str(rel))
    for rel in refused:
        print(f"refused {rel}: outcome change needs --allow-outcome-change")
    return 1 if (check and changed) or refused else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
