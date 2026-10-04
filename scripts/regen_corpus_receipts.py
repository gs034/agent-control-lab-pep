# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Rewrite expected receipts from live evaluation, for reviewed fixture changes.

Only the compared receipt fields and ``envelope_hash`` are rewritten;
``timestamp`` is kept as it is in the file, because most runtime fixtures
have no frozen clock and the tests do not compare it. Review the diff: it
should change only the fields the fixture change was meant to change.

    python scripts/regen_corpus_receipts.py          # write
    python scripts/regen_corpus_receipts.py --check  # exit 1 if any file would change
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


def _merged(path: Path, live: dict) -> tuple[str, str]:
    before = path.read_text(encoding="utf-8")
    current = json.loads(before)
    for key in REWRITTEN_KEYS:
        current[key] = live[key]
    return before, json.dumps(current, indent=2, sort_keys=True) + "\n"


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
    changed = []
    for path, live in _targets():
        before, after = _merged(path, live)
        if before != after:
            changed.append(path.relative_to(ROOT))
            if not check:
                path.write_text(after, encoding="utf-8")
    for path in changed:
        print(("would change " if check else "rewrote ") + str(path))
    return 1 if check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
