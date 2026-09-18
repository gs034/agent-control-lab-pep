# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_sources_carry_spdx():
    paths = list((ROOT / "pep").glob("*.py")) + list((ROOT / "evals").rglob("*.py"))
    paths += list((ROOT / "tests").glob("*.py"))
    assert paths
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "SPDX-License-Identifier: Apache-2.0" in text, path
