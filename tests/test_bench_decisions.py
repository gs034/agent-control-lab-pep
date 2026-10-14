# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""The decision-time benchmark runs and reports the three series."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bench_decisions", ROOT / "scripts" / "bench_decisions.py")
bench = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(bench)


@pytest.mark.skipif(os.getuid() == 0, reason="the reference host refuses to run as root")
def test_benchmark_reports_three_series_and_a_gap_distribution(tmp_path: Path) -> None:
    gaps = tmp_path / "gaps.json"
    gaps.write_text(json.dumps([0.0, 1.5, 3.0, 9.0]), encoding="utf-8")
    out = tmp_path / "report.json"
    assert bench.main(["--iterations", "5", "--gaps", str(gaps), "--json", str(out)]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert set(report["series"]) == {"deny_unknown_tool", "deny_envelope_invalid", "allow_echo"}
    for series in report["series"].values():
        assert series["n"] == 5
        assert series["p50_ms"] <= series["p99_ms"] <= series["max_ms"]
    assert report["call_gaps"]["n"] == 3
    assert report["call_gaps"]["max_ms"] == 6000.0


def test_percentiles_are_order_statistics() -> None:
    result = bench._percentiles([0.001 * i for i in range(1, 101)])
    assert result["n"] == 100
    assert result["p50_ms"] == 51.0
    assert result["p99_ms"] == 99.0
    assert result["max_ms"] == 100.0
