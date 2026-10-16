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
    assert isinstance(report["cpu_count"], int) and report["cpu_count"] >= 1
    assert set(report["load"]) == {"load_1m", "load_5m", "load_15m"}
    for sample in report["load"].values():
        assert sample is None or (isinstance(sample, (int, float)) and not isinstance(sample, bool) and sample >= 0)


def test_cpu_and_load_records_count_and_three_averages() -> None:
    recorded = bench._cpu_and_load()
    assert recorded["cpu_count"] == os.cpu_count()
    load = recorded["load"]
    assert list(load) == ["load_1m", "load_5m", "load_15m"]
    getloadavg = getattr(os, "getloadavg", None)
    if getloadavg is None:
        assert all(sample is None for sample in load.values())
        return
    try:
        getloadavg()
    except OSError:
        assert all(sample is None for sample in load.values())
    else:
        assert all(isinstance(sample, float) and sample >= 0 for sample in load.values())


def test_missing_load_average_records_null(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(bench.os, "getloadavg", raising=False)
    recorded = bench._cpu_and_load()
    assert recorded["load"] == {"load_1m": None, "load_5m": None, "load_15m": None}

    def _unavailable() -> tuple[float, float, float]:
        raise OSError("load average unavailable")

    monkeypatch.setattr(bench.os, "getloadavg", _unavailable, raising=False)
    recorded = bench._cpu_and_load()
    assert recorded["load"] == {"load_1m": None, "load_5m": None, "load_15m": None}


def test_percentiles_are_order_statistics() -> None:
    result = bench._percentiles([0.001 * i for i in range(1, 101)])
    assert result["n"] == 100
    assert result["p50_ms"] == 51.0
    assert result["p99_ms"] == 99.0
    assert result["max_ms"] == 100.0
