# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Measure reference-host decision times for the ADR-0008 limits discussion.

Three series are timed on one in-process host, each as a distribution
(p50, p95, p99, max) over ``--iterations`` calls:

- ``deny_unknown_tool``: a rules-only DENY (``unknown_tool``) with the log
  append included. No approval, no executor.
- ``deny_envelope_invalid``: a rules-only DENY for a malformed envelope.
- ``allow_echo``: a granted ``echo.ping`` call that enters the executor
  worker and returns. This is gate plus executor round trip, not a
  rules-only number.

The host refuses to run as root, so run this as an ordinary user. Nothing
here is an attack-success measurement; the numbers describe this machine
and this Python on the day, and are inputs to a limits proposal, not a
claim about any deployment.

The gap between an agent's successive tool calls is not measured here:
this tree holds no agent traces. Any trace supplied to ``--gaps`` must be
a JSON list of monotonic seconds at which calls were issued; the script
then reports the gap distribution next to the decision times.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from pep.host.haltfile import init_active
from pep.host.server import ReferenceHost, PeerCred

ARGS = {"message": "bench"}


def _percentiles(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)

    def at(q: float) -> float:
        index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
        return ordered[index]

    return {
        "n": len(ordered),
        "p50_ms": round(at(0.50) * 1000, 3),
        "p95_ms": round(at(0.95) * 1000, 3),
        "p99_ms": round(at(0.99) * 1000, 3),
        "max_ms": round(ordered[-1] * 1000, 3),
        "mean_ms": round(statistics.fmean(ordered) * 1000, 3),
    }


def _agent_uid() -> int:
    candidate = os.getuid() + 1
    return 2 if candidate == 0 else candidate


def run(iterations: int, gaps: list[float] | None) -> dict:
    if os.getuid() == 0:
        raise SystemExit("the reference host refuses to run as root; run this as an ordinary user")
    with tempfile.TemporaryDirectory(prefix="pep-bench-") as tmp:
        root = Path(tmp)
        halt = root / "halt.json"
        init_active(halt)
        host = ReferenceHost(
            halt_path=halt,
            log_path=root / "decisions.log",
            socket_path=root / "pep.sock",
            allowed_uids=frozenset({_agent_uid()}),
        )
        try:
            session = host.open_session(PeerCred(pid=4242, uid=_agent_uid(), gid=_agent_uid()))
            series: dict[str, list[float]] = {"deny_unknown_tool": [], "deny_envelope_invalid": [], "allow_echo": []}
            # Warm up the executor worker so the first fork is not in the samples.
            host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
            host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
            for _ in range(iterations):
                started = time.perf_counter()
                reply = host.handle_request({"tool_name": "no.such.tool", "args": {}}, session)
                series["deny_unknown_tool"].append(time.perf_counter() - started)
                assert reply["decision"] == "DENY", reply
            for _ in range(iterations):
                started = time.perf_counter()
                reply = host.handle_request(b"[]", session)
                series["deny_envelope_invalid"].append(time.perf_counter() - started)
                assert reply["decision"] == "DENY", reply
            for _ in range(iterations):
                host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
                started = time.perf_counter()
                reply = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
                series["allow_echo"].append(time.perf_counter() - started)
                assert reply["decision"] == "ALLOW", reply
        finally:
            host.close()
    report = {
        "measured_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "iterations": iterations,
        "series": {name: _percentiles(values) for name, values in series.items()},
        "note": (
            "In-process handle_request timings on one machine. deny_* are rules-only decisions "
            "with the log append; allow_echo includes the executor worker round trip. Not a socket "
            "round trip and not an attack-success measurement."
        ),
    }
    if gaps is not None:
        deltas = [b - a for a, b in zip(gaps, gaps[1:]) if b >= a]
        report["call_gaps"] = _percentiles(deltas) if deltas else {"n": 0}
    else:
        report["call_gaps"] = "not measured: this tree holds no agent traces"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--gaps", type=Path, help="JSON list of call issue times (monotonic seconds)")
    parser.add_argument("--json", type=Path, help="write the report here as JSON")
    args = parser.parse_args(argv)
    gaps = json.loads(args.gaps.read_text(encoding="utf-8")) if args.gaps else None
    report = run(args.iterations, gaps)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
