# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Reference host regressions for the separate policy enforcement point.

These checks correspond to the gaps where the in-process library trusts
its caller: the callable, the clock, the identity, unknown envelope keys,
a halt file that can be deleted, and a decision that only the caller kept.
"""

from __future__ import annotations

import io
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from pep.evaluate import PepRuntime, evaluate
from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError
from pep.host.__main__ import main
from pep.host.client import invoke
from pep.host.haltfile import ACTIVE, init_active, read_fail_closed
from pep.host.log import FORBIDDEN_KEYS, MAX_LOG_STARTUP_BYTES, DecisionLog, DecisionLogError
from pep.host.protocol import ProtocolError, parse_host_request
from pep.host.server import SOCKET_MODE, HostError, PeerCred, ReferenceHost

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
ARGS = {"message": "hi"}


def _walk(value: Any) -> list[Any]:
    found = [value]
    if isinstance(value, dict):
        for key, item in value.items():
            found.append(key)
            found.extend(_walk(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk(item))
    return found


def _assert_record_claims_only_what_ran(record: dict[str, Any]) -> None:
    for item in _walk(record):
        assert not isinstance(item, bool)
        if isinstance(item, str):
            assert item not in FORBIDDEN_KEYS
    names = [check["name"] for check in record["checks"]]
    assert len(names) == len(set(names))


def _host(
    tmp_path: Path,
    *,
    registry: dict | None = None,
    clock=None,
    init: bool = True,
    **kwargs: Any,
) -> ReferenceHost:
    halt = tmp_path / "halt.json"
    if init:
        init_active(halt)
    return ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=tmp_path / "sock" / "pep.sock",
        registry=registry,
        clock=clock,
        **kwargs,
    )


def _peer(pid: int = 10, uid: int = 1000) -> PeerCred:
    return PeerCred(pid=pid, uid=uid, gid=1000)


def _denial_tally(records: list[dict[str, Any]]) -> int:
    """Individual denial lines plus the counts carried on summary lines."""
    total = 0
    for record in records:
        if record.get("reason_code") == "rate_limited":
            total += int(record["suppressed_count"])
        elif record.get("decision") == "DENY":
            total += 1
    return total


def _load_log(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


class _Mono:
    """Fake monotonic clock. Tests set ``now``; the host reads it under its lock."""

    def __init__(self) -> None:
        self.now = 0.0
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.now


def test_in_process_api_is_not_described_as_the_boundary():
    text = Path(__file__).resolve().parents[1].joinpath("pep", "evaluate.py").read_text(encoding="utf-8")
    assert "not a security boundary" in text


def test_caller_supplied_callable_is_refused_and_registry_runs(tmp_path: Path):
    calls: list[str] = []

    def registered(args: dict) -> dict:
        calls.append("registry")
        return {"pong": args["message"]}

    def attacker(*_args: object, **_kwargs: object) -> dict:
        calls.append("attacker")
        return {"pwned": True}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)

    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert allowed["decision"] == "ALLOW"
    assert allowed["result"] == {"pong": "hi"}
    assert allowed["result_origin"] == "host-registry"
    assert calls == ["registry"]

    denied = host.handle_request(
        {"tool_name": "echo.ping", "args": ARGS, "tool": attacker},
        session,
    )
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "envelope_invalid"
    assert calls == ["registry"]

    with pytest.raises(TypeError):
        host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session, tool=attacker)  # type: ignore[call-arg]
    assert calls == ["registry"]

    def hidden() -> None:
        calls.append("hidden")

    smuggled = host.handle_request(
        {"tool_name": "echo.ping", "args": {"message": hidden}},
        session,
    )
    assert smuggled["decision"] == "DENY"
    assert smuggled["reason_code"] == "envelope_invalid"
    assert "hidden" not in calls


def test_caller_supplied_time_cannot_revive_an_expired_approval(tmp_path: Path):
    clock = {"now": NOW}
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "no"}

    host = _host(tmp_path, registry={"echo.ping": registered}, clock=lambda: clock["now"])
    session = host.open_session(_peer())
    grant = host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    clock["now"] = NOW + timedelta(seconds=61)

    expired = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert expired["decision"] == "DENY"
    assert expired["reason_code"] == "approval_expired"
    assert calls == []

    revived = host.handle_request(
        {"tool_name": "echo.ping", "args": ARGS, "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ")},
        session,
    )
    assert revived["decision"] == "DENY"
    assert revived["reason_code"] == "envelope_invalid"
    assert calls == []
    assert host.runtime.approvals.lookup(grant.approval_id).consumed_at is None
    expired_record = host.decision_records()[0]
    expired_names = [check["name"] for check in expired_record["checks"]]
    assert "evaluate" in expired_names
    assert "registry_tool" not in expired_names
    _assert_record_claims_only_what_ran(expired_record)


def test_unknown_envelope_keys_are_denied(tmp_path: Path):
    host = _host(tmp_path)
    session = host.open_session(_peer())
    extras = [
        {"now": "2020-01-01T00:00:00Z"},
        {"schema_fields": {"injected": True}},
        {"invoke": {"extra": True}},
        {"principal": "u1000.c1"},
        {"caller_identity": "lab.demo.agent"},
        {"session_id": "u1000.c1"},
        {"capability_token": "lab.cap.echo.demo"},
        {"approval_id": "lab.appr.stolen"},
    ]
    for extra in extras:
        decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS, **extra}, session)
        assert decision["decision"] == "DENY", extra
        assert decision["reason_code"] == "envelope_invalid", extra
        record = host.decision_records()[-1]
        names = [check["name"] for check in record["checks"]]
        assert "envelope_keys" in names
        assert "evaluate" not in names
        assert "registry_tool" not in names
        _assert_record_claims_only_what_ran(record)
    with pytest.raises(ProtocolError) as caught:
        parse_host_request({"tool_name": "echo.ping", "args": ARGS, "please_allow": True})
    assert caught.value.reason == "agent_prose_rejected"


def test_library_unknown_invoke_and_schema_keys_stay_denied():
    invoke = evaluate(
        {
            "caller": {"identity": "lab.demo.agent"},
            "envelope_version": "1.0",
            "invoke": {"tool_name": "echo.ping", "argv": [], "schema_fields": {}, "extra": 1},
            "pep_eval_id": "host-regression-invoke",
        }
    )
    schema = evaluate(
        {
            "caller": {"identity": "lab.demo.agent"},
            "envelope_version": "1.0",
            "invoke": {
                "tool_name": "echo.ping",
                "argv": [],
                "schema_fields": {"capability_token": "lab.cap.echo.demo", "extra": 1},
            },
            "pep_eval_id": "host-regression-schema",
        }
    )
    assert invoke.receipt.reason_code == "envelope_invalid"
    assert schema.receipt.reason_code == "envelope_invalid"


def test_missing_halt_file_is_halted_and_not_written_active(tmp_path: Path):
    host = _host(tmp_path, init=False)
    session = host.open_session(_peer())
    decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "kill_active"
    assert not host.halt_path.exists()
    records = host.decision_records()
    assert records[-1]["reason_code"] == "kill_active"
    assert records[-1]["checks"] == [{"name": "halt_file", "outcome": "deny", "observed": "missing"}]
    _assert_record_claims_only_what_ran(records[-1])


def test_unreadable_halt_file_is_halted(tmp_path: Path):
    halt = tmp_path / "halt.json"
    halt.mkdir()
    host = ReferenceHost(halt_path=halt, log_path=tmp_path / "decisions.log")
    session = host.open_session(_peer())
    decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert decision["reason_code"] == "kill_active"
    assert host.decision_records()[-1]["checks"][0]["observed"] == "not_a_file"


def test_deleting_the_halt_file_does_not_resume(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    assert host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)["decision"] == "ALLOW"
    host.halt_path.unlink()
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "kill_active"
    assert calls == ["registry"]

    log_path = host.log_path
    host.close()
    restarted = ReferenceHost(
        halt_path=tmp_path / "halt.json",
        log_path=log_path,
        registry={"echo.ping": registered},
    )
    again = restarted.handle_request(
        {"tool_name": "echo.ping", "args": ARGS},
        restarted.open_session(_peer(pid=11)),
    )
    assert again["reason_code"] == "kill_active"
    if (tmp_path / "halt.json").exists():
        _state, observed = read_fail_closed(tmp_path / "halt.json")
        assert observed != ACTIVE
    assert calls == ["registry"]


def test_failed_kill_write_leaves_the_gate_halted(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    host.halt_path.unlink()
    host.halt_path.mkdir()
    with pytest.raises(HaltStoreError):
        host.kill()
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "kill_active"
    assert calls == []
    assert host.halted()


def test_session_b_cannot_act_as_session_a(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session_a = host.open_session(_peer(pid=10, uid=1000))
    session_b = host.open_session(_peer(pid=11, uid=1000))
    assert session_a.principal != session_b.principal
    host.issue_session_approval(session_a, tool_name="echo.ping", args=ARGS, ttl_seconds=60)

    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session_a)
    assert allowed["decision"] == "ALLOW"
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session_b)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] != "allowed"
    stolen = host.handle_request(
        {
            "tool_name": "echo.ping",
            "args": ARGS,
            "caller_identity": session_a.principal,
            "principal": session_a.principal,
            "session_id": session_a.principal,
        },
        session_b,
    )
    assert stolen["decision"] == "DENY"
    assert stolen["reason_code"] == "envelope_invalid"
    assert calls == ["registry"]

    deny_lines = [
        record
        for record in host.decision_records()
        if record["decision"] == "DENY" and record["session_id"] == session_b.principal
    ]
    assert deny_lines
    assert deny_lines[0]["peer_uid"] == 1000
    for record in host.decision_records():
        _assert_record_claims_only_what_ran(record)
    mode = host.log_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_socket_binds_identity_to_the_connection(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    os.chmod(sock_dir, 0o2750)
    halt = tmp_path / "halt.json"
    init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=sock_dir / "pep.sock",
        registry={"echo.ping": registered},
        idle_timeout=30,
    )
    host.serve_in_background()
    client_a: socket.socket | None = None
    client_b: socket.socket | None = None
    try:
        client_a = _connect(host.socket_path)
        _wait_sessions(host, 1)
        session_a = host.sessions()[0]
        assert session_a.peer.uid == os.getuid()
        host.issue_session_approval(session_a, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        _send(client_a, {"tool_name": "echo.ping", "args": ARGS})
        allowed = _recv(client_a)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result_origin"] == "host-registry"

        client_b = _connect(host.socket_path)
        _wait_sessions(host, 2)
        session_b = host.sessions()[1]
        assert session_b.principal != session_a.principal
        _send(client_b, {"tool_name": "echo.ping", "args": ARGS})
        denied = _recv(client_b)
        assert denied["decision"] == "DENY"
        _send(
            client_b,
            {
                "tool_name": "echo.ping",
                "args": ARGS,
                "uid": 0,
                "principal": session_a.principal,
                "session_id": session_a.principal,
            },
        )
        stolen = _recv(client_b)
        assert stolen["decision"] == "DENY"
        assert stolen["reason_code"] == "envelope_invalid"
        assert calls == ["registry"]
        sock_info = host.socket_path.lstat()
        assert stat.S_ISSOCK(sock_info.st_mode)
        assert stat.S_IMODE(sock_info.st_mode) == SOCKET_MODE
        assert sock_info.st_uid == os.getuid()
        assert sock_info.st_gid == sock_dir.stat().st_gid

        denies = [
            record
            for record in host.decision_records()
            if record["decision"] == "DENY" and record.get("session_id") == session_b.principal
        ]
        assert denies
        assert all(record.get("peer_uid") == os.getuid() for record in denies)
        for record in denies:
            _assert_record_claims_only_what_ran(record)
        # A request that asks to delete the log is not a command, and the deny stays.
        before = host.log_path.read_text(encoding="utf-8")
        _send(client_b, {"tool_name": "echo.ping", "args": ARGS, "op": "delete_log"})
        assert _recv(client_b)["reason_code"] == "envelope_invalid"
        after = host.log_path.read_text(encoding="utf-8")
        assert before in after
        assert host.log_path.exists()
    finally:
        if client_a is not None:
            client_a.close()
        if client_b is not None:
            client_b.close()
        host.close()


def _connect(path: Path | None) -> socket.socket:
    assert path is not None
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(path))
    return client


def _wait_sessions(host: ReferenceHost, count: int) -> None:
    deadline = time.time() + 2
    while time.time() < deadline:
        if len(host.sessions()) >= count:
            return
        time.sleep(0.01)
    raise AssertionError(f"expected {count} sessions, saw {len(host.sessions())}")


def _send(client: socket.socket, payload: dict) -> None:
    client.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def _recv(client: socket.socket) -> dict:
    buf = b""
    client.settimeout(2)
    while b"\n" not in buf:
        chunk = client.recv(4096)
        if not chunk:
            break
        buf += chunk
    return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))


def _listen(tmp_path: Path, **kwargs: Any) -> ReferenceHost:
    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    os.chmod(sock_dir, 0o2750)
    halt = tmp_path / "halt.json"
    init_active(halt)
    idle = kwargs.pop("idle_timeout", 30)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=sock_dir / "pep.sock",
        idle_timeout=idle,
        **kwargs,
    )
    host.serve_in_background()
    return host


def test_kill_after_the_first_halt_check_stops_the_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    real = read_fail_closed
    seen = {"n": 0}

    def wrapped(path: Path):
        seen["n"] += 1
        if seen["n"] >= 2:
            HaltStore(path).write(HaltState(mode=HaltMode.KILLED, available=True))
        return real(path)

    monkeypatch.setattr("pep.host.server.read_fail_closed", wrapped)
    decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "kill_active"
    assert calls == []
    denies = [record for record in host.decision_records() if record["decision"] == "DENY"]
    assert denies
    assert denies[-1]["checks"][0]["observed"] == "killed"
    assert "request_id" in denies[-1]
    _assert_record_claims_only_what_ran(denies[-1])


def test_allow_log_carries_the_tool_outcome_and_a_request_id(tmp_path: Path):
    host = _host(tmp_path)
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert allowed["decision"] == "ALLOW"
    assert allowed["request_id"].startswith("host.")
    allows = [record for record in host.decision_records() if record["decision"] == "ALLOW"]
    assert allows
    assert allows[-1]["request_id"] == allowed["request_id"]
    assert {"name": "registry_tool", "outcome": "entered"} in allows[-1]["checks"]
    pre = [record for record in host.decision_records() if record["decision"] == "PRE_ENTRY"]
    assert pre and pre[0]["request_id"] == allowed["request_id"]
    for record in host.decision_records():
        _assert_record_claims_only_what_ran(record)


def test_tool_exception_is_not_logged_as_a_policy_miss(tmp_path: Path):
    def registered(_args: dict) -> dict:
        raise RuntimeError("boom")

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "tool_failed"
    assert host.decision_records()[-1]["reason_code"] == "tool_failed"
    assert host.decision_records()[-1]["request_id"] == denied["request_id"]


def test_deeply_nested_json_is_denied_and_logged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    host = _host(tmp_path)
    session = host.open_session(_peer())
    denied = host.handle_request(b"[" * 60_000, session)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "envelope_invalid"
    assert host.decision_records()[-1]["decision"] == "DENY"
    assert host.decision_records()[-1]["request_id"] == denied["request_id"]

    def boom(_raw: object) -> tuple[str, dict, list]:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr("pep.host.server.parse_host_request", boom)
    crashed = host.handle_request(b"{}", session)
    assert crashed["decision"] == "DENY"
    assert host.decision_records()[-1]["decision"] == "DENY"


def test_nested_json_on_the_socket_gets_a_deny(tmp_path: Path):
    host = _listen(tmp_path)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        client.sendall(b"[" * 60_000 + b"\n")
        reply = _recv(client)
        assert reply["decision"] == "DENY"
        assert any(record["decision"] == "DENY" for record in host.decision_records())
    finally:
        client.close()
        host.close()


def test_connection_cap_denies_the_extra_client(tmp_path: Path):
    host = _listen(tmp_path, max_connections=1)
    first: socket.socket | None = None
    second: socket.socket | None = None
    try:
        first = _connect(host.socket_path)
        _wait_sessions(host, 1)
        second = _connect(host.socket_path)
        denied = _recv(second)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "connection_limit"
        assert len(host.sessions()) == 1
    finally:
        if first is not None:
            first.close()
        if second is not None:
            second.close()
        host.close()


def test_idle_connection_is_closed_and_the_session_is_dropped(tmp_path: Path):
    host = _listen(tmp_path, idle_timeout=0.4)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        reply = _recv(client)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "idle_timeout"
        deadline = time.time() + 2
        while time.time() < deadline and host.sessions():
            time.sleep(0.01)
        assert host.sessions() == ()
        assert any(record["reason_code"] == "idle_timeout" for record in host.decision_records())
    finally:
        client.close()
        host.close()


def test_denial_log_is_coalesced(tmp_path: Path):
    clock = _Mono()
    window = 10.0
    host = _host(tmp_path, deny_log_burst=2, deny_log_window=window, monotonic=clock)
    session = host.open_session(_peer())

    def deny() -> dict:
        decision = host.handle_request(b"[]", session)
        assert decision["decision"] == "DENY"
        assert decision["reason_code"] == "envelope_invalid"
        return decision

    clock.now = 0.0
    for _ in range(2):
        deny()
    for _ in range(3):
        deny()
    records = host.decision_records()
    assert len(records) == 2
    assert all(record["reason_code"] != "rate_limited" for record in records)

    clock.now = window / 2
    for _ in range(2):
        deny()
    records = host.decision_records()
    assert len(records) == 2
    assert all(record["reason_code"] != "rate_limited" for record in records)

    clock.now = window
    deny()
    records = host.decision_records()
    summaries = [record for record in records if record["reason_code"] == "rate_limited"]
    assert len(summaries) == 1
    assert summaries[0]["suppressed_count"] == 5
    assert len(records) == 4

    deny()
    for _ in range(4):
        deny()
    summaries = [record for record in host.decision_records() if record["reason_code"] == "rate_limited"]
    assert len(summaries) == 1

    host.close()
    records = host.decision_records()
    summaries = [record for record in records if record["reason_code"] == "rate_limited"]
    assert [record["suppressed_count"] for record in summaries] == [5, 4]
    assert host.halted() is False
    for record in records:
        _assert_record_claims_only_what_ran(record)


def test_held_count_flushes_when_the_window_closes_without_another_denial(tmp_path: Path):
    clock = _Mono()
    host = _host(tmp_path, deny_log_burst=2, deny_log_window=10, monotonic=clock)
    session = host.open_session(_peer())
    for _ in range(5):
        denied = host.handle_request(b"[]", session)
        assert denied["decision"] == "DENY"
    assert all(record["reason_code"] != "rate_limited" for record in host.decision_records())

    clock.now = 10
    host._flush_expired_window()
    records = host.decision_records()
    summaries = [record for record in records if record["reason_code"] == "rate_limited"]
    assert [record["suppressed_count"] for record in summaries] == [3]
    assert _denial_tally(records) == 5
    assert host.halted() is False
    host.close()
    assert [record["suppressed_count"] for record in host.decision_records() if record["reason_code"] == "rate_limited"] == [3]


def test_quiet_flood_flushes_from_the_accept_loop(tmp_path: Path):
    host = _listen(tmp_path, deny_log_burst=2, deny_log_window=1.0)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        for _ in range(5):
            client.sendall(b"[]\n")
            reply = _recv(client)
            assert reply["decision"] == "DENY"
            assert reply["reason_code"] == "envelope_invalid"
        deadline = time.monotonic() + 3
        records: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            try:
                records = host.decision_records()
            except (json.JSONDecodeError, DecisionLogError, OSError, UnicodeError):
                time.sleep(0.05)
                continue
            if _denial_tally(records) == 5 and any(record["reason_code"] == "rate_limited" for record in records):
                break
            time.sleep(0.05)
        assert _denial_tally(records) == 5
        summaries = [record for record in records if record["reason_code"] == "rate_limited"]
        assert sum(record["suppressed_count"] for record in summaries) == 3
        assert host.sessions()
        for record in records:
            _assert_record_claims_only_what_ran(record)
    finally:
        client.close()
        host.close()


def test_denial_in_flight_at_shutdown_is_folded_into_the_summary(tmp_path: Path):
    class _Clock:
        def __init__(self) -> None:
            self.calls = 0
            self.entered = threading.Event()
            self.release = threading.Event()

        def __call__(self) -> datetime:
            self.calls += 1
            if self.calls >= 5:
                self.entered.set()
                self.release.wait(timeout=5)
            return NOW

    clock = _Clock()
    host = _host(tmp_path, clock=clock, deny_log_burst=2, deny_log_window=60)
    session = host.open_session(_peer())
    for _ in range(4):
        denied = host.handle_request(b"[]", session)
        assert denied["reason_code"] == "envelope_invalid"
    assert all(record["reason_code"] != "rate_limited" for record in host.decision_records())

    box: list[dict[str, Any]] = []

    def call() -> None:
        box.append(host.handle_request(b"[]", session))

    worker = threading.Thread(target=call)
    closer = threading.Thread(target=host.close)
    worker.start()
    try:
        assert clock.entered.wait(timeout=2)
        closer.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not closer.is_alive():
            time.sleep(0.01)
        time.sleep(0.05)
        assert closer.is_alive()
    finally:
        clock.release.set()
        worker.join(timeout=5)
        closer.join(timeout=5)
    assert not worker.is_alive()
    assert not closer.is_alive()
    assert box[0]["decision"] == "DENY"
    assert box[0]["reason_code"] == "envelope_invalid"
    records = host.decision_records()
    summaries = [record for record in records if record["reason_code"] == "rate_limited"]
    assert [record["suppressed_count"] for record in summaries] == [3]
    assert _denial_tally(records) == 5
    for record in records:
        _assert_record_claims_only_what_ran(record)


@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGHUP])
def test_stop_signal_flushes_held_denial_counts(tmp_path: Path, stop_signal: int):
    os.chmod(tmp_path, 0o700)
    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    os.chmod(sock_dir, 0o2750)
    halt = tmp_path / "halt.json"
    log_path = tmp_path / "decisions.log"
    sock = sock_dir / "pep.sock"
    init_active(halt)
    err_path = tmp_path / "serve.err"
    root = str(Path(__file__).resolve().parents[1])
    env = os.environ.copy()
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    with err_path.open("w", encoding="utf-8") as err:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "pep.host",
                "serve",
                "--socket",
                str(sock),
                "--halt",
                str(halt),
                "--log",
                str(log_path),
            ],
            cwd=root,
            env=env,
            stdout=err,
            stderr=subprocess.STDOUT,
        )
    client: socket.socket | None = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if sock.exists():
                try:
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(str(sock))
                    break
                except OSError:
                    if client is not None:
                        client.close()
                        client = None
                    time.sleep(0.02)
            else:
                if proc.poll() is not None:
                    break
                time.sleep(0.02)
        assert client is not None, err_path.read_text(encoding="utf-8")
        sent = 80
        payload = b"[]\n" * sent
        client.sendall(payload)
        client.settimeout(5)
        buf = b""
        replies = 0
        while replies < sent:
            chunk = client.recv(65536)
            assert chunk, err_path.read_text(encoding="utf-8")
            buf += chunk
            while b"\n" in buf and replies < sent:
                line, buf = buf.split(b"\n", 1)
                reply = json.loads(line)
                assert reply["decision"] == "DENY"
                replies += 1
        client.close()
        client = None
        proc.send_signal(stop_signal)
        assert proc.wait(timeout=5) == 0, err_path.read_text(encoding="utf-8")
    finally:
        if client is not None:
            client.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    records = _load_log(log_path)
    assert _denial_tally(records) == 80
    assert any(record["reason_code"] == "rate_limited" for record in records)
    for record in records:
        _assert_record_claims_only_what_ran(record)


def test_socket_open_without_a_path_raises_host_error(tmp_path: Path):
    host = _host(tmp_path)
    host.socket_path = None
    with pytest.raises(HostError, match="socket path is required"):
        host._open_agent_socket()
    host.admin_path = None
    with pytest.raises(HostError, match="admin socket path is required"):
        host._open_admin_socket()


def test_reconnect_needs_a_free_slot_and_is_a_new_session(tmp_path: Path):
    host = _listen(tmp_path, max_connections=1)
    held = _connect(host.socket_path)
    extra: socket.socket | None = None
    again: socket.socket | None = None
    try:
        _wait_sessions(host, 1)
        first_id = host.sessions()[0].connection_id
        extra = _connect(host.socket_path)
        denied = _recv(extra)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "connection_limit"
        extra.close()
        extra = None
        held.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and host.sessions():
            time.sleep(0.01)
        assert host.sessions() == ()
        again = _connect(host.socket_path)
        _wait_sessions(host, 1)
        assert host.sessions()[0].connection_id != first_id
        _send(again, {"tool_name": "echo.ping", "args": ARGS})
        reply = _recv(again)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] != "connection_limit"
    finally:
        held.close()
        if extra is not None:
            extra.close()
        if again is not None:
            again.close()
        host.close()


def test_admitted_denials_are_logged_during_a_flood(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = _Mono()

    def boom(_args: dict) -> dict:
        raise RuntimeError("boom")

    host = _host(
        tmp_path,
        registry={"echo.ping": boom},
        monotonic=clock,
        deny_log_burst=1,
        deny_log_window=10,
    )
    session = host.open_session(_peer())
    clock.now = 0.0
    for _ in range(5):
        denied = host.handle_request(b"[]", session)
        assert denied["reason_code"] == "envelope_invalid"
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    failed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert failed["reason_code"] == "tool_failed"
    assert any(record["reason_code"] == "tool_failed" for record in host.decision_records())

    real = read_fail_closed
    seen = {"n": 0}

    def wrapped(path: Path):
        seen["n"] += 1
        if seen["n"] >= 2:
            HaltStore(path).write(HaltState(mode=HaltMode.KILLED, available=True))
        return real(path)

    monkeypatch.setattr("pep.host.server.read_fail_closed", wrapped)
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    halted = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert halted["reason_code"] == "kill_active"
    assert any(
        record["reason_code"] == "kill_active" and record["checks"][0].get("observed") == "killed"
        for record in host.decision_records()
    )
    host.close()
    summaries = [record for record in host.decision_records() if record["reason_code"] == "rate_limited"]
    assert summaries
    assert summaries[0]["suppressed_count"] == 4
    for record in host.decision_records():
        _assert_record_claims_only_what_ran(record)


def test_decision_log_checks_the_file_before_fchmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "decisions.log"
    path.write_text("")
    order: list[str] = []
    real_fstat = os.fstat
    real_fchmod = os.fchmod

    def fstat(fd: int):
        order.append("fstat")
        return real_fstat(fd)

    def fchmod(fd: int, mode: int) -> None:
        order.append("fchmod")
        real_fchmod(fd, mode)

    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "fchmod", fchmod)
    DecisionLog(path)
    assert order.index("fstat") < order.index("fchmod")


def test_decision_log_refuses_a_file_over_the_startup_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "decisions.log"
    path.write_text("x" * 64)
    monkeypatch.setattr("pep.host.log.MAX_LOG_STARTUP_BYTES", 32)
    with pytest.raises(DecisionLogError, match="startup read limit"):
        DecisionLog(path)
    assert MAX_LOG_STARTUP_BYTES == 1_048_576


def test_decision_log_streams_many_short_lines_past_the_line_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("pep.host.log.MAX_LOG_STARTUP_BYTES", 32)
    path = tmp_path / "decisions.log"
    line = b'{"decision":"DENY"}\n'
    assert len(line) < 32
    path.write_bytes(line * 3 + b"\n\n")
    log = DecisionLog(path)
    stored = log.append(
        {
            "decision": "DENY",
            "reason_code": "envelope_invalid",
            "reason_detail": "x",
            "checks": [{"name": "json_object", "outcome": "deny"}],
        }
    )
    assert stored["seq"] == 4
    log.close()


def test_host_restarts_when_the_decision_log_exceeds_one_mebibyte(tmp_path: Path):
    path = tmp_path / "decisions.log"
    seed = {
        "decision": "DENY",
        "reason_code": "envelope_invalid",
        "reason_detail": "seed",
        "checks": [{"name": "json_object", "outcome": "deny"}],
    }
    line = (json.dumps(seed, separators=(",", ":")) + "\n").encode("utf-8")
    count = (MAX_LOG_STARTUP_BYTES // len(line)) + 5
    path.write_bytes(line * count)
    assert path.stat().st_size > MAX_LOG_STARTUP_BYTES
    halt = tmp_path / "halt.json"
    init_active(halt)
    host = ReferenceHost(halt_path=halt, log_path=path)
    try:
        session = host.open_session(_peer())
        denied = host.handle_request(b"[]", session)
        assert denied["decision"] == "DENY"
        last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
        assert last["seq"] == count + 1
        assert last["reason_code"] == "envelope_invalid"
    finally:
        host.close()


def test_decision_log_refuses_a_symlink_and_does_not_chmod_the_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "elsewhere.log"
    link = tmp_path / "decisions.log"
    link.symlink_to(target)
    with pytest.raises(DecisionLogError):
        DecisionLog(link)
    assert not target.exists()

    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("chmod on the path")

    monkeypatch.setattr(os, "chmod", boom)
    log = DecisionLog(tmp_path / "real.log")
    log.append(
        {
            "decision": "DENY",
            "reason_code": "envelope_invalid",
            "reason_detail": "x",
            "checks": [{"name": "json_object", "outcome": "deny"}],
        }
    )
    assert (tmp_path / "real.log").stat().st_mode & 0o777 == 0o600
    init_active(tmp_path / "halt.json")
    assert (tmp_path / "halt.json").stat().st_mode & 0o777 == 0o600


def test_halt_read_uses_the_bytes_from_one_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "halt.json"
    init_active(path)
    HaltStore(path).write(HaltState(mode=HaltMode.KILLED, available=True))

    def boom(self: HaltStore) -> HaltState:
        raise AssertionError("halt file was read a second time")

    monkeypatch.setattr(HaltStore, "read", boom)
    _state, observed = read_fail_closed(path)
    assert observed == "killed"


def test_loose_halt_and_log_directories_are_refused(tmp_path: Path):
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o755)
    with pytest.raises(DecisionLogError):
        DecisionLog(loose / "decisions.log")
    with pytest.raises(HostError):
        ReferenceHost(halt_path=loose / "halt.json", log_path=tmp_path / "decisions.log")


def test_group_writable_socket_directory_is_refused(tmp_path: Path):
    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    os.chmod(sock_dir, 0o770)
    halt = tmp_path / "halt.json"
    init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=sock_dir / "pep.sock",
    )
    with pytest.raises(HostError, match="writable"):
        host.serve_in_background()
    assert not (sock_dir / "pep.sock").exists()


def test_live_socket_is_not_replaced(tmp_path: Path):
    host = _listen(tmp_path)
    other_halt = tmp_path / "other-halt.json"
    init_active(other_halt)
    second = ReferenceHost(
        halt_path=other_halt,
        log_path=tmp_path / "other.log",
        socket_path=host.socket_path,
    )
    try:
        with pytest.raises(HostError, match="already listening"):
            second.serve_in_background()
        client = _connect(host.socket_path)
        try:
            _wait_sessions(host, 1)
            _send(client, {"tool_name": "echo.ping", "args": ARGS})
            assert _recv(client)["decision"] == "DENY"
        finally:
            client.close()
    finally:
        host.close()


def test_stale_socket_is_replaced_and_a_non_socket_is_not(tmp_path: Path):
    sock_dir = tmp_path / "run"
    sock_dir.mkdir()
    os.chmod(sock_dir, 0o750)
    stale = sock_dir / "pep.sock"
    leftover = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    leftover.bind(str(stale))
    leftover.close()
    host = _listen_at(tmp_path, stale)
    client = _connect(stale)
    client.close()
    host.close()

    blocked = sock_dir / "blocked.sock"
    blocked.write_text("keep", encoding="utf-8")
    halt = tmp_path / "halt.json"
    refused = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=blocked,
    )
    with pytest.raises(HostError, match="not a socket"):
        refused.serve_in_background()
    assert blocked.read_text(encoding="utf-8") == "keep"

    link = sock_dir / "link.sock"
    link.symlink_to(stale)
    linked = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=link,
    )
    with pytest.raises(HostError, match="symlink"):
        linked.serve_in_background()
    assert link.is_symlink()


def test_client_denies_a_reply_without_a_decision(tmp_path: Path):
    path = tmp_path / "reply.sock"

    def serve(payload: bytes, ready: threading.Event) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(2)
        listener.bind(str(path))
        listener.listen(1)
        ready.set()
        conn, _addr = listener.accept()
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            conn.sendall(payload)
        finally:
            conn.close()
            listener.close()

    for payload in (b'{"ok":true}\n', b'{"decision":"MAYBE"}\n'):
        if path.exists():
            path.unlink()
        ready = threading.Event()
        thread = threading.Thread(target=serve, args=(payload, ready), daemon=True)
        thread.start()
        assert ready.wait(timeout=2)
        try:
            reply = invoke(path, "echo.ping", ARGS, host_uid=os.getuid(), timeout=2)
        finally:
            thread.join(timeout=2)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "envelope_invalid"
        assert "decision" in reply["reason_detail"]


def test_connection_deadline_closes_a_slow_drip(tmp_path: Path):
    clock = _Mono()
    host = _listen(tmp_path, monotonic=clock, connection_deadline=10, idle_timeout=30)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        deadline = time.time() + 2
        while time.time() < deadline and clock.calls < 2:
            time.sleep(0.01)
        assert clock.calls >= 2
        clock.now = 10
        client.sendall(b"x")
        reply = _recv(client)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "connection_deadline"
        assert any(record["reason_code"] == "connection_deadline" for record in host.decision_records())
    finally:
        client.close()
        host.close()


def test_client_denies_when_the_host_is_down_or_the_peer_is_wrong(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    missing = invoke(tmp_path / "missing.sock", "echo.ping", ARGS, host_uid=os.getuid())
    assert missing["decision"] == "DENY"
    assert missing["reason_code"] == "host_unreachable"

    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    host = _listen(tmp_path, registry={"echo.ping": registered})
    try:
        wrong_owner = invoke(host.socket_path, "echo.ping", ARGS, host_uid=os.getuid() + 1)
        assert wrong_owner["decision"] == "DENY"
        assert wrong_owner["reason_code"] == "host_unattested"
        monkeypatch.setattr(
            "pep.host.client.peer_credentials",
            lambda _conn: PeerCred(pid=1, uid=os.getuid() + 1, gid=os.getuid()),
        )
        wrong_peer = invoke(host.socket_path, "echo.ping", ARGS, host_uid=os.getuid())
        assert wrong_peer["decision"] == "DENY"
        assert wrong_peer["reason_code"] == "host_unattested"
        assert calls == []
    finally:
        host.close()


def test_allow_list_rejects_a_peer_and_logs_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    host = _host(tmp_path, allowed_uids={os.getuid() + 1})
    assert host.peer_permitted(_peer(uid=os.getuid())) is False
    assert host.peer_permitted(PeerCred(pid=1, uid=os.getuid() + 1, gid=1000)) is True

    def fake(conn: socket.socket) -> PeerCred:
        cred = peer_credentials_real(conn)
        return PeerCred(pid=cred.pid, uid=cred.uid + 1, gid=cred.gid)

    from pep.host.server import peer_credentials as peer_credentials_real

    monkeypatch.setattr("pep.host.server.peer_credentials", fake)
    listening = _listen(tmp_path, allowed_uids=frozenset({os.getuid()}))
    client = _connect(listening.socket_path)
    try:
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "peer_rejected"
        assert listening.decision_records()[-1]["reason_code"] == "peer_rejected"
        assert listening.sessions() == ()
    finally:
        client.close()
        listening.close()


def test_admin_grant_allows_the_held_connection(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok"}

    admin = tmp_path / "admin.sock"
    host = _listen(tmp_path, registry={"echo.ping": registered}, admin_path=admin)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        assert stat.S_IMODE(admin.stat().st_mode) == 0o600
        listed = io.StringIO()
        with redirect_stdout(listed):
            assert main(["sessions", "--admin", str(admin)]) == 0
        connection_id = json.loads(listed.getvalue())["sessions"][0]["connection_id"]
        granted = io.StringIO()
        with redirect_stdout(granted):
            assert (
                main(
                    [
                        "grant",
                        "--admin",
                        str(admin),
                        "--connection",
                        str(connection_id),
                        "--tool",
                        "echo.ping",
                        "--args",
                        json.dumps(ARGS),
                        "--ttl",
                        "60",
                    ]
                )
                == 0
            )
        _send(client, {"tool_name": "echo.ping", "args": ARGS})
        allowed = _recv(client)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result_origin"] == "host-registry"
        assert calls == ["registry"]
        _send(client, {"op": "grant", "tool_name": "echo.ping", "args": ARGS})
        assert _recv(client)["reason_code"] == "envelope_invalid"
        assert calls == ["registry"]
    finally:
        client.close()
        host.close()


def test_suspended_halt_at_startup_is_not_latched(tmp_path: Path):
    halt = tmp_path / "halt.json"
    HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED, available=True))
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        registry={"echo.ping": lambda _args: {"pong": "ok"}},
    )
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["reason_code"] == "suspend_active"
    HaltStore(halt).write(HaltState(mode=HaltMode.ACTIVE, available=True))
    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert allowed["decision"] == "ALLOW"


def test_halt_file_vanishing_at_startup_is_not_left_active(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "halt.json"
    init_active(path)
    real_init = PepRuntime.__init__

    def wrapped(self: PepRuntime, *args: object, **kwargs: object) -> None:
        if path.exists():
            path.unlink()
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(PepRuntime, "__init__", wrapped)
    host = ReferenceHost(halt_path=path, log_path=tmp_path / "decisions.log")
    assert host.halted()
    assert path.exists()
    _state, observed = read_fail_closed(path)
    assert observed == "killed"


def _listen_at(tmp_path: Path, socket_path: Path) -> ReferenceHost:
    halt = tmp_path / "halt.json"
    if not halt.exists():
        init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=socket_path,
        idle_timeout=30,
    )
    host.serve_in_background()
    return host
