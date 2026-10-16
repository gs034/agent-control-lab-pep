# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Reference host regressions for the separate policy enforcement point.

These checks correspond to the gaps where the in-process library trusts
its caller: the callable, the clock, the identity, unknown envelope keys,
a halt file that can be deleted, and a decision that only the caller kept.
"""

from __future__ import annotations

import ctypes
import errno
import io
import json
import mmap
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
from pep.policy import STUB_POLICY_DOCUMENT
from pep.host.__main__ import main
from pep.host.client import AgentConnection, invoke
from pep.host.haltfile import ACTIVE, init_active, read_fail_closed
from pep.host.log import FORBIDDEN_KEYS, MAX_LOG_STARTUP_BYTES, DecisionLog, DecisionLogError
from pep.host.protocol import ProtocolError, parse_host_request
from pep.host.fsguard import file_owner
from pep.host.server import SOCKET_MODE, HostError, PeerCred, ReferenceHost, peer_credentials

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


def _agent_uid() -> int:
    """A user id that is neither root nor the process running the tests."""
    candidate = os.getuid() + 1
    if candidate == 0:
        return 2
    return candidate


def _inject_agent_peer(
    host: ReferenceHost,
    uid: int | None = None,
    admin_path: Path | None = None,
) -> int:
    """Make this host see a non-host uid on the agent socket.

    The test process is the host user, so a real peer credential would be
    refused. This substitutes an id for the logic under test. Connections
    to ``admin_path`` keep the kernel credential, so an in-process operator
    command still looks like the host user.
    """
    agent = _agent_uid() if uid is None else uid
    admin_name = None if admin_path is None else os.path.abspath(admin_path)

    def _peer_of(conn: socket.socket) -> PeerCred:
        cred = peer_credentials(conn)
        if admin_name is not None:
            try:
                name = conn.getsockname()
            except OSError:
                name = ""
            if isinstance(name, bytes):
                name = os.fsdecode(name)
            if os.path.abspath(str(name)) == admin_name:
                return cred
        return PeerCred(pid=cred.pid, uid=agent, gid=cred.gid)

    host._peer_of = _peer_of  # type: ignore[method-assign]
    return agent


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
        return {"pong": args["message"], "ran": "registry"}

    def attacker(*_args: object, **_kwargs: object) -> dict:
        calls.append("attacker")
        return {"pwned": True}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)

    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert allowed["decision"] == "ALLOW"
    assert allowed["result"] == {"pong": "hi", "ran": "registry"}
    assert allowed["result_origin"] == "host-registry"
    # The registry function ran in the executor. This process's list is unchanged.
    assert calls == []

    denied = host.handle_request(
        {"tool_name": "echo.ping", "args": ARGS, "tool": attacker},
        session,
    )
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "envelope_invalid"
    assert calls == []

    with pytest.raises(TypeError):
        host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session, tool=attacker)  # type: ignore[call-arg]
    assert calls == []

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
    allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert allowed["decision"] == "ALLOW"
    assert allowed["result"] == {"pong": "ok"}
    assert calls == []
    host.halt_path.unlink()
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["decision"] == "DENY"
    assert denied["reason_code"] == "kill_active"
    assert calls == []

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
    assert calls == []


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
    assert allowed["result"] == {"pong": "ok"}
    assert calls == []
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
    assert calls == []

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
        allowed_uids=frozenset({_agent_uid()}),
    )
    agent_uid = _inject_agent_peer(host)
    host.serve_in_background()
    client_a: socket.socket | None = None
    client_b: socket.socket | None = None
    try:
        client_a = _connect(host.socket_path)
        _wait_sessions(host, 1)
        session_a = host.sessions()[0]
        assert session_a.peer.uid == agent_uid
        host.issue_session_approval(session_a, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        _send(client_a, {"tool_name": "echo.ping", "args": ARGS})
        allowed = _recv(client_a)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result"] == {"pong": "ok"}
        assert allowed["result_origin"] == "host-registry"
        assert calls == []

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
        assert calls == []
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
        assert all(record.get("peer_uid") == agent_uid for record in denies)
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


def _records_after_session_closes(host: ReferenceHost) -> list[dict[str, Any]]:
    """Log lines once the served connection has written open and close."""
    deadline = time.time() + 2
    while time.time() < deadline:
        if host.sessions():
            time.sleep(0.01)
            continue
        try:
            records = host.decision_records()
        except (json.JSONDecodeError, DecisionLogError, OSError, UnicodeError):
            time.sleep(0.01)
            continue
        decisions = [record.get("decision") for record in records]
        if "SESSION_OPEN" in decisions and "SESSION_CLOSE" in decisions:
            return records
        time.sleep(0.01)
    raise AssertionError("session did not close with open and close lines")


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
    admin_path = kwargs.get("admin_path")
    inject = "allowed_uids" not in kwargs and "allowed_gids" not in kwargs
    if inject:
        kwargs["allowed_uids"] = frozenset({_agent_uid()})
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=sock_dir / "pep.sock",
        idle_timeout=idle,
        **kwargs,
    )
    if inject:
        _inject_agent_peer(host, admin_path=admin_path if isinstance(admin_path, Path) else None)
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
                "--allow-uid",
                str(os.getuid() + 1),
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
        # This process is the host user, so each connection is refused
        # before it can send a request. Eighty connections still exercise
        # the denial window and the signal flush. The probe connection is
        # the first of those eighty.
        for index in range(80):
            reply = _recv(client)
            assert reply["decision"] == "DENY"
            client.close()
            client = None
            if index + 1 < 80:
                client = _connect(sock)
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
        allowed_uids=frozenset({_agent_uid()}),
    )
    try:
        with pytest.raises(HostError, match="writable"):
            host.serve_in_background()
    finally:
        host.close()
    assert not (sock_dir / "pep.sock").exists()


def test_live_socket_is_not_replaced(tmp_path: Path):
    host = _listen(tmp_path)
    other_halt = tmp_path / "other-halt.json"
    init_active(other_halt)
    second = ReferenceHost(
        halt_path=other_halt,
        log_path=tmp_path / "other.log",
        socket_path=host.socket_path,
        allowed_uids=frozenset({_agent_uid()}),
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
        second.close()
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
        allowed_uids=frozenset({_agent_uid()}),
    )
    try:
        with pytest.raises(HostError, match="not a socket"):
            refused.serve_in_background()
    finally:
        refused.close()
    assert blocked.read_text(encoding="utf-8") == "keep"

    link = sock_dir / "link.sock"
    link.symlink_to(stale)
    linked = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=link,
        allowed_uids=frozenset({_agent_uid()}),
    )
    try:
        with pytest.raises(HostError, match="symlink"):
            linked.serve_in_background()
    finally:
        linked.close()
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
        cred = peer_credentials(conn)
        return PeerCred(pid=cred.pid, uid=cred.uid + 2, gid=cred.gid)

    monkeypatch.setattr("pep.host.server.peer_credentials", fake)
    listening = _listen(tmp_path, allowed_uids=frozenset({os.getuid() + 1}))
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
        assert allowed["result"] == {"pong": "ok"}
        assert allowed["result_origin"] == "host-registry"
        assert calls == []
        _send(client, {"op": "grant", "tool_name": "echo.ping", "args": ARGS})
        assert _recv(client)["reason_code"] == "envelope_invalid"
        assert calls == []
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


def test_gate_resume_rewrite_does_not_lose_a_concurrent_kill(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """P-5: ``pep.host kill`` lands between the gate's resume read and its rename."""
    import pep.halt as halt_module
    from pep.host.haltfile import write_killed

    halt = tmp_path / "halt.json"
    HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED, available=True))
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        registry={"echo.ping": lambda _args: {"pong": "ok"}},
    )
    session = host.open_session(_peer())
    for _ in range(3):
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["reason_code"] == "suspend_active"
    HaltStore(halt).write(HaltState(mode=HaltMode.ACTIVE, available=True))

    real_merge = halt_module._merge_sticky_kill
    box: dict[str, Any] = {"armed": True}
    landed = threading.Event()

    def kill() -> None:
        try:
            write_killed(halt)
        except (HaltStoreError, OSError) as exc:
            box["error"] = exc
        finally:
            landed.set()

    def merge_after_kill(current, requested):  # type: ignore[no-untyped-def]
        if box.pop("armed", False):
            box["thread"] = threading.Thread(target=kill, daemon=True)
            box["thread"].start()
            landed.wait(timeout=1.0)
        return real_merge(current, requested)

    monkeypatch.setattr(halt_module, "_merge_sticky_kill", merge_after_kill)
    host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert "thread" in box, "the gate did not rewrite the halt file on resume"
    box["thread"].join(timeout=10)
    assert "error" not in box
    _state, observed = read_fail_closed(halt)
    assert observed == "killed"
    after = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert after["decision"] == "DENY"
    assert after["reason_code"] == "kill_active"


def _operator_acts_before_gate_lock(
    monkeypatch: pytest.MonkeyPatch, halt: Path, action: str
) -> dict[str, Any]:
    """P-8: run an operator change after the gate read the halt file, before its write locks.

    The hook runs once, in the gate's thread, at the start of the gate's
    locked write. The operator's own write takes the file lock itself, so the
    order is fixed: gate read, operator change, gate locked write.
    """
    import pep.halt as halt_module

    real_lock = halt_module.HaltStore._acquire_file_lock
    box: dict[str, Any] = {"armed": True}

    def operator_then_lock(self):  # type: ignore[no-untyped-def]
        if box.pop("armed", False):
            if action == "suspend":
                HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED, available=True))
            elif action == "resume":
                HaltStore(halt).write(HaltState(mode=HaltMode.ACTIVE, available=True))
            else:
                halt.unlink()
            box["operator_left"] = read_fail_closed(halt)[1]
        return real_lock(self)

    monkeypatch.setattr(halt_module.HaltStore, "_acquire_file_lock", operator_then_lock)
    return box


@pytest.mark.parametrize(("action", "expected"), [("suspend", "suspended"), ("delete", "missing")])
def test_gate_resume_rewrite_does_not_overwrite_an_operator_halt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, expected: str
):
    """P-8: a suspend or a delete between the gate's read and its resume write stays."""
    halt = tmp_path / "halt.json"
    HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED, available=True))
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        registry={"echo.ping": lambda _args: {"pong": "ok"}},
    )
    session = host.open_session(_peer())
    for _ in range(3):
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["reason_code"] == "suspend_active"
    HaltStore(halt).write(HaltState(mode=HaltMode.ACTIVE, available=True))

    box = _operator_acts_before_gate_lock(monkeypatch, halt, action)
    host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert "armed" not in box, "the gate did not reach a locked halt write on resume"
    assert box["operator_left"] == expected
    assert read_fail_closed(halt)[1] == expected
    after = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert after["decision"] == "DENY"
    assert after["reason_code"] == ("suspend_active" if action == "suspend" else "kill_active")
    assert read_fail_closed(halt)[1] != ACTIVE


@pytest.mark.parametrize(("action", "expected"), [("resume", "active"), ("delete", "missing")])
def test_gate_suspend_rewrite_does_not_overwrite_an_operator_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, expected: str
):
    """P-8: the suspend mirror does not undo a resume or recreate a deleted file as suspended."""
    halt = tmp_path / "halt.json"
    init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        registry={"echo.ping": lambda _args: {"pong": "ok"}},
    )
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED, available=True))

    box = _operator_acts_before_gate_lock(monkeypatch, halt, action)
    denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    assert denied["reason_code"] == "suspend_active"
    assert "armed" not in box, "the gate did not reach a locked halt write on suspend"
    assert box["operator_left"] == expected
    assert read_fail_closed(halt)[1] == expected
    after = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
    if action == "resume":
        assert after["decision"] == "ALLOW", after
    else:
        assert after["decision"] == "DENY"
        assert after["reason_code"] == "kill_active"


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
        allowed_uids=frozenset({_agent_uid()}),
    )
    _inject_agent_peer(host)
    host.serve_in_background()
    return host


def test_held_connection_is_allowed_only_once_the_operator_grants_it(tmp_path: Path):
    host = _listen(tmp_path)
    try:
        with AgentConnection(host.socket_path, host_uid=os.getuid()) as held:
            assert held.call("echo.ping", ARGS)["decision"] == "DENY"
            _wait_sessions(host, 1)
            session = host.sessions()[0]
            host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
            allowed = held.call("echo.ping", ARGS)
            assert allowed["decision"] == "ALLOW"
            assert held.call("echo.ping", {"message": "other"})["decision"] == "DENY"
    finally:
        host.close()


def test_held_connection_gives_deny_once_the_host_has_closed_it(tmp_path: Path):
    host = _listen(tmp_path)
    try:
        with AgentConnection(host.socket_path, host_uid=os.getuid()) as held:
            host.close()
            reply = held.call("echo.ping", ARGS)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "host_unreachable"
    finally:
        host.close()


def test_held_connection_refuses_a_host_owned_by_another_user(tmp_path: Path):
    host = _listen(tmp_path)
    try:
        with AgentConnection(host.socket_path, host_uid=os.getuid() + 1) as held:
            reply = held.call("echo.ping", ARGS)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "host_unattested"
    finally:
        host.close()


def test_held_connection_returns_deny_when_no_socket_can_be_opened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def no_descriptors(*_args: object, **_kwargs: object) -> None:
        raise OSError(24, "Too many open files")

    monkeypatch.setattr("pep.host.client._connect_attested", no_descriptors)
    with AgentConnection(tmp_path / "pep.sock", host_uid=os.getuid()) as held:
        reply = held.call("echo.ping", ARGS)
    assert reply["decision"] == "DENY"
    assert reply["reason_code"] == "host_unreachable"


def _private(path: Path) -> Path:
    path.mkdir(exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _policy_file(directory: Path) -> Path:
    _private(directory)
    path = directory / "policy.json"
    path.write_text(json.dumps(STUB_POLICY_DOCUMENT), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def test_root_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(HostError, match="root"):
        _host(tmp_path)
    monkeypatch.undo()

    nested = tmp_path / "real-uid"
    nested.mkdir()
    os.chmod(nested, 0o700)
    halt = nested / "halt.json"
    init_active(halt)
    monkeypatch.setattr(os, "getuid", lambda: 0)
    with pytest.raises(HostError, match="root"):
        ReferenceHost(halt_path=halt, log_path=nested / "decisions.log")
    assert main(["init-halt", "--halt", str(nested / "ignored.json")]) == 1


def test_agent_socket_refuses_the_host_user(tmp_path: Path):
    host = _listen(tmp_path, allowed_uids=frozenset({_agent_uid()}))
    client = _connect(host.socket_path)
    try:
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "peer_rejected"
        assert "host user" in denied["reason_detail"]
        assert host.decision_records()[-1]["peer_uid"] == os.getuid()
        assert host.sessions() == ()
    finally:
        client.close()
        host.close()


def test_agent_socket_refuses_a_root_peer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def root_peer(conn: socket.socket) -> PeerCred:
        cred = peer_credentials(conn)
        return PeerCred(pid=cred.pid, uid=0, gid=cred.gid)

    monkeypatch.setattr("pep.host.server.peer_credentials", root_peer)
    host = _listen(tmp_path, allowed_uids=frozenset({_agent_uid()}))
    client = _connect(host.socket_path)
    try:
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "peer_rejected"
        assert "root" in denied["reason_detail"]
        assert host.decision_records()[-1]["peer_uid"] == 0
        assert host.sessions() == ()
    finally:
        client.close()
        host.close()


def test_serve_requires_an_allow_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    host = _host(tmp_path)
    try:
        with pytest.raises(HostError, match="allow list"):
            host.serve_forever()
    finally:
        host.close()

    other = _private(tmp_path / "empty")
    empty = _host(other, allowed_uids=frozenset())
    try:
        with pytest.raises(HostError, match="allow list"):
            empty.serve_forever()
    finally:
        empty.close()

    os.chmod(tmp_path, 0o700)
    sock_dir = _private(tmp_path / "run")
    os.chmod(sock_dir, 0o2750)
    halt = tmp_path / "cli-halt.json"
    init_active(halt)
    code = main(
        [
            "serve",
            "--socket",
            str(sock_dir / "pep.sock"),
            "--halt",
            str(halt),
            "--log",
            str(tmp_path / "cli.log"),
        ]
    )
    assert code == 1
    assert "allow list" in capsys.readouterr().err


def test_allow_list_cannot_name_root_or_the_host_user(tmp_path: Path):
    with pytest.raises(HostError, match="host user"):
        _host(tmp_path, allowed_uids={os.getuid()})
    nested = tmp_path / "root-uid"
    nested.mkdir()
    os.chmod(nested, 0o700)
    with pytest.raises(HostError, match="root"):
        _host(nested, allowed_uids={0})


def test_host_user_is_refused_before_a_group_allow_list(tmp_path: Path):
    host = _host(tmp_path, allowed_gids=frozenset({os.getgid()}))
    try:
        same = PeerCred(pid=1, uid=os.getuid(), gid=os.getgid())
        assert host.peer_permitted(same) is False
        assert host._agent_peer_denial(same) == "peer uid is the host user"
        assert host.peer_permitted(PeerCred(pid=1, uid=_agent_uid(), gid=os.getgid())) is True
        assert host.peer_permitted(PeerCred(pid=1, uid=_agent_uid(), gid=os.getgid() + 1)) is False
    finally:
        host.close()


def test_admin_socket_refuses_a_pid_the_agent_socket_rejected(tmp_path: Path):
    admin = tmp_path / "admin.sock"
    host = _listen(tmp_path, admin_path=admin, allowed_uids=frozenset({_agent_uid()}))
    client = _connect(host.socket_path)
    try:
        denied = _recv(client)
        assert denied["reason_code"] == "peer_rejected"
        assert "host user" in denied["reason_detail"]
        admin_client = _connect(admin)
        try:
            reply = _recv(admin_client)
        finally:
            admin_client.close()
        assert reply["ok"] is False
        assert "operator" in reply["error"]
        # A different process id with this user id is still accepted. The kernel
        # credential does not say which of those processes is the operator.
        assert host._admin_peer_denial(PeerCred(pid=os.getpid() + 1, uid=os.getuid(), gid=os.getgid())) is None
    finally:
        client.close()
        host.close()


def test_admin_socket_refuses_an_allow_listed_uid(tmp_path: Path):
    admin = tmp_path / "admin.sock"
    agent = _agent_uid()
    host = _listen(tmp_path, admin_path=admin, allowed_uids=frozenset({agent}))
    _inject_agent_peer(host, agent)
    client = _connect(admin)
    try:
        reply = _recv(client)
        assert reply["ok"] is False
        assert "host user" in reply["error"]
    finally:
        client.close()
        host.close()


def test_symlinked_policy_is_refused(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    target = _policy_file(tmp_path)
    target_bytes = target.read_bytes()
    link = tmp_path / "policy-link.json"
    link.symlink_to(target)
    halt = tmp_path / "halt.json"
    init_active(halt)
    with pytest.raises(HostError, match="symlink"):
        ReferenceHost(
            halt_path=halt,
            log_path=tmp_path / "decisions.log",
            policy_path=link,
        )
    assert link.is_symlink()
    assert target.read_bytes() == target_bytes
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_group_readable_policy_is_refused(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = _policy_file(tmp_path)
    os.chmod(path, 0o640)
    halt = tmp_path / "halt.json"
    init_active(halt)
    with pytest.raises(HostError, match="group or other"):
        ReferenceHost(
            halt_path=halt,
            log_path=tmp_path / "decisions.log",
            policy_path=path,
        )


def test_private_directory_refuses_any_group_or_other_bit(tmp_path: Path):
    """Mutation audit 2026-10-14-host, M11: the halt, log and policy directories
    must carry no group or other bits at all. Group-only modes are the ones a
    widened mask (0o007) would let through, so each is checked on its own."""
    from pep.host.fsguard import PathGuardError, require_directory

    private = tmp_path / "private"
    private.mkdir()
    os.chmod(private, 0o700)
    require_directory(private, allow_group_traverse=False)
    for mode in (0o710, 0o720, 0o740, 0o750, 0o770, 0o701, 0o704, 0o707):
        os.chmod(private, mode)
        with pytest.raises(PathGuardError, match="group or other"):
            require_directory(private, allow_group_traverse=False)
    os.chmod(private, 0o700)
    require_directory(private, allow_group_traverse=False)


def test_policy_in_a_group_traversable_directory_is_refused(tmp_path: Path):
    """Mutation audit 2026-10-14-host, M11: a policy directory readable and
    traversable by its group (0750) is not private; the host refuses to start."""
    os.chmod(tmp_path, 0o700)
    shared = tmp_path / "shared"
    shared.mkdir()
    path = shared / "policy.json"
    path.write_text(json.dumps(STUB_POLICY_DOCUMENT), encoding="utf-8")
    os.chmod(path, 0o600)
    os.chmod(shared, 0o750)
    halt = tmp_path / "halt.json"
    init_active(halt)
    with pytest.raises(HostError, match="directory"):
        ReferenceHost(
            halt_path=halt,
            log_path=tmp_path / "decisions.log",
            policy_path=path,
        )


def test_policy_in_a_loose_directory_is_refused(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o755)
    path = loose / "policy.json"
    path.write_text(json.dumps(STUB_POLICY_DOCUMENT), encoding="utf-8")
    os.chmod(path, 0o600)
    halt = tmp_path / "halt.json"
    init_active(halt)
    with pytest.raises(HostError, match="directory"):
        ReferenceHost(
            halt_path=halt,
            log_path=tmp_path / "decisions.log",
            policy_path=path,
        )


def test_policy_owned_by_someone_else_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    os.chmod(tmp_path, 0o700)
    path = _policy_file(tmp_path)
    halt = tmp_path / "halt.json"
    init_active(halt)
    monkeypatch.setattr("pep.host.fsguard.file_owner", lambda _info: os.getuid() + 1)
    with pytest.raises(HostError, match="owned"):
        ReferenceHost(
            halt_path=halt,
            log_path=tmp_path / "decisions.log",
            policy_path=path,
        )


def test_private_policy_loads_and_a_later_loose_file_halts(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = _policy_file(tmp_path)
    host = _host(tmp_path, policy_path=path)
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        first = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert first["reason_code"] != "policy_miss"
        assert host.halted() is False
        os.chmod(path, 0o666)
        second = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert second["decision"] == "DENY"
        assert second["reason_code"] == "policy_miss"
        assert "unreadable" in second["reason_detail"]
        assert host.halted() is True
    finally:
        host.close()


def test_policy_bytes_changed_after_load_halts(tmp_path: Path):
    """Mutation audit 2026-10-14-host, M02: a digest mismatch on re-read is a
    fail-closed DENY (policy_miss) that latches the host, never an evaluation
    against the new bytes. The file stays mode 0600 and stays valid JSON, so
    only the digest comparison can notice the change."""
    os.chmod(tmp_path, 0o700)
    path = _policy_file(tmp_path)
    host = _host(tmp_path, policy_path=path)
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        first = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert first["reason_code"] != "policy_miss"
        assert host.halted() is False
        with open(path, "ab") as handle:
            handle.write(b"\n")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert json.loads(path.read_text(encoding="utf-8")) == STUB_POLICY_DOCUMENT
        second = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert second["decision"] == "DENY"
        assert second["reason_code"] == "policy_miss"
        assert "changed" in second["reason_detail"]
        assert host.halted() is True
        third = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert third["decision"] == "DENY"
    finally:
        host.close()


def test_policy_replaced_by_a_symlink_halts(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    path = _policy_file(tmp_path)
    kept = path.read_bytes()
    host = _host(tmp_path, policy_path=path)
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        path.unlink()
        path.symlink_to(tmp_path / "absent.json")
        denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert denied["reason_code"] == "policy_miss"
        assert host.halted() is True
        assert path.is_symlink()
        assert not (tmp_path / "absent.json").exists()
        assert kept.startswith(b"{")
    finally:
        host.close()


def test_host_observes_the_result_and_claims_are_checked_against_its_record(tmp_path: Path):
    """ADR-0010: the ALLOW record carries the host's own digest of the result,
    the reply carries the same digest, and an agent's claim about the call is
    judged against the record, never against the agent's words."""
    from pep.host.claims import (
        CLAIM_SCHEMA,
        CONSISTENT,
        CONTRADICTED,
        UNVERIFIABLE,
        parse_claim,
        result_digest,
        verify_claim,
    )

    def registered(args: dict) -> dict:
        return {"pong": args["message"], "ran": "registry"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        session = host.open_session(_peer())
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert allowed["decision"] == "ALLOW"
        expected = result_digest({"pong": "hi", "ran": "registry"})
        assert allowed["result_digest"] == expected
        record = host.decision_records()[-1]
        assert record["decision"] == "ALLOW"
        assert record["request_id"] == allowed["request_id"]
        observed = [check for check in record["checks"] if check["name"] == "result"]
        assert observed == [{"name": "result", "outcome": "returned", "digest": expected}]
        # The result body is in the reply, not in the record.
        assert "pong" not in json.dumps(record)

        records = host.decision_records()

        def claim(**fields: Any):
            body = {"schema": CLAIM_SCHEMA, "kind": "action", "request_id": allowed["request_id"],
                    "tool_name": "echo.ping", "outcome": "allowed", "result_digest": expected}
            body.update(fields)
            return parse_claim(body)

        assert verify_claim(claim(), records).verdict == CONSISTENT
        forged = verify_claim(claim(result_digest=result_digest({"pong": "forged"})), records)
        assert (forged.verdict, forged.field) == (CONTRADICTED, "result_digest")
        hidden = verify_claim(claim(outcome="denied", result_digest=None), records)
        assert (hidden.verdict, hidden.field) == (CONTRADICTED, "outcome")
        unknown = verify_claim(claim(request_id="host.9.9"), records)
        assert unknown.verdict == UNVERIFIABLE
        # This path does not serve a socket, so the log has no session span.
        absent = parse_claim(
            {
                "schema": CLAIM_SCHEMA,
                "kind": "absence",
                "tool_name": "echo.ping",
                "outcome": "not_called",
                "session_id": session.principal,
            }
        )
        assert verify_claim(absent, records).verdict == UNVERIFIABLE
    finally:
        host.close()


def test_a_served_session_bounds_a_not_called_claim(tmp_path: Path):
    """A connection writes session open and session close.

    A not_called claim for a tool that does not appear is consistent only on
    that whole slice. The denial line by itself is unverifiable, and so is
    the slice with a seq missing between the markers.
    """
    from pep.host.claims import CLAIM_SCHEMA, CONSISTENT, UNVERIFIABLE, parse_claim, verify_claim

    host = _listen(tmp_path)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        _send(client, {"tool_name": "echo.ping", "args": ARGS})
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        client.close()
        records = _records_after_session_closes(host)
        assert [record["decision"] for record in records][0] == "SESSION_OPEN"
        assert records[-1]["decision"] == "SESSION_CLOSE"
        session_id = records[0]["session_id"]
        assert records[-1]["session_id"] == session_id
        seqs = [record["seq"] for record in records]
        assert seqs == list(range(seqs[0], seqs[0] + len(seqs)))
        other = parse_claim(
            {
                "schema": CLAIM_SCHEMA,
                "kind": "absence",
                "tool_name": "file.read",
                "outcome": "not_called",
                "session_id": session_id,
            }
        )
        assert verify_claim(other, records).verdict == CONSISTENT
        denial = [record for record in records if record["decision"] == "DENY"]
        assert denial and denial[0]["tool_name"] == "echo.ping"
        assert verify_claim(other, denial).verdict == UNVERIFIABLE
        gapped = [records[0], records[-1]]
        assert verify_claim(other, gapped).verdict == UNVERIFIABLE
        different = parse_claim(
            {
                "schema": CLAIM_SCHEMA,
                "kind": "absence",
                "tool_name": "file.read",
                "outcome": "not_called",
                "session_id": "u9.c9",
            }
        )
        assert verify_claim(different, records).verdict == UNVERIFIABLE
    finally:
        client.close()
        host.close()


def test_a_raised_tool_contradicts_not_called_on_the_host_log(tmp_path: Path):
    """A tool that raises is on the host log, so not_called for that session is contradicted."""
    from pep.host.claims import CLAIM_SCHEMA, CONTRADICTED, parse_claim, verify_claim

    def registered(_args: dict) -> dict:
        raise RuntimeError("boom")

    host = _listen(tmp_path, registry={"echo.ping": registered})
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        session = host.sessions()[0]
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        _send(client, {"tool_name": "echo.ping", "args": ARGS})
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "tool_failed"
        assert "raised after entry" in denied["reason_detail"]
        client.close()
        absent = parse_claim(
            {
                "schema": CLAIM_SCHEMA,
                "kind": "absence",
                "tool_name": "echo.ping",
                "outcome": "not_called",
                "session_id": session.principal,
            }
        )
        verdict = verify_claim(absent, _records_after_session_closes(host))
        assert (verdict.verdict, verdict.field) == (CONTRADICTED, "tool_name")
    finally:
        client.close()
        host.close()


def test_a_frame_limit_denial_contradicts_not_called_on_the_host_log(tmp_path: Path):
    """A reply over the frame limit is a call, so not_called for that session is contradicted."""
    from pep.host.claims import CLAIM_SCHEMA, CONTRADICTED, parse_claim, verify_claim

    def registered(args: dict) -> dict:
        return {"pong": "x" * (300 * 1024)}

    host = _listen(tmp_path, registry={"echo.ping": registered})
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        session = host.sessions()[0]
        big = {"message": "big"}
        host.issue_session_approval(session, tool_name="echo.ping", args=big, ttl_seconds=60)
        _send(client, {"tool_name": "echo.ping", "args": big})
        denied = _recv(client)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "tool_failed"
        assert "frame limit" in denied["reason_detail"]
        client.close()
        absent = parse_claim(
            {
                "schema": CLAIM_SCHEMA,
                "kind": "absence",
                "tool_name": "echo.ping",
                "outcome": "not_called",
                "session_id": session.principal,
            }
        )
        verdict = verify_claim(absent, _records_after_session_closes(host))
        assert (verdict.verdict, verdict.field) == (CONTRADICTED, "tool_name")
    finally:
        client.close()
        host.close()


def test_agent_claim_on_the_host_is_bound_to_the_connection(tmp_path: Path):
    """The tool ran on the caller's connection. A claim that names an idle
    session is still checked as the caller, and is contradicted.

    An offline check of that same body, as an attested claim for the idle
    session, stays consistent.
    """
    from pep.host.claims import CLAIM_SCHEMA, CONSISTENT, CONTRADICTED, parse_claim, verify_claim

    host = _listen(tmp_path)
    caller_client = _connect(host.socket_path)
    idle_client = None
    try:
        _wait_sessions(host, 1)
        caller = host.sessions()[0]
        host.issue_session_approval(caller, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        _send(caller_client, {"tool_name": "echo.ping", "args": ARGS})
        allowed = _recv(caller_client)
        assert allowed["decision"] == "ALLOW"
        caller_client.close()
        deadline = time.time() + 2
        while time.time() < deadline and host.sessions():
            time.sleep(0.01)
        assert host.sessions() == ()
        idle_client = _connect(host.socket_path)
        _wait_sessions(host, 1)
        idle = host.sessions()[0]
        assert idle.principal != caller.principal
        idle_client.close()
        records = _records_after_session_closes(host)
        assert sum(record["decision"] == "SESSION_CLOSE" for record in records) == 2
        forged = {
            "schema": CLAIM_SCHEMA,
            "kind": "absence",
            "tool_name": "echo.ping",
            "outcome": "not_called",
            "session_id": idle.principal,
        }
        bound = host.verify_agent_claim(caller, forged)
        assert (bound.verdict, bound.field) == (CONTRADICTED, "tool_name")
        assert forged["session_id"] == idle.principal
        honest = dict(forged)
        honest["session_id"] = caller.principal
        assert host.verify_agent_claim(caller, honest).verdict == CONTRADICTED
        assert verify_claim(parse_claim(forged), records).verdict == CONSISTENT
    finally:
        caller_client.close()
        if idle_client is not None:
            idle_client.close()
        host.close()


def test_unencodable_result_is_observed_as_such_and_not_returned(tmp_path: Path):
    """ADR-0010: a result the host cannot encode is recorded as unencodable
    with no digest; the reply has no result and no digest."""

    def registered(_args: dict) -> object:
        return object()

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        session = host.open_session(_peer())
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert allowed["decision"] == "ALLOW"
        assert "result" not in allowed
        assert "result_digest" not in allowed
        assert "not JSON" in allowed["reason_detail"]
        record = host.decision_records()[-1]
        observed = [check for check in record["checks"] if check["name"] == "result"]
        assert observed == [{"name": "result", "outcome": "unencodable"}]
    finally:
        host.close()


def test_tool_runs_outside_the_gate_process(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("registry")
        return {"pong": "ok", "pid": os.getpid()}

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result"]["pong"] == "ok"
        assert allowed["result"]["pid"] != os.getpid()
        assert calls == []
    finally:
        host.close()


def test_tool_cannot_reach_halt_log_or_admin_socket(tmp_path: Path):
    os.chmod(tmp_path, 0o700)
    halt = tmp_path / "halt.json"
    log_path = tmp_path / "decisions.log"
    admin = tmp_path / "probe-admin.sock"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"keep")
    os.chmod(sentinel, 0o600)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_mask = os.umask(0o177)
    try:
        listener.bind(str(admin))
    finally:
        os.umask(old_mask)
    os.chmod(admin, 0o600)
    listener.listen(1)

    def probe(_args: dict) -> dict:
        touched: list[str] = []
        for target in (str(halt), str(log_path), str(sentinel)):
            try:
                fd = os.open(target, os.O_RDWR)
            except OSError:
                pass
            else:
                os.close(fd)
                touched.append("open")
        try:
            os.chmod(str(halt), 0o666)
        except OSError:
            pass
        else:
            touched.append("chmod")
        try:
            os.unlink(str(sentinel))
        except OSError:
            pass
        else:
            touched.append("unlink")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(1)
        try:
            client.connect(str(admin))
        except OSError:
            pass
        else:
            touched.append("connect")
        finally:
            client.close()
        if touched:
            return {"pong": "reached"}
        raise PermissionError(errno.EACCES, "denied")

    init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=log_path,
        registry={"echo.ping": probe},
    )
    try:
        halt_bytes = halt.read_bytes()
        log_before = log_path.read_bytes()
        session = host.open_session(_peer(uid=_agent_uid()))
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "tool_failed"
        assert "denied" in denied["reason_detail"]
        assert halt.read_bytes() == halt_bytes
        assert stat.S_IMODE(halt.stat().st_mode) == 0o600
        assert log_path.read_bytes().startswith(log_before)
        assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
        assert sentinel.read_bytes() == b"keep"
        assert stat.S_ISSOCK(admin.lstat().st_mode)
        assert stat.S_IMODE(admin.stat().st_mode) == 0o600
    finally:
        listener.close()
        host.close()


def test_each_session_gets_its_own_executor(tmp_path: Path):
    def registered(_args: dict) -> dict:
        return {"pong": "ok", "pid": os.getpid()}

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        first = host.open_session(_peer(uid=_agent_uid()))
        second = host.open_session(_peer(pid=11, uid=_agent_uid()))
        host.issue_session_approval(first, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        host.issue_session_approval(second, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        left = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, first)
        right = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, second)
        assert left["decision"] == "ALLOW"
        assert right["decision"] == "ALLOW"
        assert left["result"]["pid"] != os.getpid()
        assert right["result"]["pid"] != os.getpid()
        assert left["result"]["pid"] != right["result"]["pid"]
    finally:
        host.close()


def test_a_slow_tool_times_out_without_blocking_another_session(tmp_path: Path):
    def registered(args: dict) -> dict:
        if args.get("message") == "sleep":
            time.sleep(2)
            return {"pong": "late"}
        return {"pong": "ok", "pid": os.getpid()}

    host = _host(tmp_path, registry={"echo.ping": registered}, tool_timeout=1.0)
    try:
        slow = host.open_session(_peer(uid=_agent_uid()))
        fast = host.open_session(_peer(pid=12, uid=_agent_uid()))
        host.issue_session_approval(slow, tool_name="echo.ping", args={"message": "sleep"}, ttl_seconds=60)
        host.issue_session_approval(fast, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        box: dict[str, Any] = {}

        def run_slow() -> None:
            box["slow"] = host.handle_request({"tool_name": "echo.ping", "args": {"message": "sleep"}}, slow)

        thread = threading.Thread(target=run_slow)
        thread.start()
        time.sleep(0.05)
        started = time.monotonic()
        quick = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, fast)
        elapsed = time.monotonic() - started
        assert thread.is_alive()
        thread.join(timeout=3)
        assert quick["decision"] == "ALLOW"
        assert quick["result"]["pid"] != os.getpid()
        assert elapsed < 0.75
        assert box["slow"]["decision"] == "DENY"
        assert box["slow"]["reason_code"] == "tool_failed"
        assert "timed out" in box["slow"]["reason_detail"]
    finally:
        host.close()


def test_executor_limit_denies_a_session_past_the_cap(tmp_path: Path):
    host = _host(tmp_path, max_connections=1)
    try:
        first = host.open_session(_peer(uid=_agent_uid()))
        second = host.open_session(_peer(pid=13, uid=_agent_uid()))
        host.issue_session_approval(first, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        host.issue_session_approval(second, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, first)
        denied = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, second)
        assert allowed["decision"] == "ALLOW"
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "tool_failed"
        assert "limit" in denied["reason_detail"]
    finally:
        host.close()


def _native_syscall(number: int) -> tuple[int, int]:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    rc = libc.syscall(number, 0, 0, 0, 0, 0, 0)
    return int(rc), ctypes.get_errno()


def _i386_syscall(number: int, ebx: int = 0, ecx: int = 0) -> int:
    """Enter the kernel with ``int 0x80``. The filter kills that architecture."""
    code = bytes([
        0xB8, number & 0xFF, (number >> 8) & 0xFF, (number >> 16) & 0xFF, (number >> 24) & 0xFF,
        0xBB, ebx & 0xFF, (ebx >> 8) & 0xFF, (ebx >> 16) & 0xFF, (ebx >> 24) & 0xFF,
        0xB9, ecx & 0xFF, (ecx >> 8) & 0xFF, (ecx >> 16) & 0xFF, (ecx >> 24) & 0xFF,
        0xCD, 0x80,
        0xC3,
    ])
    page = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    page.write(code)
    fn = ctypes.CFUNCTYPE(ctypes.c_int)(ctypes.addressof(ctypes.c_char.from_buffer(page)))
    return int(fn())


def test_executor_denies_x32_and_the_dangerous_syscalls(tmp_path: Path):
    def probe(_args: dict) -> dict:
        found: dict[str, dict[str, int]] = {}
        numbers = {
            "x32_write": 1 | 0x40000000,
            "x32_kill": 62 | 0x40000000,
            "x32_ptrace": 521 | 0x40000000,
            "sendto": 44,
            "ptrace": 101,
            "keyctl": 250,
            "perf_event_open": 298,
            "open_by_handle_at": 304,
            "memfd_create": 319,
            "bpf": 321,
            "userfaultfd": 323,
            "io_uring_setup": 425,
            "io_uring_enter": 426,
            "io_uring_register": 427,
            "clone3": 435,
        }
        for name, number in numbers.items():
            rc, err = _native_syscall(number)
            found[name] = {"rc": rc, "err": err}
        found["worker"] = {"pid": os.getpid(), "env": len(os.environ)}
        return found

    host = _host(tmp_path, registry={"echo.ping": probe})
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert allowed["decision"] == "ALLOW"
        result = allowed["result"]
        worker = result["worker"]
        assert worker["env"] == 0
        limits = Path(f"/proc/{worker['pid']}/limits").read_text(encoding="utf-8")
        for label in ("Max core file size", "Max file size", "Max processes"):
            line = next(row for row in limits.splitlines() if row.startswith(label))
            soft, hard = line.split()[-3:-1]
            assert soft == "0" and hard == "0", label
        for name, item in result.items():
            if name == "worker":
                continue
            assert item["rc"] == -1, name
            if name == "clone3":
                assert item["err"] in {errno.EPERM, errno.ENOSYS}, name
            else:
                assert item["err"] == errno.EPERM, name
    finally:
        host.close()


def test_executor_kills_32_bit_kill_and_ptrace(tmp_path: Path):
    def probe(args: dict) -> dict:
        kind = args.get("message")
        if kind == "setup":
            mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            return {"mapped": True}
        if kind == "kill":
            # i386 kill(self, 0). Signal 0 does not deliver; a missed filter returns 0.
            _i386_syscall(37, os.getpid(), 0)
            return {"survived": "kill"}
        if kind == "ptrace":
            # i386 ptrace(PTRACE_TRACEME). A missed filter returns instead of killing us.
            _i386_syscall(26, 0, 0)
            return {"survived": "ptrace"}
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": probe})
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        for args in ({"message": "setup"}, {"message": "kill"}, {"message": "ptrace"}, ARGS):
            host.issue_session_approval(session, tool_name="echo.ping", args=args, ttl_seconds=60)
        mapped = host.handle_request({"tool_name": "echo.ping", "args": {"message": "setup"}}, session)
        assert mapped["decision"] == "ALLOW"
        assert mapped["result"]["mapped"] is True
        for kind in ("kill", "ptrace"):
            denied = host.handle_request(
                {"tool_name": "echo.ping", "args": {"message": kind}},
                session,
            )
            assert denied["decision"] == "DENY", kind
            assert denied["reason_code"] == "tool_failed", kind
            assert denied.get("result") is None, kind
        other = host.open_session(_peer(pid=14, uid=_agent_uid()))
        host.issue_session_approval(other, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        still = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, other)
        assert still["decision"] == "ALLOW"
        assert still["result"]["pong"] == "ok"
    finally:
        host.close()


def test_held_connection_shared_by_threads_never_gives_a_caller_another_callers_reply(tmp_path: Path):
    """Six threads share one held connection. Only thread 0 sends granted args.

    Without a lock across send and read, a thread could read the reply meant
    for another thread, so an ungranted caller could be told ALLOW.
    """
    host = _listen(tmp_path)
    granted = {"message": "granted"}
    wrong: list[str] = []
    allowed_ids: list[str] = []
    try:
        with AgentConnection(host.socket_path, host_uid=os.getuid()) as held:
            held.call("echo.ping", granted)
            _wait_sessions(host, 1)
            session = host.sessions()[0]
            start = threading.Barrier(6)

            def worker(index: int) -> None:
                start.wait()
                for n in range(40):
                    if index == 0:
                        host.issue_session_approval(session, tool_name="echo.ping", args=granted, ttl_seconds=60)
                        reply = held.call("echo.ping", granted)
                        if reply.get("decision") == "ALLOW":
                            allowed_ids.append(reply.get("request_id"))
                            if reply.get("result") != {"pong": "granted"}:
                                wrong.append(f"granted caller got another result: {reply}")
                    else:
                        reply = held.call("echo.ping", {"message": f"other-{index}-{n}"})
                        if reply.get("decision") == "ALLOW":
                            wrong.append(f"ungranted caller {index} was told ALLOW: {reply}")

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
    finally:
        host.close()
    assert wrong == []
    assert allowed_ids, "the granted caller was never allowed, so the check proved nothing"
    records = [json.loads(line) for line in (tmp_path / "decisions.log").read_text(encoding="utf-8").splitlines() if line.strip()]
    logged_allows = {r.get("request_id") for r in records if r.get("decision") == "ALLOW"}
    assert set(allowed_ids) <= logged_allows


def _held_on_fake_socket(reply_lines: list[bytes]) -> tuple[AgentConnection, socket.socket]:
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    held = AgentConnection("/nonexistent", host_uid=os.getuid())
    held._sock = ours
    theirs.sendall(b"".join(reply_lines))
    return held, theirs


def test_held_connection_denies_and_closes_on_a_reused_request_id():
    line = b'{"decision":"DENY","reason_code":"no_grant","request_id":"host.3.7"}\n'
    held, theirs = _held_on_fake_socket([line, line])
    try:
        first = held.call("echo.ping", ARGS)
        assert first["request_id"] == "host.3.7"
        second = held.call("echo.ping", ARGS)
        assert second["decision"] == "DENY"
        assert second["reason_code"] == "reply_mismatch"
        assert held._sock is None
        assert held.call("echo.ping", ARGS)["reason_code"] == "reply_mismatch"
    finally:
        theirs.close()


def test_held_connection_denies_and_closes_on_another_connections_request_id():
    held, theirs = _held_on_fake_socket(
        [
            b'{"decision":"DENY","reason_code":"no_grant","request_id":"host.3.7"}\n',
            b'{"decision":"ALLOW","request_id":"host.4.8"}\n',
        ]
    )
    try:
        held.call("echo.ping", ARGS)
        reply = held.call("echo.ping", ARGS)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "reply_mismatch"
        assert held._sock is None
    finally:
        theirs.close()


def test_held_connection_denies_a_reply_with_no_request_id():
    held, theirs = _held_on_fake_socket([b'{"decision":"ALLOW"}\n'])
    try:
        reply = held.call("echo.ping", ARGS)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "reply_mismatch"
        assert held._sock is None
    finally:
        theirs.close()


def test_held_connection_closes_on_a_reply_that_is_not_json():
    held, theirs = _held_on_fake_socket([b"not json\n", b'{"decision":"ALLOW","request_id":"host.1.1"}\n'])
    try:
        reply = held.call("echo.ping", ARGS)
        assert reply["decision"] == "DENY"
        assert reply["reason_code"] == "envelope_invalid"
        assert held._sock is None
        later = held.call("echo.ping", ARGS)
        assert later["decision"] == "DENY"
        assert later["reason_code"] == "envelope_invalid"
    finally:
        theirs.close()


def test_held_connection_close_clears_the_buffer_and_keeps_the_reason():
    held, theirs = _held_on_fake_socket([b"x"])
    theirs.close()
    reply = held.call("echo.ping", ARGS)
    assert reply["reason_code"] == "host_unreachable"
    assert held._buf == b""
    assert held._sock is None
    assert held.call("echo.ping", ARGS)["reason_detail"] == reply["reason_detail"]


def test_newline_flood_from_a_peer_that_never_reads_releases_the_slot(tmp_path: Path):
    host = _listen(tmp_path, max_connections=1, connection_deadline=2, idle_timeout=0.5)
    flood = _connect(host.socket_path)
    again: socket.socket | None = None
    try:
        _wait_sessions(host, 1)
        flood.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        flood.sendall(b"\n" * 4096)
        # Bound: the deadline plus one in-flight request and one blocked send.
        bound = time.monotonic() + 2 + 0.5 + 3
        while time.monotonic() < bound and host.sessions():
            time.sleep(0.05)
        assert host.sessions() == ()
        again = _connect(host.socket_path)
        _wait_sessions(host, 1)
        _send(again, {"tool_name": "echo.ping", "args": ARGS})
        reply = _recv(again)
        assert reply["reason_code"] != "connection_limit"
    finally:
        flood.close()
        if again is not None:
            again.close()
        host.close()


def test_deadline_is_checked_between_lines_of_one_chunk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = _Mono()
    host = _listen(tmp_path, monotonic=clock, connection_deadline=10, idle_timeout=30)
    real = host.handle_request
    handled = {"n": 0}

    def _counting(line, session):  # type: ignore[no-untyped-def]
        handled["n"] += 1
        clock.now = 10
        return real(line, session)

    monkeypatch.setattr(host, "handle_request", _counting)
    client = _connect(host.socket_path)
    try:
        _wait_sessions(host, 1)
        client.sendall(b"\n" * 50)
        first = _recv(client)
        assert first["reason_code"] == "envelope_invalid"
        deadline = time.time() + 2
        while time.time() < deadline and host.sessions():
            time.sleep(0.01)
        assert host.sessions() == ()
        assert handled["n"] == 1
        assert any(record["reason_code"] == "connection_deadline" for record in host.decision_records())
    finally:
        client.close()
        host.close()


def test_a_worker_that_drips_bytes_is_cut_off_at_the_call_timeout():
    from pep.host.executor import ToolExecutionError, _Worker

    gate, worker_end = socket.socketpair()
    dummy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    stop = threading.Event()

    def drip() -> None:
        try:
            worker_end.recv(65536)
            worker_end.sendall((200_000).to_bytes(4, "big"))
            while not stop.is_set():
                worker_end.sendall(b" ")
                time.sleep(0.05)
        except OSError:
            return

    thread = threading.Thread(target=drip, daemon=True)
    thread.start()
    worker = _Worker(dummy.pid, gate, call_timeout=0.5)
    outcome: dict[str, Any] = {}

    def bounded_call() -> None:
        # Mutation audit 2026-10-14-host, M07: a per-recv window instead of one
        # whole-call deadline keeps this call alive for as long as the worker
        # drips. The call runs on its own thread so that case fails the join
        # below instead of hanging the suite.
        try:
            outcome["result"] = worker.call("echo.ping", ARGS)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertions below
            outcome["error"] = exc

    started = time.monotonic()
    caller = threading.Thread(target=bounded_call, daemon=True)
    caller.start()
    caller.join(timeout=3)
    try:
        assert not caller.is_alive(), "worker.call outlived a 0.5 s call timeout by 3 s"
        assert time.monotonic() - started < 2
        error = outcome.get("error")
        assert isinstance(error, ToolExecutionError)
        assert error.kind == "timeout"
        assert worker.closed
        assert dummy.wait(timeout=5) is not None
    finally:
        stop.set()
        worker_end.close()
        worker.close()
        thread.join(timeout=2)
        caller.join(timeout=2)


def _fake_worker_call(reply: bytes) -> tuple[Any, bool, bool]:
    """Answer one gate call with ``reply`` from a fake worker. Returns (outcome, closed, reaped)."""
    from pep.host.executor import ToolExecutionError, _Worker

    gate, worker_end = socket.socketpair()
    dummy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    def answer() -> None:
        try:
            worker_end.recv(65536)
            worker_end.sendall(reply)
        except OSError:
            return

    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    worker = _Worker(dummy.pid, gate, call_timeout=5.0)
    try:
        try:
            outcome: Any = worker.call("echo.ping", ARGS)
        except ToolExecutionError as exc:
            outcome = exc
        thread.join(timeout=5)
        closed = worker.closed
        try:
            reaped = dummy.wait(timeout=5) is not None
        except subprocess.TimeoutExpired:
            reaped = False
        return outcome, closed, reaped
    finally:
        worker_end.close()
        worker.close()
        dummy.kill()
        dummy.wait(timeout=5)


def _frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def test_a_worker_reply_over_the_frame_limit_is_refused_and_the_worker_discarded():
    """P-4: one oversized reply frame is refused from its header; the worker is killed."""
    from pep.host.executor import ToolExecutionError

    body = json.dumps({"status": "ok", "result": "x" * (1024 * 1024)}).encode()
    outcome, closed, reaped = _fake_worker_call(_frame(body))
    assert isinstance(outcome, ToolExecutionError)
    assert outcome.kind == "oversize"
    assert closed and reaped


def test_a_worker_that_sends_a_second_frame_is_refused_and_discarded():
    """P-4: the per-call budget is one reply frame. A second frame is not left queued."""
    from pep.host.executor import ToolExecutionError

    one = _frame(json.dumps({"status": "ok", "result": {"pong": "hi"}}).encode())
    outcome, closed, reaped = _fake_worker_call(one + one)
    assert isinstance(outcome, ToolExecutionError)
    assert outcome.kind == "protocol"
    assert closed and reaped


def test_a_worker_that_speaks_between_calls_is_discarded_before_the_next_call():
    from pep.host.executor import ToolExecutionError, _Worker

    gate, worker_end = socket.socketpair()
    dummy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    worker = _Worker(dummy.pid, gate, call_timeout=2.0)
    try:
        worker_end.sendall(_frame(json.dumps({"status": "ok", "result": {"pong": "queued"}}).encode()))
        with pytest.raises(ToolExecutionError) as raised:
            worker.call("echo.ping", ARGS)
        assert raised.value.kind == "protocol"
        assert worker.closed
        assert dummy.wait(timeout=5) is not None
    finally:
        worker_end.close()
        worker.close()


def test_a_deeply_nested_worker_reply_fails_closed_and_discards_the_worker():
    from pep.host.executor import ToolExecutionError

    depth = 100_000
    body = b'{"status":"ok","result":' + b"[" * depth + b"]" * depth + b"}"
    outcome, closed, reaped = _fake_worker_call(_frame(body))
    assert isinstance(outcome, ToolExecutionError)
    assert outcome.kind == "error"
    assert closed and reaped


def test_an_honest_tool_result_over_the_frame_limit_is_denied_with_a_reason(tmp_path: Path):
    def registered(args: dict) -> dict:
        if args.get("message") == "big":
            return {"pong": "x" * (300 * 1024)}
        return {"pong": args.get("message", "")}

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        session = host.open_session(_peer())
        big = {"message": "big"}
        host.issue_session_approval(session, tool_name="echo.ping", args=big, ttl_seconds=60)
        denied = host.handle_request({"tool_name": "echo.ping", "args": big}, session)
        assert denied["decision"] == "DENY"
        assert denied["reason_code"] == "tool_failed"
        assert "frame limit" in denied["reason_detail"]
        assert "result" not in denied
        # The largest echo a request can carry still fits one reply frame.
        largest = {"message": "y" * 60_000}
        host.issue_session_approval(session, tool_name="echo.ping", args=largest, ttl_seconds=60)
        allowed = host.handle_request({"tool_name": "echo.ping", "args": largest}, session)
        assert allowed["decision"] == "ALLOW"
        assert allowed["result"] == {"pong": "y" * 60_000}
    finally:
        host.close()


def test_shutdown_does_not_wait_for_ever_on_a_blocked_tool_call(tmp_path: Path):
    def registered(args: dict) -> dict:
        if args.get("message") == "hang":
            time.sleep(20)
        return {"pong": "ok"}

    (tmp_path / "sock").mkdir()
    os.chmod(tmp_path / "sock", 0o2750)
    host = _host(tmp_path, registry={"echo.ping": registered}, tool_timeout=30.0, allowed_uids=frozenset({_agent_uid()}))
    serving = host.serve_in_background()
    session = host.open_session(_peer(uid=_agent_uid()))
    host.issue_session_approval(session, tool_name="echo.ping", args={"message": "hang"}, ttl_seconds=60)
    box: dict[str, Any] = {}
    caller = threading.Thread(
        target=lambda: box.setdefault(
            "reply", host.handle_request({"tool_name": "echo.ping", "args": {"message": "hang"}}, session)
        ),
        daemon=True,
    )
    caller.start()
    try:
        time.sleep(0.3)
        started = time.monotonic()
        host.request_stop()
        serving.join(timeout=5)
        assert not serving.is_alive()
        assert time.monotonic() - started < 5
        caller.join(timeout=2)
        assert box["reply"]["decision"] == "DENY"
    finally:
        host.close()


def test_shutdown_abort_refuses_calls_that_had_not_reached_a_worker(tmp_path: Path):
    calls: list[str] = []

    def registered(_args: dict) -> dict:
        calls.append("ran")
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    try:
        session = host.open_session(_peer(uid=_agent_uid()))
        host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
        nursery = host._executors
        assert nursery._spare is not None
        nursery.abort_calls()
        assert nursery._spare is None
        decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)
        assert decision["decision"] == "DENY"
        assert decision["reason_code"] == "tool_failed"
        assert decision["reason_detail"].startswith("host is shutting down")
        assert calls == []
    finally:
        host.close()


def test_shutdown_race_many_callers_all_get_deny_and_the_log_closes(tmp_path: Path):
    """Threaded shutdown race: a first wave of callers is inside its workers
    when stop fires, and a second wave arrives on open sessions after the
    accept loop has returned (abort done, log closed).

    Every caller gets a DENY, serve_forever returns inside the drain bound,
    and the decision log is closed with its held count written. No caller
    hangs and no exception escapes a worker thread.
    """

    def registered(args: dict) -> dict:
        # Runs in a forked worker: it is cut off by the worker's SIGKILL on abort.
        if args.get("message") == "hang":
            time.sleep(20)
        return {"pong": "ok"}

    (tmp_path / "sock").mkdir()
    os.chmod(tmp_path / "sock", 0o2750)
    host = _host(tmp_path, registry={"echo.ping": registered}, tool_timeout=30.0, allowed_uids=frozenset({_agent_uid()}))
    serving = host.serve_in_background()
    sessions = [host.open_session(_peer(pid=100 + index, uid=_agent_uid())) for index in range(6)]
    for session in sessions:
        host.issue_session_approval(session, tool_name="echo.ping", args={"message": "hang"}, ttl_seconds=60)
    replies: list[dict[str, Any]] = []
    errors: list[BaseException] = []
    lock = threading.Lock()
    go = threading.Event()

    def call(session: Any) -> None:
        go.wait(timeout=5)
        try:
            reply = host.handle_request({"tool_name": "echo.ping", "args": {"message": "hang"}}, session)
        except BaseException as exc:  # noqa: BLE001 - the test records every escape
            with lock:
                errors.append(exc)
            return
        with lock:
            replies.append(reply)

    first_wave = sessions[:3]
    second_wave = sessions[3:]
    callers = [threading.Thread(target=call, args=(session,), daemon=True) for session in first_wave]
    for caller in callers:
        caller.start()
    try:
        go.set()
        time.sleep(0.2)
        started = time.monotonic()
        host.request_stop()
        serving.join(timeout=5)
        assert not serving.is_alive()
        assert time.monotonic() - started < 5
        # The second wave arrives on sessions that are still open after shutdown.
        late = [threading.Thread(target=call, args=(session,), daemon=True) for session in second_wave]
        for caller in late:
            caller.start()
        callers.extend(late)
        for caller in callers:
            caller.join(timeout=5)
        assert not any(caller.is_alive() for caller in callers)
    finally:
        host.close()
    assert errors == []
    assert len(replies) == len(sessions)
    assert all(reply["decision"] == "DENY" for reply in replies)
    details = sorted(reply["reason_detail"] for reply in replies)
    # First wave: inside a worker, cut off by the abort. Second wave: refused
    # at the closed log gate, counted, not appended.
    assert sum(detail == "host tool raised after entry" for detail in details) == len(first_wave)
    assert sum(detail.startswith("host is shut down") for detail in details) == len(second_wave)
    assert host.refused_after_close == len(second_wave)
    assert host._log_closed
    records = host.decision_records()
    # No record says a tool completed.
    tool_records = [record for record in records if record.get("tool_name") == "echo.ping"]
    assert all(record["decision"] in {"PRE_ENTRY", "DENY"} for record in tool_records)
    assert all(record["reason_code"] == "tool_failed" for record in tool_records if record["decision"] == "DENY")
    for record in records:
        _assert_record_claims_only_what_ran(record)


@pytest.mark.parametrize("abort_error", [RuntimeError, KeyboardInterrupt])
def test_log_is_closed_even_when_aborting_the_executor_raises(
    tmp_path: Path, abort_error: type[BaseException]
) -> None:
    """If stopping the workers raises during shutdown, the decision log is still drained and closed.

    KeyboardInterrupt is a BaseException. It still propagates out of
    serve_forever, and the log is closed afterwards.
    """
    (tmp_path / "sock").mkdir()
    os.chmod(tmp_path / "sock", 0o2750)
    host = _host(tmp_path, allowed_uids=frozenset({_agent_uid()}))
    session = host.open_session(_peer())
    assert host.handle_request(b"[]", session)["reason_code"] == "envelope_invalid"

    def boom() -> None:
        raise abort_error("worker refused to stop")

    host._executors.abort_calls = boom  # type: ignore[method-assign]
    box: list[BaseException] = []

    def run() -> None:
        try:
            host.serve_forever(stop=host._stop)
        except BaseException as exc:  # noqa: BLE001 - the escape is the point
            box.append(exc)

    serving = threading.Thread(target=run, daemon=True)
    serving.start()
    try:
        time.sleep(0.2)
        host.request_stop()
        serving.join(timeout=5)
        assert not serving.is_alive()
        assert box and isinstance(box[0], abort_error)
        assert host._log_closed
        with pytest.raises(Exception):
            host._decisions.append({"decision": "DENY", "reason_code": "probe"})
    finally:
        host._executors.abort_calls = lambda: None  # type: ignore[method-assign]
        host._executors.close()


def test_a_decision_that_outlives_the_drain_is_counted_not_lost(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A call holding a log ticket when the drain bound passes cannot append; it is counted."""
    from pep.host import server as server_module

    monkeypatch.setattr(server_module, "SHUTDOWN_DRAIN_SECONDS", 0.2)

    def registered(_args: dict) -> dict:
        # Runs in a forked worker; it outlives the shortened drain and then returns.
        time.sleep(1.0)
        return {"pong": "ok"}

    host = _host(tmp_path, registry={"echo.ping": registered})
    session = host.open_session(_peer())
    host.issue_session_approval(session, tool_name="echo.ping", args=ARGS, ttl_seconds=60)
    box: list[dict[str, Any]] = []
    caller = threading.Thread(
        target=lambda: box.append(host.handle_request({"tool_name": "echo.ping", "args": ARGS}, session)),
        daemon=True,
    )
    caller.start()
    try:
        time.sleep(0.3)
        host._shutdown_log()
        assert host._log_closed
        assert host.refused_after_close == 0
    finally:
        caller.join(timeout=5)
        host.close()
    assert not caller.is_alive()
    assert box[0]["decision"] == "DENY"
    assert box[0]["reason_code"] == "kill_active"
    assert host.refused_after_close == 1


# Finding P-3: an agent controls the names in its request. A denial must not
# copy an unbounded list of them into the log, and no line may exceed the cap.


def _log_lines(path: Path) -> list[bytes]:
    return [line for line in path.read_bytes().split(b"\n") if line]


def _assert_listed_keys_are_clipped(detail: str, total: int) -> None:
    import pep.host.log as host_log

    assert detail.startswith("unknown keys: ")
    assert detail.endswith(f" (+{total - host_log.MAX_LISTED_KEYS} more)")
    listed = detail[len("unknown keys: ") :].rsplit(" (+", 1)[0].split(", ")
    assert len(listed) == host_log.MAX_LISTED_KEYS
    assert all(len(name) <= host_log.MAX_KEY_CHARS for name in listed)


def test_unknown_envelope_key_flood_is_clipped_in_the_log(tmp_path: Path):
    import pep.host.log as host_log

    host = _host(tmp_path)
    session = host.open_session(_peer())
    extras: dict[str, Any] = {f"k{i:05d}": 1 for i in range(4000)}
    extras["a" + "x" * 5000] = 1
    decision = host.handle_request({"tool_name": "echo.ping", "args": ARGS, **extras}, session)
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "envelope_invalid"
    lines = _log_lines(tmp_path / "decisions.log")
    assert all(len(line) <= host_log.MAX_RECORD_BYTES for line in lines)
    record = json.loads(lines[-1])
    check = next(item for item in record["checks"] if item["name"] == "envelope_keys")
    _assert_listed_keys_are_clipped(check["detail"], len(extras))
    assert "truncated" not in record
    _assert_record_claims_only_what_ran(record)


def test_unknown_args_key_flood_is_clipped_in_the_log(tmp_path: Path):
    import pep.host.log as host_log

    host = _host(tmp_path)
    session = host.open_session(_peer())
    args: dict[str, Any] = {"message": "hi", **{f"arg{i:05d}" + "y" * 80: 1 for i in range(500)}}
    decision = host.handle_request({"tool_name": "echo.ping", "args": args}, session)
    assert decision["decision"] == "DENY"
    assert decision["reason_code"] == "envelope_invalid"
    lines = _log_lines(tmp_path / "decisions.log")
    assert all(len(line) <= host_log.MAX_RECORD_BYTES for line in lines)
    record = json.loads(lines[-1])
    check = next(item for item in record["checks"] if item["name"] == "args_keys")
    _assert_listed_keys_are_clipped(check["detail"], 500)


def test_decision_log_caps_one_record_and_marks_it(tmp_path: Path):
    import pep.host.log as host_log

    path = tmp_path / "decisions.log"
    log = DecisionLog(path)
    small = log.append({"decision": "DENY", "reason_code": "envelope_invalid", "request_id": "r1", "checks": []})
    assert "truncated" not in small

    long_detail = {"name": "args_keys", "outcome": "deny", "detail": "z" * 50_000}
    clipped = log.append(
        {"decision": "DENY", "reason_code": "envelope_invalid", "request_id": "r2", "checks": [long_detail]}
    )
    assert clipped["truncated"].startswith("record of ")
    assert len(clipped["checks"][0]["detail"]) == host_log.MAX_FIELD_CHARS

    many = [{"name": f"c{i}", "outcome": "deny", "detail": "w" * 200} for i in range(60)]
    flat = log.append({"decision": "DENY", "reason_code": "envelope_invalid", "request_id": "r3", "checks": many})
    assert "check names and outcomes kept" in flat["truncated"]
    assert flat["checks"][0] == {"name": "c0", "outcome": "deny"}

    flood = [{"name": f"c{i}", "outcome": "deny"} for i in range(5000)]
    core = log.append({"decision": "DENY", "reason_code": "envelope_invalid", "request_id": "r4", "checks": flood})
    assert "only core fields kept" in core["truncated"]
    assert core["decision"] == "DENY" and core["reason_code"] == "envelope_invalid" and core["seq"] == 4

    lines = _log_lines(path)
    assert len(lines) == 4
    assert all(len(line) <= host_log.MAX_RECORD_BYTES for line in lines)
    assert log.read_records() == [small, clipped, flat, core]
    log.close()
