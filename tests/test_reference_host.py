# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Reference host regressions for the separate policy enforcement point.

These checks correspond to the gaps where the in-process library trusts
its caller: the callable, the clock, the identity, unknown envelope keys,
a halt file that can be deleted, and a decision that only the caller kept.
"""

from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from pep.evaluate import evaluate
from pep.halt import HaltStoreError
from pep.host.haltfile import ACTIVE, init_active, read_fail_closed
from pep.host.log import FORBIDDEN_KEYS
from pep.host.protocol import ProtocolError, parse_host_request
from pep.host.server import PeerCred, ReferenceHost

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
    )


def _peer(pid: int = 10, uid: int = 1000) -> PeerCred:
    return PeerCred(pid=pid, uid=uid, gid=1000)


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
    halt = tmp_path / "halt.json"
    init_active(halt)
    host = ReferenceHost(
        halt_path=halt,
        log_path=tmp_path / "decisions.log",
        socket_path=sock_dir / "pep.sock",
        registry={"echo.ping": registered},
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
