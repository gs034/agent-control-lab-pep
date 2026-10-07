# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Reference host process for the policy enforcement point (PEP).

The host owns the tool registry, the clock, the caller's identity, the
policy, the halt state, and the decision log. An agent sends a request
envelope over a Unix socket. Identity comes from the operating system's
peer credentials on that connection, plus a session this process assigns.
The agent cannot supply the function that runs, the time, or another
session's identity.

This is a reference prototype. It is not a measured attack-success
reduction and not a product. See ADR-0007.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pep.approval import ApprovalRecord, is_principal
from pep.evaluate import PepRuntime
from pep.gate import begin_invoke, complete_invoke
from pep.halt import HaltStore, HaltStoreError
from pep.host.haltfile import (
    ACTIVE,
    SUSPENDED,
    init_active,
    read_fail_closed,
    write_killed,
)
from pep.host.log import DecisionLog, DecisionLogError
from pep.host.protocol import ProtocolError, parse_host_request
from pep.policy import DEMO_POLICY, PolicyStore

RegistryTool = Callable[[Mapping[str, Any]], Any]


class HostError(RuntimeError):
    """The host could not attest a caller or start. Not an allow."""


@dataclass(frozen=True, slots=True)
class PeerCred:
    """Identity taken from the connection, not from the request body."""

    pid: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class Session:
    """One accepted connection. The principal is not a bearer token."""

    principal: str
    peer: PeerCred
    connection_id: int


def echo_ping(args: Mapping[str, Any]) -> dict[str, str]:
    """Built-in registry entry for the stub tool ``echo.ping``."""
    message = args.get("message", "")
    if not isinstance(message, str):
        message = ""
    return {"pong": message}


def default_registry() -> dict[str, RegistryTool]:
    return {"echo.ping": echo_ping}


def peer_credentials(conn: socket.socket) -> PeerCred:
    """Linux peer credentials (pid, uid, gid) for a Unix-socket connection."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise HostError("this operating system does not report Unix-socket peer credentials")
    size = struct.calcsize("3i")
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    except OSError as exc:
        raise HostError(f"peer credentials unreadable: {exc}") from exc
    if len(raw) < size:
        raise HostError("peer credentials truncated")
    pid, uid, gid = struct.unpack("3i", raw[:size])
    if pid < 0 or uid < 0 or gid < 0:
        raise HostError("peer credentials unusable")
    return PeerCred(pid=pid, uid=uid, gid=gid)


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


class ReferenceHost:
    """The gate as its own process. Constructed by the operator, not the agent."""

    def __init__(
        self,
        *,
        halt_path: Path,
        log_path: Path,
        socket_path: Path | None = None,
        policy: PolicyStore | None = None,
        policy_path: Path | None = None,
        registry: Mapping[str, RegistryTool] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.halt_path = Path(halt_path)
        self.socket_path = None if socket_path is None else Path(socket_path)
        self._clock = clock or _system_clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._next_connection = 0
        self._next_request = 0
        self._sessions: list[Session] = []
        self._known: set[str] = set()
        self._grants: dict[str, list[str]] = {}
        self._sticky_halt = False
        self._policy_path = None if policy_path is None else Path(policy_path)
        self._file_digest: str | None = None
        self._policy = self._load_policy(policy)
        self._registry = self._copy_registry(registry)
        self._runtime = self._open_runtime()
        self._decisions = DecisionLog(Path(log_path))

    @property
    def runtime(self) -> PepRuntime:
        return self._runtime

    @property
    def log_path(self) -> Path:
        return self._decisions.path

    def sessions(self) -> tuple[Session, ...]:
        with self._lock:
            return tuple(self._sessions)

    def decision_records(self) -> list[dict[str, Any]]:
        """Records this process appended. The agent socket cannot call this."""
        return self._decisions.read_records()

    def halted(self) -> bool:
        if self._sticky_halt or self._runtime.kill_active:
            return True
        _state, observed = read_fail_closed(self.halt_path)
        return observed != ACTIVE

    def init_halt(self) -> None:
        """Create an active halt file before this process has latched a halt.

        A process that already observed a missing, bad, or killed file stays
        halted. Init does not clear that. Start again after the file exists.
        """
        if self._sticky_halt or self._runtime.kill_active:
            raise HaltStoreError("this process is halted; init does not clear it")
        init_active(self.halt_path)
        self._runtime = self._open_runtime()

    def kill(self) -> None:
        """Persist a kill. A failed write leaves this process halted and raises."""
        self._sticky_halt = True
        try:
            write_killed(self.halt_path)
        except HaltStoreError:
            self._kill_runtime_memory()
            raise
        self._kill_runtime_memory()
        self._restrict_halt()

    def open_session(self, peer: PeerCred) -> Session:
        """Bind a session to peer credentials the host already holds."""
        if peer.pid < 0 or peer.uid < 0 or peer.gid < 0:
            raise HostError("peer credentials unusable")
        with self._lock:
            self._next_connection += 1
            connection_id = self._next_connection
            principal = f"u{peer.uid}.c{connection_id}"
        if not is_principal(principal):
            raise HostError("could not name this connection")
        session = Session(principal=principal, peer=peer, connection_id=connection_id)
        with self._lock:
            self._sessions.append(session)
            self._known.add(principal)
        return session

    def issue_session_approval(
        self,
        session: Session,
        *,
        tool_name: str,
        args: Mapping[str, Any],
        ttl_seconds: int,
    ) -> ApprovalRecord:
        """Mint a grant for one connection. Not available on the agent socket."""
        if session.principal not in self._known:
            raise HostError("that session was not opened by this host")
        record = self._runtime.issue_approval(
            tool_name=tool_name,
            args=dict(args),
            ttl_seconds=ttl_seconds,
            now=self._clock_now(),
            principal=session.principal,
        )
        with self._lock:
            self._grants.setdefault(session.principal, []).append(record.approval_id)
        return record

    def handle_request(self, raw: bytes | str | Any, session: Session) -> dict[str, Any]:
        """Decide one envelope. There is no parameter for a callable or a clock."""
        if session.principal not in self._known:
            return self._logged(
                session,
                "DENY",
                "envelope_invalid",
                "session is not bound to a connection this host accepted",
                [{"name": "connection", "outcome": "deny"}],
                tool_name=None,
                now=None,
            )
        try:
            now = self._clock_now()
        except HostError as exc:
            self._sticky_halt = True
            return self._logged(
                session,
                "DENY",
                "kill_active",
                str(exc),
                [{"name": "host_clock", "outcome": "deny"}],
                tool_name=None,
                now=None,
            )

        blocked = self._halt_block()
        if blocked is not None:
            check, reason, detail = blocked
            return self._logged(session, "DENY", reason, detail, [check], tool_name=None, now=now)

        checks: list[dict[str, str]] = [{"name": "halt_file", "outcome": "pass", "observed": ACTIVE}]
        try:
            tool_name, args, parse_checks = parse_host_request(raw)
        except ProtocolError as exc:
            checks.extend(exc.checks)
            return self._logged(session, "DENY", exc.reason, exc.detail, checks, tool_name=None, now=now)
        checks.extend(parse_checks)

        policy_ok, policy_check, policy_detail = self._policy_observation()
        checks.append(policy_check)
        if not policy_ok:
            self._sticky_halt = True
            self._kill_runtime_memory()
            return self._logged(
                session,
                "DENY",
                "policy_miss",
                policy_detail,
                checks,
                tool_name=tool_name,
                now=now,
            )

        if tool_name not in self._registry:
            checks.append({"name": "registry", "outcome": "deny", "detail": "no host implementation"})
            return self._logged(
                session,
                "DENY",
                "unknown_tool",
                f"no host implementation for {tool_name}",
                checks,
                tool_name=tool_name,
                now=now,
            )
        checks.append({"name": "registry", "outcome": "present"})

        extra_args = self._unknown_arg_keys(tool_name, args)
        if extra_args:
            checks.append(
                {
                    "name": "args_keys",
                    "outcome": "deny",
                    "detail": "unknown keys: " + ", ".join(extra_args),
                }
            )
            return self._logged(
                session,
                "DENY",
                "envelope_invalid",
                f"unknown args keys rejected: {extra_args}",
                checks,
                tool_name=tool_name,
                now=now,
            )
        if extra_args is not None:
            checks.append({"name": "args_keys", "outcome": "pass"})

        status, approval_id = self._select_approval(session, tool_name, args, now)
        if status == "ambiguous":
            checks.append({"name": "approval_match", "outcome": "deny", "detail": "ambiguous"})
            return self._logged(
                session,
                "DENY",
                "approval_invalid",
                "more than one grant matches this session; fail-closed deny",
                checks,
                tool_name=tool_name,
                now=now,
            )
        checks.append({"name": "approval_match", "outcome": status})

        envelope = self._internal_envelope(session, tool_name, args, approval_id)
        pending = begin_invoke(
            envelope,
            runtime=self._runtime,
            now=now,
            principal=session.principal,
        )
        decision = pending.decision
        checks.append(
            {
                "name": "evaluate",
                "outcome": decision.verdict,
                "reason_code": str(decision.receipt.reason_code),
            }
        )
        if not decision.allowed():
            return self._logged(
                session,
                "DENY",
                str(decision.receipt.reason_code),
                decision.receipt.reason_detail,
                checks,
                tool_name=tool_name,
                now=now,
            )

        if not self._append(session, "ALLOW", str(decision.receipt.reason_code), decision.receipt.reason_detail, checks, tool_name, now):
            return _response(
                "DENY",
                "kill_active",
                "decision log append failed before tool entry; fail-closed deny",
            )

        impl = self._registry[tool_name]
        snapshot = dict(args)

        def run_registered() -> Any:
            return impl(snapshot)

        try:
            finished, result = complete_invoke(pending, run_registered)
        except Exception:
            self._append(
                session,
                "DENY",
                "policy_miss",
                "host tool raised after entry",
                [{"name": "registry_tool", "outcome": "raised"}],
                tool_name,
                now,
            )
            return _response("DENY", "policy_miss", "host tool raised after entry")
        if not finished.allowed():
            return self._logged(
                session,
                "DENY",
                str(finished.receipt.reason_code),
                finished.receipt.reason_detail,
                [{"name": "registry_tool", "outcome": "not_entered"}],
                tool_name=tool_name,
                now=now,
            )
        self._append(
            session,
            "ALLOW",
            str(finished.receipt.reason_code),
            finished.receipt.reason_detail,
            [{"name": "registry_tool", "outcome": "entered"}],
            tool_name,
            now,
        )
        response = _response("ALLOW", str(finished.receipt.reason_code), finished.receipt.reason_detail)
        try:
            encoded = json.dumps(result, ensure_ascii=True)
            parsed = json.loads(encoded)
        except (TypeError, ValueError):
            response["reason_detail"] = "host tool returned a value that is not JSON"
            return response
        response["result"] = parsed
        response["result_origin"] = "host-registry"
        return response

    def serve_forever(self, *, stop: threading.Event | None = None, ready: threading.Event | None = None) -> None:
        """Listen on the Unix socket until ``stop`` is set."""
        if self.socket_path is None:
            raise HostError("socket path is required")
        if not hasattr(socket, "SO_PEERCRED"):
            raise HostError("this operating system does not report Unix-socket peer credentials")
        parent = self.socket_path.parent
        if not parent.is_dir():
            raise HostError(f"socket directory does not exist: {parent}")
        if self.socket_path.exists() and not self.socket_path.is_socket():
            raise HostError("socket path exists and is not a socket")
        if self.socket_path.is_socket():
            self.socket_path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener = listener
        stop_flag = stop if stop is not None else self._stop
        try:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o660)
            listener.listen(16)
            listener.settimeout(0.2)
            if ready is not None:
                ready.set()
            while not stop_flag.is_set():
                try:
                    conn, _addr = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if stop_flag.is_set():
                        break
                    raise
                worker = threading.Thread(target=self._serve_connection, args=(conn,), daemon=True)
                worker.start()
        finally:
            listener.close()
            self._listener = None

    def serve_in_background(self) -> threading.Thread:
        """Start ``serve_forever`` on a daemon thread. Used by tests and local runs."""
        ready = threading.Event()
        thread = threading.Thread(
            target=self.serve_forever,
            kwargs={"stop": self._stop, "ready": ready},
            daemon=True,
        )
        thread.start()
        if not ready.wait(timeout=2):
            raise HostError("reference host did not start listening")
        return thread

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        self._decisions.close()

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            try:
                peer = peer_credentials(conn)
            except HostError as exc:
                self._refuse_unattested(conn, str(exc))
                return
            session = self.open_session(peer)
            conn.settimeout(5)
            buf = b""
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65_536 and b"\n" not in buf:
                    response = self.handle_request(b" " * 65_537, session)
                    _send_line(conn, response)
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    response = self.handle_request(line, session)
                    _send_line(conn, response)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _refuse_unattested(self, conn: socket.socket, detail: str) -> None:
        """No peer credentials means no session and no tool entry."""
        try:
            self._decisions.append(
                {
                    "decision": "DENY",
                    "reason_code": "envelope_invalid",
                    "reason_detail": detail,
                    "checks": [{"name": "peer_credentials", "outcome": "deny"}],
                }
            )
        except (DecisionLogError, OSError, ValueError):
            self._sticky_halt = True
        _send_line(
            conn,
            _response("DENY", "envelope_invalid", "peer credentials unreadable; fail-closed deny"),
        )
        try:
            conn.close()
        except OSError:
            pass

    def _load_policy(self, policy: PolicyStore | None) -> PolicyStore:
        if self._policy_path is None:
            return policy if policy is not None else DEMO_POLICY
        try:
            raw = self._policy_path.read_bytes()
            document = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self._sticky_halt = True
            raise HostError(f"policy file unreadable: {exc}") from exc
        if not isinstance(document, dict):
            self._sticky_halt = True
            raise HostError("policy file must be a JSON object")
        self._file_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        return PolicyStore.from_document(document)

    def _copy_registry(self, registry: Mapping[str, RegistryTool] | None) -> dict[str, RegistryTool]:
        from pep.envelope import TOOL_NAME_RE

        chosen = dict(default_registry() if registry is None else registry)
        if not chosen:
            raise HostError("host registry is empty")
        for name, fn in chosen.items():
            if not isinstance(name, str) or not TOOL_NAME_RE.fullmatch(name):
                raise HostError(f"registry tool name is malformed: {name!r}")
            if not callable(fn):
                raise HostError(f"registry entry for {name} is not a function")
        return chosen

    def _open_runtime(self) -> PepRuntime:
        _state, observed = read_fail_closed(self.halt_path)
        if observed != ACTIVE:
            self._sticky_halt = True
            # No halt store: constructing one would treat a missing file as active
            # and could write that active state back.
            return PepRuntime(policy=self._policy, kill_active=True)
        runtime = PepRuntime(policy=self._policy, halt_store=HaltStore(self.halt_path))
        self._restrict_halt()
        return runtime

    def _restrict_halt(self) -> None:
        if not self.halt_path.is_file():
            return
        try:
            self.halt_path.chmod(0o600)
        except OSError as exc:
            self._sticky_halt = True
            raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc

    def _kill_runtime_memory(self) -> None:
        try:
            if not self._runtime.kill_active:
                self._runtime.kill()
        except Exception:
            self._sticky_halt = True

    def _clock_now(self) -> datetime:
        try:
            clock = self._clock()
        except Exception as exc:
            self._sticky_halt = True
            raise HostError("host clock failed; gate halted") from exc
        if not isinstance(clock, datetime) or clock.tzinfo is None:
            self._sticky_halt = True
            raise HostError("host clock must be timezone-aware; gate halted")
        return clock.astimezone(timezone.utc)

    def _halt_block(self) -> tuple[dict[str, str], str, str] | None:
        if self._sticky_halt or self._runtime.kill_active:
            _state, observed = read_fail_closed(self.halt_path)
            return (
                {"name": "halt_file", "outcome": "deny", "observed": observed},
                "kill_active",
                f"gate halted ({observed})",
            )
        _state, observed = read_fail_closed(self.halt_path)
        if observed == SUSPENDED:
            return (
                {"name": "halt_file", "outcome": "deny", "observed": observed},
                "suspend_active",
                "halt file is suspended",
            )
        if observed != ACTIVE:
            self._sticky_halt = True
            self._kill_runtime_memory()
            return (
                {"name": "halt_file", "outcome": "deny", "observed": observed},
                "kill_active",
                f"halt file is {observed}; fail-closed deny",
            )
        return None

    def _policy_observation(self) -> tuple[bool, dict[str, str], str]:
        if self._policy_path is None:
            digest = "sha256:" + self._policy.digest
            return True, {"name": "policy_digest", "outcome": "recorded", "digest": digest}, ""
        try:
            raw = self._policy_path.read_bytes()
        except OSError:
            return (
                False,
                {"name": "policy_file_reread", "outcome": "unreadable"},
                "policy file unreadable on re-read; fail-closed deny",
            )
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest != self._file_digest:
            return (
                False,
                {"name": "policy_file_reread", "outcome": "mismatch", "digest": digest},
                "policy file bytes changed after the host loaded them; fail-closed deny",
            )
        return (
            True,
            {"name": "policy_file_reread", "outcome": "match", "digest": digest},
            "",
        )

    def _unknown_arg_keys(self, tool_name: str, args: Mapping[str, Any]) -> list[str] | None:
        """Unknown argument names, or None when this tool has no schema to check."""
        spec = self._policy.allowed_tools().get(tool_name)
        if not isinstance(spec, Mapping):
            return None
        schema = spec.get("args_schema")
        if not isinstance(schema, Mapping):
            return None
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            return None
        return sorted(set(args) - set(properties))

    def _select_approval(
        self,
        session: Session,
        tool_name: str,
        args: Mapping[str, Any],
        now: datetime,
    ) -> tuple[str, str | None]:
        with self._lock:
            ids = list(self._grants.get(session.principal, ()))
        matched: list[ApprovalRecord] = []
        for approval_id in ids:
            record = self._runtime.approvals.lookup(approval_id)
            if record is None or record.consumed():
                continue
            if record.principal != session.principal:
                continue
            if record.matches_binding(tool_name, args):
                matched.append(record)
        usable = [record for record in matched if not record.expired(now)]
        if len(usable) > 1:
            return "ambiguous", None
        if len(usable) == 1:
            return "one", usable[0].approval_id
        if matched:
            return "expired", matched[0].approval_id
        return "none", None

    def _internal_envelope(
        self,
        session: Session,
        tool_name: str,
        args: Mapping[str, Any],
        approval_id: str | None,
    ) -> dict[str, Any]:
        with self._lock:
            self._next_request += 1
            number = self._next_request
        return {
            "tool_name": tool_name,
            "args": dict(args),
            "capability_token": None,
            "approval_id": approval_id,
            "caller_identity": session.principal,
            "request_id": f"host.{session.connection_id}.{number}",
        }

    def _logged(
        self,
        session: Session,
        decision: str,
        reason: str,
        detail: str,
        checks: list[dict[str, str]],
        *,
        tool_name: str | None,
        now: datetime | None,
    ) -> dict[str, Any]:
        if not self._append(session, decision, reason, detail, checks, tool_name, now):
            self._sticky_halt = True
            return _response("DENY", "kill_active", "decision log append failed; fail-closed deny")
        return _response(decision, reason, detail)

    def _append(
        self,
        session: Session,
        decision: str,
        reason: str,
        detail: str,
        checks: list[dict[str, str]],
        tool_name: str | None,
        now: datetime | None,
    ) -> bool:
        record: dict[str, Any] = {
            "decision": decision,
            "reason_code": reason,
            "reason_detail": detail,
            "session_id": session.principal,
            "peer_pid": session.peer.pid,
            "peer_uid": session.peer.uid,
            "peer_gid": session.peer.gid,
            "checks": checks,
        }
        if tool_name is not None:
            record["tool_name"] = tool_name
        if now is not None:
            record["timestamp"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._decisions.append(record)
        except (DecisionLogError, OSError, ValueError):
            self._sticky_halt = True
            return False
        return True


def _response(decision: str, reason: str, detail: str) -> dict[str, str]:
    return {"decision": decision, "reason_code": reason, "reason_detail": detail}


def _send_line(conn: socket.socket, payload: Mapping[str, Any]) -> None:
    try:
        line = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        conn.sendall(line.encode("utf-8") + b"\n")
    except OSError:
        pass
