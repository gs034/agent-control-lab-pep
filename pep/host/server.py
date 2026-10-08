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

import errno
import hashlib
import json
import os
import socket
import stat
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pep.approval import ApprovalRecord, is_principal
from pep.evaluate import PepRuntime
from pep.gate import begin_invoke, complete_invoke
from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError
from pep.host.fsguard import PathGuardError, require_directory
from pep.host.haltfile import (
    ACTIVE,
    SUSPENDED,
    init_active,
    read_fail_closed,
    write_killed,
)
from pep.host.log import DecisionLog, DecisionLogError
from pep.host.protocol import MAX_REQUEST_BYTES, ProtocolError, parse_host_request
from pep.policy import DEMO_POLICY, PolicyStore

RegistryTool = Callable[[Mapping[str, Any]], Any]

MAX_CONNECTIONS = 8
IDLE_TIMEOUT_SECONDS = 5.0
DENY_LOG_BURST = 30
DENY_LOG_WINDOW_SECONDS = 1.0
ADMIN_MAX_CONNECTIONS = 4
SOCKET_MODE = 0o660
ADMIN_SOCKET_MODE = 0o600
_PROBE_TIMEOUT_SECONDS = 0.2


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
    """Linux peer credentials (pid, uid, gid) for a Unix-socket connection.

    These are the credentials of the process that called ``connect``.
    If that process passes the connected file descriptor to another
    process, the host still sees the original process. The host does
    not notice the hand-off.
    """
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
        admin_path: Path | None = None,
        allowed_uids: Collection[int] | None = None,
        allowed_gids: Collection[int] | None = None,
        max_connections: int = MAX_CONNECTIONS,
        idle_timeout: float = IDLE_TIMEOUT_SECONDS,
        deny_log_burst: int = DENY_LOG_BURST,
        deny_log_window: float = DENY_LOG_WINDOW_SECONDS,
    ) -> None:
        self.halt_path = Path(halt_path)
        self.socket_path = None if socket_path is None else Path(socket_path)
        self.admin_path = None if admin_path is None else Path(admin_path)
        self._clock = clock or _system_clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._admin_listener: socket.socket | None = None
        self._next_connection = 0
        self._next_request = 0
        self._sessions: list[Session] = []
        self._known: set[str] = set()
        self._grants: dict[str, list[str]] = {}
        self._sticky_halt = False
        self._live = 0
        self._admin_live = 0
        self._max_connections = max_connections
        self._idle_timeout = idle_timeout
        self._deny_burst = deny_log_burst
        self._deny_window = deny_log_window
        self._deny_stamps: deque[float] = deque()
        self._suppressed = 0
        self._last_coalesce = 0.0
        self._allowed_uids = _id_set(allowed_uids, "uid")
        self._allowed_gids = _id_set(allowed_gids, "gid")
        self._policy_path = None if policy_path is None else Path(policy_path)
        self._file_digest: str | None = None
        if max_connections < 1 or idle_timeout <= 0 or deny_log_burst < 1 or deny_log_window <= 0:
            raise HostError("connection and log limits must be positive")
        _require_private(self.halt_path.parent)
        if self.admin_path is not None:
            if self.socket_path is not None and self.admin_path.absolute() == self.socket_path.absolute():
                raise HostError("admin socket must be a different path from the agent socket")
            _require_private(self.admin_path.parent)
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

    def peer_permitted(self, peer: PeerCred) -> bool:
        """True when no allow list is set, or the peer is on each list that is set."""
        if self._allowed_uids is not None and peer.uid not in self._allowed_uids:
            return False
        if self._allowed_gids is not None and peer.gid not in self._allowed_gids:
            return False
        return True

    def init_halt(self) -> None:
        """Create an active halt file before this process has latched a halt.

        A process that already observed a missing, bad, or killed file stays
        halted. Init does not clear that, and it does not rewrite a suspend
        as active. Start again after an active file exists.
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
        try:
            return self._decide(raw, session)
        except RecursionError:
            return self._parse_failure(session, "request nesting exceeded the host limit")
        except (MemoryError, OverflowError, ValueError, OSError, TypeError):
            return self._parse_failure(session, "request could not be read")

    def serve_forever(self, *, stop: threading.Event | None = None, ready: threading.Event | None = None) -> None:
        """Listen on the Unix socket until ``stop`` is set."""
        if self.socket_path is None:
            raise HostError("socket path is required")
        if not hasattr(socket, "SO_PEERCRED"):
            raise HostError("this operating system does not report Unix-socket peer credentials")
        listener = self._open_agent_socket()
        self._listener = listener
        admin_listener: socket.socket | None = None
        stop_flag = stop if stop is not None else self._stop
        try:
            if self.admin_path is not None:
                admin_listener = self._open_admin_socket()
                self._admin_listener = admin_listener
                threading.Thread(
                    target=self._admin_loop,
                    args=(admin_listener, stop_flag),
                    daemon=True,
                ).start()
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
                if not self._acquire_slot():
                    self._reject_busy(conn)
                    continue
                worker = threading.Thread(target=self._serve_connection, args=(conn,), daemon=True)
                try:
                    worker.start()
                except Exception:
                    self._release_slot()
                    conn.close()
                    raise
        finally:
            listener.close()
            self._listener = None
            if admin_listener is not None:
                try:
                    admin_listener.close()
                except OSError:
                    pass
                self._admin_listener = None

    def serve_in_background(self) -> threading.Thread:
        """Start ``serve_forever`` on a daemon thread. Used by tests and local runs."""
        ready = threading.Event()
        box: list[BaseException] = []

        def run() -> None:
            try:
                self.serve_forever(stop=self._stop, ready=ready)
            except Exception as exc:
                box.append(exc)
                ready.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        if not ready.wait(timeout=2):
            raise HostError("reference host did not start listening")
        if box:
            raise box[0]
        return thread

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        admin = self._admin_listener
        if admin is not None:
            try:
                admin.close()
            except OSError:
                pass
        self._decisions.close()

    def _decide(self, raw: bytes | str | Any, session: Session) -> dict[str, Any]:
        request_id = self._request_id(session)
        if session.principal not in self._known:
            return self._logged(
                session,
                "DENY",
                "envelope_invalid",
                "session is not bound to a connection this host accepted",
                [{"name": "connection", "outcome": "deny"}],
                tool_name=None,
                now=None,
                request_id=request_id,
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
                request_id=request_id,
            )

        blocked = self._halt_block()
        if blocked is not None:
            check, reason, detail = blocked
            return self._logged(
                session, "DENY", reason, detail, [check], tool_name=None, now=now, request_id=request_id
            )

        checks: list[dict[str, str]] = [{"name": "halt_file", "outcome": "pass", "observed": ACTIVE}]
        try:
            tool_name, args, parse_checks = parse_host_request(raw)
        except ProtocolError as exc:
            checks.extend(exc.checks)
            return self._logged(
                session, "DENY", exc.reason, exc.detail, checks, tool_name=None, now=now, request_id=request_id
            )
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
                request_id=request_id,
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
                request_id=request_id,
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
                request_id=request_id,
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
                request_id=request_id,
            )
        checks.append({"name": "approval_match", "outcome": status})

        envelope = self._internal_envelope(session, tool_name, args, approval_id, request_id)
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
                request_id=request_id,
            )

        # The log has to accept a line before the tool runs. This line is not
        # the ALLOW. The ALLOW is written after the tool, with the outcome.
        if not self._append(
            session,
            "PRE_ENTRY",
            str(decision.receipt.reason_code),
            "checks recorded; tool not entered yet",
            checks,
            tool_name,
            now,
            request_id,
        ):
            return _response(
                "DENY",
                "kill_active",
                "decision log append failed before tool entry; fail-closed deny",
                request_id,
            )

        # A kill that lands after the first halt check, including during the
        # log fsync, is read again here. The tool does not run.
        blocked = self._halt_block()
        if blocked is not None:
            check, reason, detail = blocked
            return self._logged(
                session,
                "DENY",
                reason,
                detail,
                [check],
                tool_name=tool_name,
                now=now,
                request_id=request_id,
            )

        impl = self._registry[tool_name]
        snapshot = dict(args)

        def run_registered() -> Any:
            return impl(snapshot)

        try:
            finished, result = complete_invoke(pending, run_registered)
        except Exception:
            self._logged(
                session,
                "DENY",
                "tool_failed",
                "host tool raised after entry",
                [{"name": "registry_tool", "outcome": "raised"}],
                tool_name=tool_name,
                now=now,
                request_id=request_id,
            )
            return _response("DENY", "tool_failed", "host tool raised after entry", request_id)
        if not finished.allowed():
            return self._logged(
                session,
                "DENY",
                str(finished.receipt.reason_code),
                finished.receipt.reason_detail,
                [{"name": "registry_tool", "outcome": "not_entered"}],
                tool_name=tool_name,
                now=now,
                request_id=request_id,
            )
        outcome = [dict(item) for item in checks]
        outcome.append({"name": "registry_tool", "outcome": "entered"})
        if not self._append(
            session,
            "ALLOW",
            str(finished.receipt.reason_code),
            finished.receipt.reason_detail,
            outcome,
            tool_name,
            now,
            request_id,
        ):
            return _response(
                "DENY",
                "kill_active",
                "decision log append failed after tool entry; fail-closed deny",
                request_id,
            )
        response = _response(
            "ALLOW",
            str(finished.receipt.reason_code),
            finished.receipt.reason_detail,
            request_id,
        )
        try:
            encoded = json.dumps(result, ensure_ascii=True)
            parsed = json.loads(encoded)
        except (TypeError, ValueError, RecursionError):
            response["reason_detail"] = "host tool returned a value that is not JSON"
            return response
        response["result"] = parsed
        response["result_origin"] = "host-registry"
        return response

    def _serve_connection(self, conn: socket.socket) -> None:
        session: Session | None = None
        try:
            try:
                peer = peer_credentials(conn)
            except HostError as exc:
                self._refuse_unattested(conn, str(exc), reason="envelope_invalid")
                return
            if not self.peer_permitted(peer):
                self._refuse_unattested(
                    conn,
                    "peer is not on the host allow list",
                    reason="peer_rejected",
                    peer=peer,
                )
                return
            session = self.open_session(peer)
            conn.settimeout(self._idle_timeout)
            buf = b""
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except TimeoutError:
                    if self._stop.is_set():
                        break
                    request_id = self._request_id(session)
                    response = self._logged(
                        session,
                        "DENY",
                        "idle_timeout",
                        "connection was idle and was closed",
                        [{"name": "idle_timeout", "outcome": "deny"}],
                        tool_name=None,
                        now=None,
                        request_id=request_id,
                    )
                    _send_line(conn, response)
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_REQUEST_BYTES and b"\n" not in buf[: MAX_REQUEST_BYTES + 1]:
                    response = self.handle_request(b" " * (MAX_REQUEST_BYTES + 1), session)
                    _send_line(conn, response)
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        response = self.handle_request(line, session)
                    except Exception:
                        response = self._parse_failure(session, "request could not be read")
                    _send_line(conn, response)
        finally:
            if session is not None:
                self._drop_session(session)
            self._release_slot()
            try:
                conn.close()
            except OSError:
                pass

    def _admin_loop(self, listener: socket.socket, stop_flag: threading.Event) -> None:
        try:
            listener.listen(4)
            listener.settimeout(0.2)
            while not stop_flag.is_set():
                try:
                    conn, _addr = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if stop_flag.is_set():
                        break
                    return
                if not self._acquire_admin_slot():
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
                worker = threading.Thread(target=self._serve_admin, args=(conn,), daemon=True)
                try:
                    worker.start()
                except Exception:
                    self._release_admin_slot()
                    conn.close()
        finally:
            try:
                listener.close()
            except OSError:
                pass

    def _serve_admin(self, conn: socket.socket) -> None:
        try:
            try:
                peer = peer_credentials(conn)
            except HostError:
                _send_line(conn, {"ok": False, "error": "peer credentials unreadable"})
                return
            # The admin socket is the operator's. An allow-listed agent uid
            # does not become an operator by connecting here.
            if peer.uid != os.getuid():
                _send_line(conn, {"ok": False, "error": "admin peer is not the host user"})
                return
            conn.settimeout(self._idle_timeout)
            buf = b""
            while b"\n" not in buf:
                if len(buf) > MAX_REQUEST_BYTES:
                    _send_line(conn, {"ok": False, "error": "admin request exceeds the host limit"})
                    return
                try:
                    chunk = conn.recv(4096)
                except (TimeoutError, OSError):
                    return
                if not chunk:
                    return
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            _send_line(conn, self._admin_request(line))
        finally:
            self._release_admin_slot()
            try:
                conn.close()
            except OSError:
                pass

    def _admin_request(self, raw: bytes) -> dict[str, Any]:
        try:
            if len(raw) > MAX_REQUEST_BYTES:
                return {"ok": False, "error": "admin request exceeds the host limit"}
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError, OverflowError):
            return {"ok": False, "error": "admin request is not a JSON object"}
        if not isinstance(body, dict):
            return {"ok": False, "error": "admin request is not a JSON object"}
        op = body.get("op")
        if op == "sessions":
            return {"ok": True, "sessions": [self._session_view(item) for item in self.sessions()]}
        if op == "grant":
            return self._admin_grant(body)
        return {"ok": False, "error": "unknown admin op"}

    def _admin_grant(self, body: Mapping[str, Any]) -> dict[str, Any]:
        connection_id = body.get("connection_id")
        tool_name = body.get("tool_name")
        args = body.get("args")
        ttl = body.get("ttl_seconds")
        if isinstance(connection_id, bool) or not isinstance(connection_id, int):
            return {"ok": False, "error": "connection_id must be an integer"}
        if not isinstance(tool_name, str):
            return {"ok": False, "error": "tool_name must be a string"}
        if not isinstance(args, dict):
            return {"ok": False, "error": "args must be an object"}
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            return {"ok": False, "error": "ttl_seconds must be a positive integer"}
        session = next((item for item in self.sessions() if item.connection_id == connection_id), None)
        if session is None:
            return {"ok": False, "error": "no such connection"}
        try:
            record = self.issue_session_approval(
                session,
                tool_name=tool_name,
                args=args,
                ttl_seconds=ttl,
            )
        except (HostError, ValueError, HaltStoreError) as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": True,
            "approval_id": record.approval_id,
            "principal": session.principal,
            "connection_id": connection_id,
        }

    def _session_view(self, session: Session) -> dict[str, int | str]:
        return {
            "connection_id": session.connection_id,
            "principal": session.principal,
            "peer_pid": session.peer.pid,
            "peer_uid": session.peer.uid,
            "peer_gid": session.peer.gid,
        }

    def _open_agent_socket(self) -> socket.socket:
        assert self.socket_path is not None
        try:
            directory = require_directory(self.socket_path.parent, allow_group_traverse=True)
        except PathGuardError as exc:
            raise HostError(str(exc)) from exc
        return _bind_unix(self.socket_path, SOCKET_MODE, directory.st_gid)

    def _open_admin_socket(self) -> socket.socket:
        assert self.admin_path is not None
        try:
            require_directory(self.admin_path.parent, allow_group_traverse=False)
        except PathGuardError as exc:
            raise HostError(str(exc)) from exc
        return _bind_unix(self.admin_path, ADMIN_SOCKET_MODE, None)

    def _parse_failure(self, session: Session, detail: str) -> dict[str, Any]:
        request_id = self._request_id(session)
        return self._logged(
            session,
            "DENY",
            "envelope_invalid",
            detail,
            [{"name": "json_object", "outcome": "deny"}],
            tool_name=None,
            now=None,
            request_id=request_id,
        )

    def _refuse_unattested(
        self,
        conn: socket.socket,
        detail: str,
        *,
        reason: str,
        peer: PeerCred | None = None,
    ) -> None:
        """No usable peer credentials means no session and no tool entry."""
        request_id = self._request_id(None)
        if not self._claim_denial_slot():
            self._coalesce_denial(None, request_id)
        else:
            record: dict[str, Any] = {
                "decision": "DENY",
                "reason_code": reason,
                "reason_detail": _clip(detail),
                "checks": [{"name": "peer_credentials", "outcome": "deny"}],
                "request_id": request_id,
            }
            if peer is not None:
                record["peer_pid"] = peer.pid
                record["peer_uid"] = peer.uid
                record["peer_gid"] = peer.gid
            try:
                self._decisions.append(record)
            except (DecisionLogError, OSError, ValueError):
                self._sticky_halt = True
        _send_line(conn, _response("DENY", reason, detail, request_id))
        try:
            conn.close()
        except OSError:
            pass

    def _reject_busy(self, conn: socket.socket) -> None:
        request_id = self._request_id(None)
        try:
            conn.settimeout(1)
        except OSError:
            pass
        response = self._logged(
            None,
            "DENY",
            "connection_limit",
            "too many connections",
            [{"name": "connection_limit", "outcome": "deny"}],
            tool_name=None,
            now=None,
            request_id=request_id,
        )
        _send_line(conn, response)
        try:
            conn.close()
        except OSError:
            pass

    def _acquire_slot(self) -> bool:
        with self._lock:
            if self._live >= self._max_connections:
                return False
            self._live += 1
            return True

    def _release_slot(self) -> None:
        with self._lock:
            if self._live > 0:
                self._live -= 1

    def _acquire_admin_slot(self) -> bool:
        with self._lock:
            if self._admin_live >= ADMIN_MAX_CONNECTIONS:
                return False
            self._admin_live += 1
            return True

    def _release_admin_slot(self) -> None:
        with self._lock:
            if self._admin_live > 0:
                self._admin_live -= 1

    def _drop_session(self, session: Session) -> None:
        """Forget a closed connection so the session list cannot grow without bound."""
        with self._lock:
            self._sessions = [item for item in self._sessions if item.connection_id != session.connection_id]
            self._known.discard(session.principal)
            self._grants.pop(session.principal, None)

    def _load_policy(self, policy: PolicyStore | None) -> PolicyStore:
        if self._policy_path is None:
            return policy if policy is not None else DEMO_POLICY
        try:
            raw = self._policy_path.read_bytes()
            document = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
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
        if observed not in {ACTIVE, SUSPENDED}:
            self._sticky_halt = True
            # No halt store: constructing one would treat a missing file as active
            # and could write that active state back.
            return PepRuntime(policy=self._policy, kill_active=True)
        runtime = PepRuntime(
            policy=self._policy,
            halt_store=HaltStore(self.halt_path),
            persist_on_load=False,
        )
        _again, again = read_fail_closed(self.halt_path)
        if again != observed:
            # The file changed while the runtime was opening. Do not leave a
            # fresh active file in that gap. A kill is fail-closed.
            self._sticky_halt = True
            try:
                runtime.kill()
            except Exception:
                self._sticky_halt = True
            return runtime
        self._restrict_halt()
        return runtime

    def _restrict_halt(self) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.halt_path, flags)
        except OSError as exc:
            self._sticky_halt = True
            raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc
        try:
            os.fchmod(fd, 0o600)
        except OSError as exc:
            self._sticky_halt = True
            raise HaltStoreError(f"could not restrict the halt file: {exc}") from exc
        finally:
            os.close(fd)

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
        # One read. A second read of a file that vanished in between would
        # look active, and this check must not do that.
        _state, observed = read_fail_closed(self.halt_path)
        if self._sticky_halt or self._runtime.kill_active:
            return (
                {"name": "halt_file", "outcome": "deny", "observed": observed},
                "kill_active",
                f"gate halted ({observed})",
            )
        if observed == ACTIVE:
            if self._runtime.suspend_active:
                # A suspend observed at startup is not latched. An active
                # file clears it. Kill and a missing file do not.
                self._runtime.resume()
            return None
        if observed == SUSPENDED:
            if not self._runtime.suspend_active:
                self._runtime.suspend()
            return (
                {"name": "halt_file", "outcome": "deny", "observed": observed},
                "suspend_active",
                "halt file is suspended",
            )
        self._sticky_halt = True
        self._kill_runtime_memory()
        return (
            {"name": "halt_file", "outcome": "deny", "observed": observed},
            "kill_active",
            f"halt file is {observed}; fail-closed deny",
        )

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
        request_id: str,
    ) -> dict[str, Any]:
        return {
            "tool_name": tool_name,
            "args": dict(args),
            "capability_token": None,
            "approval_id": approval_id,
            "caller_identity": session.principal,
            "request_id": request_id,
        }

    def _request_id(self, session: Session | None) -> str:
        with self._lock:
            self._next_request += 1
            number = self._next_request
        connection = 0 if session is None else session.connection_id
        return f"host.{connection}.{number}"

    def _claim_denial_slot(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._deny_stamps and now - self._deny_stamps[0] >= self._deny_window:
                self._deny_stamps.popleft()
            if len(self._deny_stamps) < self._deny_burst:
                self._deny_stamps.append(now)
                return True
            return False

    def _coalesce_denial(self, session: Session | None, request_id: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._suppressed += 1
            count = self._suppressed
            due = now - self._last_coalesce >= self._deny_window
            if due:
                self._last_coalesce = now
        if not due:
            return True
        return self._append(
            session,
            "DENY",
            "rate_limited",
            f"{count} denials coalesced so the decision log cannot fill the disk",
            [{"name": "denial_log", "outcome": "coalesced"}],
            None,
            None,
            request_id,
        )

    def _logged(
        self,
        session: Session | None,
        decision: str,
        reason: str,
        detail: str,
        checks: list[dict[str, str]],
        *,
        tool_name: str | None,
        now: datetime | None,
        request_id: str,
    ) -> dict[str, Any]:
        if decision == "DENY" and not self._claim_denial_slot():
            if not self._coalesce_denial(session, request_id):
                self._sticky_halt = True
                return _response("DENY", "kill_active", "decision log append failed; fail-closed deny", request_id)
            return _response(decision, reason, detail, request_id)
        if not self._append(session, decision, reason, detail, checks, tool_name, now, request_id):
            self._sticky_halt = True
            return _response("DENY", "kill_active", "decision log append failed; fail-closed deny", request_id)
        return _response(decision, reason, detail, request_id)

    def _append(
        self,
        session: Session | None,
        decision: str,
        reason: str,
        detail: str,
        checks: list[dict[str, str]],
        tool_name: str | None,
        now: datetime | None,
        request_id: str,
    ) -> bool:
        record: dict[str, Any] = {
            "decision": decision,
            "reason_code": reason,
            "reason_detail": _clip(detail),
            "request_id": request_id,
            "checks": checks,
        }
        if session is not None:
            record["session_id"] = session.principal
            record["peer_pid"] = session.peer.pid
            record["peer_uid"] = session.peer.uid
            record["peer_gid"] = session.peer.gid
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


def _id_set(values: Collection[int] | None, label: str) -> frozenset[int] | None:
    if values is None:
        return None
    chosen: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise HostError(f"allow list {label} is not a user or group id")
        chosen.add(value)
    return frozenset(chosen)


def _require_private(path: Path) -> None:
    try:
        require_directory(path, allow_group_traverse=False)
    except PathGuardError as exc:
        raise HostError(str(exc)) from exc


def _bind_unix(path: Path, mode: int, group_gid: int | None) -> socket.socket:
    """Bind a Unix socket. The file is mode 000 until its mode is set.

    An existing socket is removed only when a connect probe finds no
    listener. A live socket, a symlink, or a non-socket is left in place
    and the host refuses to start.
    """
    _replace_dead_socket(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound = False
    old_mask = os.umask(0o777)
    try:
        try:
            listener.bind(str(path))
            bound = True
        finally:
            os.umask(old_mask)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
            raise HostError("socket path is not a socket after bind")
        if info.st_uid != os.getuid():
            raise HostError("socket is not owned by this user")
        # umask 0777 made the new socket mode 000, so nothing can connect
        # in the gap. fchmod on a Unix-socket descriptor does not change
        # the mode lstat reports, so the mode is set on the path after the
        # checks above. The directory is not writable by the agent.
        try:
            os.fchmod(listener.fileno(), mode)
        except OSError:
            pass
        os.chmod(path, mode)
        if group_gid is not None:
            try:
                os.chown(path, -1, group_gid)
            except PermissionError:
                # A setgid directory already put the socket in that group.
                pass
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
            raise HostError("socket path is not a socket after bind")
        if info.st_uid != os.getuid():
            raise HostError("socket is not owned by this user")
        actual = stat.S_IMODE(info.st_mode) & 0o777
        if actual != mode:
            raise HostError(f"socket mode is {oct(actual)}, wanted {oct(mode)}")
        if group_gid is not None and info.st_gid != group_gid:
            raise HostError(
                "socket group does not match the socket directory; "
                "make that directory setgid to the agent group"
            )
    except Exception:
        listener.close()
        if bound:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    return listener


def _replace_dead_socket(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise HostError("socket path is a symlink; refusing to replace it")
    if not stat.S_ISSOCK(info.st_mode):
        raise HostError("socket path exists and is not a socket")
    if info.st_uid != os.getuid():
        raise HostError("socket path is owned by another user; refusing to replace it")
    if _socket_is_live(path):
        raise HostError("a host is already listening on this socket")
    try:
        again = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(again.st_mode) or not stat.S_ISSOCK(again.st_mode) or again.st_uid != os.getuid():
        raise HostError("socket path changed; refusing to replace it")
    if (again.st_dev, again.st_ino) != (info.st_dev, info.st_ino):
        raise HostError("socket path changed; refusing to replace it")
    os.unlink(path)


def _socket_is_live(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_PROBE_TIMEOUT_SECONDS)
    try:
        probe.connect(str(path))
    except ConnectionRefusedError:
        return False
    except FileNotFoundError:
        return False
    except TimeoutError as exc:
        raise HostError("socket probe timed out; refusing to replace it") from exc
    except OSError as exc:
        if exc.errno in {errno.ECONNREFUSED, errno.ENOENT}:
            return False
        raise HostError(f"socket path is not usable: {exc}") from exc
    else:
        return True
    finally:
        probe.close()


def _response(decision: str, reason: str, detail: str, request_id: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decision": decision,
        "reason_code": reason,
        "reason_detail": detail,
    }
    if request_id is not None:
        body["request_id"] = request_id
    return body


def _clip(text: str, limit: int = 240) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _send_line(conn: socket.socket, payload: Mapping[str, Any]) -> None:
    try:
        line = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        conn.sendall(line.encode("utf-8") + b"\n")
    except (OSError, TypeError, ValueError, RecursionError):
        pass
