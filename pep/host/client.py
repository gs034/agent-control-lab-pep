# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Minimal client for the reference host.

Sends ``tool_name`` and ``args`` only. It cannot set the clock, the
principal, or the function that runs.

A dead host, a timeout, or a peer that is not the expected host user
comes back as a DENY. This function does not raise for those cases.
"""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import threading
from pathlib import Path
from typing import Any

from pep.host.protocol import MAX_REQUEST_BYTES
from pep.host.server import HostError, peer_credentials

DEFAULT_TIMEOUT_SECONDS = 5.0
_REQUEST_ID = re.compile(r"host\.(\d+)\.(\d+)")


class _ClientDeny(Exception):
    """Turned into a DENY dict at the public boundary."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def invoke(
    socket_path: Path | str,
    tool_name: str,
    args: dict[str, Any],
    *,
    host_uid: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """One request on a new connection. The connection is the session.

    ``host_uid`` is the user the real host runs as. The socket file must
    be owned by that user, and the process that accepts the connection
    must have that user id (``SO_PEERCRED``). Either mismatch is a DENY.
    """
    try:
        payload = json.dumps(
            {"args": args, "tool_name": tool_name},
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return _deny("envelope_invalid", "request is not JSON")
    if len(payload) > MAX_REQUEST_BYTES:
        return _deny("envelope_invalid", "request exceeds the host limit")
    try:
        with _connect_attested(socket_path, host_uid, timeout) as sock:
            sock.sendall(payload + b"\n")
            return _read_response(sock, require_decision=True)
    except _ClientDeny as exc:
        return _deny(exc.reason, exc.detail)
    except (TimeoutError, OSError):
        return _deny("host_unreachable", "host is not listening")


def admin_call(
    admin_path: Path | str,
    body: dict[str, Any],
    *,
    host_uid: int,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """One operator request on the admin socket. Not for the agent."""
    try:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        return _deny("envelope_invalid", "admin request is not JSON")
    if len(payload) > MAX_REQUEST_BYTES:
        return _deny("envelope_invalid", "request exceeds the host limit")
    try:
        with _connect_attested(admin_path, host_uid, timeout) as sock:
            sock.sendall(payload + b"\n")
            return _read_response(sock, require_decision=False)
    except _ClientDeny as exc:
        return _deny(exc.reason, exc.detail)
    except (TimeoutError, OSError):
        return _deny("host_unreachable", "host is not listening")


def _connect_attested(path: Path | str, host_uid: int, timeout: float) -> socket.socket:
    socket_path = Path(path)
    try:
        info = os.lstat(socket_path)
    except OSError as exc:
        raise _ClientDeny("host_unreachable", "host socket is not there") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise _ClientDeny("host_unattested", "host socket path is not a socket")
    if info.st_uid != host_uid:
        raise _ClientDeny("host_unattested", "host socket is not owned by the expected user")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        try:
            peer = peer_credentials(sock)
        except HostError as exc:
            raise _ClientDeny("host_unattested", "host peer credentials unreadable") from exc
        if peer.uid != host_uid:
            raise _ClientDeny(
                "host_unattested",
                "host peer uid does not match the expected host user",
            )
    except _ClientDeny:
        sock.close()
        raise
    except (TimeoutError, OSError) as exc:
        sock.close()
        raise _ClientDeny("host_unreachable", "host is not listening") from exc
    return sock


def _read_response(sock: socket.socket, *, require_decision: bool) -> dict[str, Any]:
    buf = b""
    while b"\n" not in buf:
        if len(buf) > MAX_REQUEST_BYTES:
            return _deny("envelope_invalid", "host response exceeds the limit")
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            return _deny("host_unreachable", "host timed out")
        except OSError:
            return _deny("host_unreachable", "host is not listening")
        if not chunk:
            break
        buf += chunk
    if not buf.strip():
        return _deny("host_unreachable", "host closed the connection")
    return _parse_reply(buf.split(b"\n", 1)[0], require_decision=require_decision)


def _parse_reply(line: bytes, *, require_decision: bool) -> dict[str, Any]:
    try:
        parsed = json.loads(line.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        return _deny("envelope_invalid", "host response is not a JSON object")
    if not isinstance(parsed, dict):
        return _deny("envelope_invalid", "host response is not a JSON object")
    if require_decision and parsed.get("decision") not in {"ALLOW", "DENY"}:
        return _deny("envelope_invalid", "host response has no decision")
    return parsed


class AgentConnection:
    """A held connection, which is the session the operator grants against.

    The host mints a grant for one live connection, so an agent makes its
    calls on one connection it keeps open. ``invoke`` opens a new connection
    per call, so a grant minted in advance never applies to it. The host
    closes a connection after 5 seconds with no bytes, and 30 seconds after it
    was accepted. A closed connection gives DENY; the next connection is a new
    session with no grant.

    Threads may share one instance. Each call holds the lock from its send to
    its reply, so a reply is read by the call that sent its request. A reply
    that is not one JSON object with a decision, or whose request id is not
    from this connection in increasing order, closes the connection and is a
    DENY.

    A DENY with ``host_unreachable`` after the request was sent does not mean
    the tool did not run: the host may have admitted the call and still be
    running it. Check the decision log before retrying an effect.
    """

    def __init__(self, socket_path: Path | str, *, host_uid: int, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._socket_path = socket_path
        self._host_uid = host_uid
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._refused: dict[str, str] | None = None
        self._buf = b""
        self._lock = threading.RLock()
        self._connection: str | None = None
        self._last_number = 0

    def __enter__(self) -> AgentConnection:
        self.close()
        with self._lock:
            self._refused = None
            self._buf = b""
            self._connection = None
            self._last_number = 0
            try:
                self._sock = _connect_attested(self._socket_path, self._host_uid, self._timeout)
            except _ClientDeny as exc:
                self._refused = _deny(exc.reason, exc.detail)
            except OSError:
                self._refused = _deny("host_unreachable", "could not open a connection to the host")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def call(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            return self._call_locked(tool_name, args)

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            self._buf = b""

    def _call_locked(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if self._sock is None:
            return self._refused or _deny("host_unreachable", "connection is not open")
        try:
            payload = json.dumps({"args": args, "tool_name": tool_name}, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            return _deny("envelope_invalid", "request is not JSON")
        if len(payload) > MAX_REQUEST_BYTES:
            return _deny("envelope_invalid", "request exceeds the host limit")
        try:
            self._sock.sendall(payload + b"\n")
            line = self._read_line()
        except (TimeoutError, OSError):
            self.close()
            return _deny("host_unreachable", "host did not reply")
        if line is None:
            self.close()
            return _deny("host_unreachable", "host closed the connection")
        try:
            reply = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
            self.close()
            return _deny("envelope_invalid", "host response is not valid JSON")
        if not isinstance(reply, dict) or reply.get("decision") not in {"ALLOW", "DENY"}:
            self.close()
            return _deny("envelope_invalid", "host response has no decision")
        problem = self._check_request_id(reply)
        if problem is not None:
            self.close()
            return _deny("host_unattested", problem)
        return reply

    def _check_request_id(self, reply: dict[str, Any]) -> str | None:
        """Why the reply does not belong to this connection, or None.

        The host numbers requests with one counter for the whole process, so
        the numbers on one connection rise but are not consecutive. The
        connection part is fixed for this connection, and the number must rise.
        """
        request_id = reply.get("request_id")
        match = _REQUEST_ID.fullmatch(request_id) if isinstance(request_id, str) else None
        if match is None:
            return "host reply carries no request id"
        connection, number = match.group(1), int(match.group(2))
        if self._connection is None:
            self._connection = connection
        elif connection != self._connection:
            return "host reply is for another connection"
        if number <= self._last_number:
            return "host reply is out of order"
        self._last_number = number
        return None

    def _read_line(self) -> bytes | None:
        while b"\n" not in self._buf:
            if len(self._buf) > MAX_REQUEST_BYTES:
                raise OSError("host response exceeds the limit")
            chunk = self._sock.recv(4096)
            if not chunk:
                return None
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line


def _deny(reason: str, detail: str) -> dict[str, str]:
    return {"decision": "DENY", "reason_code": reason, "reason_detail": detail}
