# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Minimal client for the reference host.

Sends ``tool_name`` and ``args`` only. It cannot set the clock, the
principal, or the function that runs.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from pep.host.protocol import MAX_REQUEST_BYTES


def invoke(socket_path: Path | str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """One request on a new connection. The connection is the session."""
    payload = json.dumps({"args": args, "tool_name": tool_name}, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds the host limit")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(str(socket_path))
        sock.sendall(payload + b"\n")
        return _read_response(sock)


def _read_response(sock: socket.socket) -> dict[str, Any]:
    buf = b""
    while b"\n" not in buf:
        if len(buf) > MAX_REQUEST_BYTES:
            raise ValueError("host response exceeds the limit")
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    line = buf.split(b"\n", 1)[0]
    parsed = json.loads(line.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("host response is not a JSON object")
    return parsed
