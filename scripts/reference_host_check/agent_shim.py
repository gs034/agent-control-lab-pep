# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent-side end of the live deployment check: one held connection.

Run as the agent user. Usage:

    agent_shim.py SOCKET            raw: each stdin line is one request line
    agent_shim.py SOCKET HOST_UID   client: each stdin line is {"tool_name", "args"},
                                    sent through pep.host.client.AgentConnection

The connection stays open between lines, so the session survives between
requests. One reply line is printed per request.
"""

import json
import socket
import sys

from pep.host.client import AgentConnection


def raw(path: str) -> None:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(path)
    stream = conn.makefile("rwb")
    for text in sys.stdin:
        text = text.rstrip("\n")
        if not text:
            continue
        stream.write(text.encode("utf-8") + b"\n")
        stream.flush()
        reply = stream.readline()
        print(reply.decode("utf-8", "replace").strip() if reply else "EOF", flush=True)
    conn.close()


def via_client(path: str, host_uid: int) -> None:
    with AgentConnection(path, host_uid=host_uid) as held:
        for text in sys.stdin:
            text = text.rstrip("\n")
            if not text:
                continue
            request = json.loads(text)
            print(json.dumps(held.call(request["tool_name"], request["args"])), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        via_client(sys.argv[1], int(sys.argv[2]))
    else:
        raw(sys.argv[1])
