# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent-side end of the live deployment check: one held connection.

Run as the agent user. Usage:

    agent_shim.py SOCKET            raw: each stdin line is one request line
    agent_shim.py SOCKET HOST_UID   client: each stdin line is {"tool_name", "args"},
                                    sent through pep.host.client.AgentConnection
    agent_shim.py SOCKET HOST_UID threads
                                    six threads share one AgentConnection; each
                                    stdin line runs one round and prints a summary

The connection stays open between lines, so the session survives between
requests. One reply line is printed per request.
"""

import json
import socket
import sys
import threading

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


def via_threads(path: str, host_uid: int) -> None:
    """Thread 0 sends the granted args; threads 1 to 5 send other args at the same time."""
    granted = {"message": "granted"}
    with AgentConnection(path, host_uid=host_uid) as held:
        for number, text in enumerate(sys.stdin):
            if not text.strip():
                continue
            if json.loads(text).get("round") == "probe":
                print(json.dumps(held.call("echo.ping", {"message": "probe"})), flush=True)
                continue
            replies: dict[int, dict] = {}
            start = threading.Barrier(6)

            def worker(index: int) -> None:
                start.wait()
                args = granted if index == 0 else {"message": f"other-{number}-{index}"}
                replies[index] = held.call("echo.ping", args)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            summary = {
                "granted_allow": replies[0].get("decision") == "ALLOW",
                "ungranted_allow": sum(1 for i in range(1, 6) if replies[i].get("decision") == "ALLOW"),
            }
            print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[3] == "threads":
        via_threads(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 3:
        via_client(sys.argv[1], int(sys.argv[2]))
    else:
        raw(sys.argv[1])
