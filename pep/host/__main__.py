# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Run the reference host: ``python -m pep.host``.

Start this process as its own operating-system user. It does not switch
user itself.

``serve`` without ``--admin`` has no way to mint a grant, so every tool
call is denied. Grants are minted with ``grant`` on the admin socket.
That socket is not the agent socket.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pep.halt import HaltStoreError
from pep.host.client import admin_call
from pep.host.haltfile import init_active, write_killed
from pep.host.log import DecisionLogError
from pep.host.server import HostError, ReferenceHost


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pep.host",
        description="Agent Control Lab reference host for the policy enforcement point.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init-halt", help="Create an active halt file. Does not clear a kill.")
    init_parser.add_argument("--halt", required=True, type=Path)

    kill_parser = sub.add_parser("kill", help="Persist a kill. Fails if the file cannot be written.")
    kill_parser.add_argument("--halt", required=True, type=Path)

    serve_parser = sub.add_parser("serve", help="Listen on a Unix socket. Without --admin, every call is denied.")
    serve_parser.add_argument("--socket", required=True, type=Path)
    serve_parser.add_argument("--halt", required=True, type=Path)
    serve_parser.add_argument("--log", required=True, type=Path)
    serve_parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Policy JSON owned by this process. Omit to use the built-in stub policy.",
    )
    serve_parser.add_argument(
        "--admin",
        type=Path,
        default=None,
        help="Operator socket, mode 0600, in the private halt directory. The agent socket cannot mint grants.",
    )
    serve_parser.add_argument(
        "--allow-uid",
        type=int,
        action="append",
        default=None,
        help="Repeat to allow only these peer user ids. Omit to allow any peer that can connect.",
    )
    serve_parser.add_argument(
        "--allow-gid",
        type=int,
        action="append",
        default=None,
        help="Repeat to allow only these peer group ids. With --allow-uid, the peer must match both.",
    )

    sessions_parser = sub.add_parser("sessions", help="List live connections on the admin socket.")
    sessions_parser.add_argument("--admin", required=True, type=Path)

    grant_parser = sub.add_parser("grant", help="Mint a grant for one live connection. Run this as the host user.")
    grant_parser.add_argument("--admin", required=True, type=Path)
    grant_parser.add_argument("--connection", required=True, type=int)
    grant_parser.add_argument("--tool", required=True)
    grant_parser.add_argument("--args", required=True, help="JSON object of tool arguments.")
    grant_parser.add_argument("--ttl", required=True, type=int)

    args = parser.parse_args(argv)
    try:
        if args.command == "init-halt":
            init_active(args.halt)
            return 0
        if args.command == "kill":
            write_killed(args.halt)
            return 0
        if args.command == "sessions":
            return _print_admin(args.admin, {"op": "sessions"})
        if args.command == "grant":
            try:
                tool_args = json.loads(args.args)
            except json.JSONDecodeError:
                print("pep.host: --args must be a JSON object", file=sys.stderr)
                return 1
            if not isinstance(tool_args, dict):
                print("pep.host: --args must be a JSON object", file=sys.stderr)
                return 1
            return _print_admin(
                args.admin,
                {
                    "op": "grant",
                    "connection_id": args.connection,
                    "tool_name": args.tool,
                    "args": tool_args,
                    "ttl_seconds": args.ttl,
                },
            )
        host = ReferenceHost(
            halt_path=args.halt,
            log_path=args.log,
            socket_path=args.socket,
            policy_path=args.policy,
            admin_path=args.admin,
            allowed_uids=args.allow_uid,
            allowed_gids=args.allow_gid,
        )
        host.serve_forever()
        return 0
    except (HaltStoreError, HostError, DecisionLogError, OSError) as exc:
        print(f"pep.host: {exc}", file=sys.stderr)
        return 1


def _print_admin(path: Path, body: dict) -> int:
    reply = admin_call(path, body, host_uid=os.getuid())
    if reply.get("decision") == "DENY" or reply.get("ok") is not True:
        detail = reply.get("error") or reply.get("reason_detail") or "admin call failed"
        print(f"pep.host: {detail}", file=sys.stderr)
        return 1
    print(json.dumps(reply, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
