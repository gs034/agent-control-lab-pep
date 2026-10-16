# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Run the reference host: ``python -m pep.host``.

Start this process as its own operating-system user. It does not switch
user itself. It refuses to start when that user is root.

``serve`` without ``--admin`` has no way to mint a grant, so every tool
call is denied. Grants are minted with ``grant`` on the admin socket.
That socket is not the agent socket.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from pathlib import Path

from pep.halt import HaltStoreError
from pep.host.client import admin_call
from pep.host.haltfile import init_active, write_killed
from pep.host.log import DecisionLogError
from pep.host.server import HostError, ReferenceHost, running_as_root


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
        help="Policy JSON owned by this user, mode owner-only, in a private directory. Omit for the built-in stub.",
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
        help="Repeat to name an agent user id. serve requires this or --allow-gid. Root and this user are refused.",
    )
    serve_parser.add_argument(
        "--allow-gid",
        type=int,
        action="append",
        default=None,
        help="Repeat to name an agent group id. With --allow-uid, the peer must match both.",
    )

    sessions_parser = sub.add_parser("sessions", help="List live connections on the admin socket.")
    sessions_parser.add_argument("--admin", required=True, type=Path)

    grant_parser = sub.add_parser("grant", help="Mint a grant for one live connection. Run this as the host user.")
    grant_parser.add_argument("--admin", required=True, type=Path)
    grant_parser.add_argument("--connection", required=True, type=int)
    grant_parser.add_argument("--tool", required=True)
    grant_parser.add_argument("--args", required=True, help="JSON object of tool arguments.")
    grant_parser.add_argument("--ttl", required=True, type=int)

    revoke_parser = sub.add_parser("revoke", help="Revoke one outstanding grant before it is spent (ADR-0011).")
    revoke_parser.add_argument("--admin", required=True, type=Path)
    revoke_parser.add_argument("--approval", required=True, help="The approval_id the grant command printed.")

    revoke_all_parser = sub.add_parser(
        "revoke-all",
        help="Revoke every outstanding grant, or only the grants minted on one connection (ADR-0011).",
    )
    revoke_all_parser.add_argument("--admin", required=True, type=Path)
    revoke_all_parser.add_argument(
        "--connection",
        type=int,
        default=None,
        help="Revoke only the grants minted on this connection.",
    )

    args = parser.parse_args(argv)
    try:
        if running_as_root():
            raise HostError("refusing to run as root")
        if args.command == "init-halt":
            init_active(args.halt)
            return 0
        if args.command == "kill":
            write_killed(args.halt)
            return 0
        if args.command == "sessions":
            return _print_admin(args.admin, {"op": "sessions"})
        if args.command == "revoke":
            return _print_admin(args.admin, {"op": "revoke", "approval_id": args.approval})
        if args.command == "revoke-all":
            body: dict[str, object] = {"op": "revoke_all"}
            if args.connection is not None:
                body["connection_id"] = args.connection
            return _print_admin(args.admin, body)
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
        try:
            _serve_until_signal(host)
        finally:
            host.close()
        return 0
    except (HaltStoreError, HostError, DecisionLogError, OSError) as exc:
        print(f"pep.host: {exc}", file=sys.stderr)
        return 1


def _serve_until_signal(host: ReferenceHost) -> None:
    """Run until the accept loop stops, including on SIGTERM or SIGHUP.

    The signal handler only sets the stop event. The accept loop then
    returns and flushes any denial count still held for the open window.
    SIGKILL cannot be caught, so it can still drop that held count.
    """

    def _stop(_signum: int, _frame: object) -> None:
        host.request_stop()

    previous = {
        signal.SIGTERM: signal.signal(signal.SIGTERM, _stop),
        signal.SIGHUP: signal.signal(signal.SIGHUP, _stop),
    }
    try:
        host.serve_forever()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


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
