# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Run the reference host: ``python -m pep.host``.

Start this process as its own operating-system user. It does not switch
user itself.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pep.halt import HaltStoreError
from pep.host.haltfile import init_active, write_killed
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

    serve_parser = sub.add_parser("serve", help="Listen on a Unix socket.")
    serve_parser.add_argument("--socket", required=True, type=Path)
    serve_parser.add_argument("--halt", required=True, type=Path)
    serve_parser.add_argument("--log", required=True, type=Path)
    serve_parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Policy JSON owned by this process. Omit to use the built-in stub policy.",
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "init-halt":
            init_active(args.halt)
            return 0
        if args.command == "kill":
            write_killed(args.halt)
            return 0
        host = ReferenceHost(
            halt_path=args.halt,
            log_path=args.log,
            socket_path=args.socket,
            policy_path=args.policy,
        )
        host.serve_forever()
        return 0
    except (HaltStoreError, HostError, OSError) as exc:
        print(f"pep.host: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
