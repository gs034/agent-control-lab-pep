#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Live check of the reference host deployment against its written claims.

Run as root on Linux. The check creates two operating-system users: the host
user, which runs the reference host, and an agent user that shares only the
agent group. It starts the host as the host user and tries each claim from
the agent side: file modes, grants, sessions, halt behaviour and limits. Each
claim prints PASS or FAIL. The exit status is 1 if any claim fails.

Nothing is left running. Every host started is stopped in a finally block.
The state and run directories are test paths, not the production ones.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HOST_USER = "acl-pep"
AGENT_USER = "acl-agent"
AGENT_GROUP = "acl-agent"
HERE = Path(__file__).resolve().parent
LIVE_HOSTS: list[Host] = []
# Set in main to the agent user's ids. Hosts that should accept the agent pass both.
AGENT_UID = ""
AGENT_GID = ""


@dataclass(frozen=True)
class Layout:
    code: Path
    state: Path
    run: Path

    @property
    def sock(self) -> Path:
        return self.run / "pep.sock"

    @property
    def admin(self) -> Path:
        return self.state / "admin.sock"

    @property
    def halt(self) -> Path:
        return self.state / "halt.json"

    @property
    def log(self) -> Path:
        return self.state / "decisions.log"


class Report:
    def __init__(self) -> None:
        self.total = 0
        self.failed = 0

    def check(self, claim: str, ok: bool, detail: str = "") -> None:
        self.total += 1
        if not ok:
            self.failed += 1
        print(f"{'PASS' if ok else 'FAIL'} {claim}: {detail}", flush=True)

    def note(self, text: str) -> None:
        print(f"NOTE {text}", flush=True)


def run(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True)


def as_user(user: str, lay: Layout, argv: list[str], *, timeout: float = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["runuser", "-u", user, "--", "env", f"PYTHONPATH={lay.code}", *argv],
        cwd=lay.code,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def host_python(lay: Layout, python: str, *args: str) -> subprocess.CompletedProcess[str]:
    return as_user(HOST_USER, lay, [python, "-m", "pep.host", *args])


def ensure_users() -> None:
    try:
        grp.getgrnam(AGENT_GROUP)
    except KeyError:
        run(["groupadd", "-r", AGENT_GROUP])
    try:
        pwd.getpwnam(HOST_USER)
    except KeyError:
        run(["useradd", "-r", "-M", "-s", "/usr/sbin/nologin", HOST_USER])
    try:
        pwd.getpwnam(AGENT_USER)
    except KeyError:
        run(["useradd", "-r", "-M", "-s", "/usr/sbin/nologin", "-g", AGENT_GROUP, AGENT_USER])


def agent_allow_args() -> tuple[str, str, str, str]:
    """``--allow-uid`` and ``--allow-gid`` for the agent user this check created."""
    user = pwd.getpwnam(AGENT_USER)
    uid = AGENT_UID or str(user.pw_uid)
    gid = AGENT_GID or str(user.pw_gid)
    return ("--allow-uid", uid, "--allow-gid", gid)


class Host:
    """The reference host, started as the host user and stopped on exit."""

    def __init__(self, lay: Layout, python: str, extra: tuple[str, ...] | None = None) -> None:
        if extra is None:
            extra = agent_allow_args()
        self.lay = lay
        pw = pwd.getpwnam(HOST_USER)
        self.proc = subprocess.Popen(
            [
                "setpriv",
                f"--reuid={pw.pw_uid}",
                f"--regid={pw.pw_gid}",
                "--clear-groups",
                "env",
                f"PYTHONPATH={lay.code}",
                python,
                "-m",
                "pep.host",
                "serve",
                "--socket",
                str(lay.sock),
                "--halt",
                str(lay.halt),
                "--log",
                str(lay.log),
                "--admin",
                str(lay.admin),
                *extra,
            ],
            cwd=lay.code,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        LIVE_HOSTS.append(self)

    def wait_ready(self, timeout: float = 15.0) -> bool:
        """True once a connection to the socket is accepted, not merely once a file exists."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(1.0)
                probe.connect(str(self.lay.sock))
                return True
            except OSError:
                time.sleep(0.05)
            finally:
                probe.close()
        return False

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> tuple[int | None, str]:
        if self.proc.poll() is None:
            _signal_group(self.proc, signal.SIGTERM)
        try:
            _, err = self.proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            _signal_group(self.proc, signal.SIGKILL)
            _, err = self.proc.communicate(timeout=15)
        if self in LIVE_HOSTS:
            LIVE_HOSTS.remove(self)
        return self.proc.returncode, err or ""


def _signal_group(proc: subprocess.Popen[str], sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


class Held:
    """One agent connection that stays open between requests."""

    def __init__(self, lay: Layout, python: str, via_client: bool = False) -> None:
        host_uid = str(pwd.getpwnam(HOST_USER).pw_uid) if via_client else None
        self.proc = subprocess.Popen(
            [
                "runuser",
                "-u",
                AGENT_USER,
                "--",
                "env",
                f"PYTHONPATH={lay.code}",
                python,
                "-u",
                str(lay.code / "agent_shim.py"),
                str(lay.sock),
                *([host_uid] if host_uid else []),
            ],
            cwd=lay.code,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def send(self, line: str, timeout: float = 10.0) -> str:
        if self.proc.poll() is not None:
            return "SHIM_EXITED"
        try:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            return "SHIM_EXITED"
        ready, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            return "TIMEOUT"
        reply = self.proc.stdout.readline()
        return reply.strip() if reply else "EOF"

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def decode(reply: str) -> dict[str, Any]:
    try:
        parsed = json.loads(reply)
    except json.JSONDecodeError:
        return {"decision": None, "raw": reply}
    return parsed if isinstance(parsed, dict) else {"decision": None, "raw": reply}


def is_allow(reply: str) -> bool:
    return decode(reply).get("decision") == "ALLOW"


def is_deny(reply: str) -> bool:
    return decode(reply).get("decision") == "DENY"


def newest_session_id(lay: Layout, python: str) -> int | None:
    result = host_python(lay, python, "sessions", "--admin", str(lay.admin))
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    sessions = data.get("sessions", []) if isinstance(data, dict) else []
    ids = [s["connection_id"] for s in sessions if isinstance(s, dict) and "connection_id" in s]
    return max(ids) if ids else None


def grant(lay: Layout, python: str, connection_id: int, args: dict[str, Any], ttl: int) -> subprocess.CompletedProcess[str]:
    return host_python(
        lay,
        python,
        "grant",
        "--admin",
        str(lay.admin),
        "--connection",
        str(connection_id),
        "--tool",
        "echo.ping",
        "--args",
        json.dumps(args),
        "--ttl",
        str(ttl),
    )


def read_log(lay: Layout) -> list[dict[str, Any]]:
    if not lay.log.exists():
        return []
    records = []
    for line in lay.log.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _grant_newest(lay: Layout, python: str, args: dict[str, Any], ttl: int) -> bool:
    """Grant the newest session. False when there is no session or the grant was refused."""
    conn = newest_session_id(lay, python)
    if conn is None:
        return False
    return grant(lay, python, conn, args, ttl=ttl).returncode == 0


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def reset_state(lay: Layout, python: str) -> None:
    """Create the directories with the README's own commands (steps 2 and 3)."""
    for path in (lay.state, lay.run):
        shutil.rmtree(path, ignore_errors=True)
    run(["install", "-d", "-o", HOST_USER, "-g", HOST_USER, "-m", "0700", str(lay.state)])
    run(["install", "-d", "-o", HOST_USER, "-g", AGENT_GROUP, "-m", "2750", str(lay.run)])
    result = host_python(lay, python, "init-halt", "--halt", str(lay.halt))
    if result.returncode != 0:
        raise SystemExit(f"init-halt failed: {result.stderr}")


def provision(lay: Layout, source: Path) -> None:
    ensure_users()
    shutil.rmtree(lay.code, ignore_errors=True)
    shutil.copytree(source / "pep", lay.code / "pep", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(HERE / "agent_shim.py", lay.code / "agent_shim.py")
    for root, dirs, files in os.walk(lay.code):
        for name in dirs:
            os.chmod(Path(root) / name, 0o755)
        for name in files:
            os.chmod(Path(root) / name, 0o644)
    os.chmod(lay.code, 0o755)


def scenario_main(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    where = as_user(HOST_USER, lay, [python, "-c", "import pep.host.server as s; print(s.__file__)"])
    expected = str(lay.code / "pep" / "host" / "server.py")
    report.check(
        "the host imports the code under test",
        where.stdout.strip() == expected,
        where.stdout.strip() or where.stderr.strip()[-120:],
    )
    host = Host(lay, python)
    if not host.wait_ready():
        _, err = host.stop()
        report.check("host starts with its socket", False, err.strip()[-300:])
        return
    report.check("host starts with its socket", True)

    host_uid = pwd.getpwnam(HOST_USER).pw_uid
    agent_gid = pwd.getpwnam(AGENT_USER).pw_gid
    run_st = os.lstat(lay.run)
    report.check(
        "socket directory is owned by the host user, group is the agent group, mode 2750",
        run_st.st_uid == host_uid and run_st.st_gid == agent_gid and mode_of(lay.run) == 0o2750,
        f"uid={run_st.st_uid} gid={run_st.st_gid} mode={oct(mode_of(lay.run))}",
    )
    sock_st = os.lstat(lay.sock)
    report.check(
        "agent socket is a socket owned by the host user, group is the agent group, mode 0660",
        stat.S_ISSOCK(sock_st.st_mode) and sock_st.st_uid == host_uid and sock_st.st_gid == agent_gid and mode_of(lay.sock) == 0o660,
        f"mode={oct(mode_of(lay.sock))}",
    )
    report.check(
        "state directory is owned by the host user, mode 0700",
        os.lstat(lay.state).st_uid == host_uid and mode_of(lay.state) == 0o700,
        f"mode={oct(mode_of(lay.state))}",
    )
    report.check(
        "halt file is owned by the host user, mode 0600",
        os.lstat(lay.halt).st_uid == host_uid and mode_of(lay.halt) == 0o600,
        f"mode={oct(mode_of(lay.halt))}",
    )
    report.check(
        "admin socket is in the private state directory, mode 0600",
        stat.S_ISSOCK(os.lstat(lay.admin).st_mode) and mode_of(lay.admin) == 0o600,
        f"mode={oct(mode_of(lay.admin))}",
    )

    halt_before = lay.halt.read_bytes()
    write = as_user(AGENT_USER, lay, ["sh", "-c", f"printf x >> {lay.halt}"])
    replace = as_user(AGENT_USER, lay, ["sh", "-c", f"rm -f {lay.halt} && printf active > {lay.halt}"])
    report.check(
        "agent cannot write or replace the halt file",
        write.returncode != 0 and replace.returncode != 0 and lay.halt.read_bytes() == halt_before,
        f"append rc={write.returncode} replace rc={replace.returncode}",
    )
    listing = as_user(AGENT_USER, lay, ["ls", str(lay.state)])
    report.check("agent cannot list the state directory", listing.returncode != 0, f"ls rc={listing.returncode}")
    log_before = lay.log.read_bytes() if lay.log.exists() else b""
    log_append = as_user(AGENT_USER, lay, ["sh", "-c", f"printf x >> {lay.log}"])
    log_remove = as_user(AGENT_USER, lay, ["rm", "-f", str(lay.log)])
    log_after = lay.log.read_bytes() if lay.log.exists() else b""
    report.check(
        "agent cannot rewrite or delete the decision log",
        log_append.returncode != 0 and log_remove.returncode != 0 and log_after == log_before,
        f"append rc={log_append.returncode} remove rc={log_remove.returncode}",
    )
    create = as_user(AGENT_USER, lay, ["touch", str(lay.run / "replacement.sock")])
    unlink = as_user(AGENT_USER, lay, ["rm", "-f", str(lay.sock)])
    report.check(
        "agent cannot create or remove entries in the socket directory",
        create.returncode != 0 and unlink.returncode != 0 and stat.S_ISSOCK(os.lstat(lay.sock).st_mode),
        f"create rc={create.returncode} unlink rc={unlink.returncode}",
    )
    admin_probe = as_user(
        AGENT_USER,
        lay,
        [
            python,
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(sys.argv[1])",
            str(lay.admin),
        ],
    )
    admin_control = host_python(lay, python, "sessions", "--admin", str(lay.admin))
    report.check(
        "agent cannot connect to the admin socket",
        admin_probe.returncode != 0 and "Permission denied" in admin_probe.stderr and admin_control.returncode == 0,
        f"agent: {admin_probe.stderr.strip()[-100:]} | host control rc={admin_control.returncode}",
    )

    agent_a = Held(lay, python)
    try:
        no_grant = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("a call with no grant is denied", is_deny(no_grant), no_grant[:160])
        conn_a = newest_session_id(lay, python)
        report.check("the operator sees the agent connection as a session", conn_a is not None, f"connection {conn_a}")
        if conn_a is not None:
            minted = grant(lay, python, conn_a, {"message": "hi"}, ttl=60)
            report.check("the operator mints a grant for that connection", minted.returncode == 0, minted.stdout.strip()[:160] or minted.stderr.strip()[-160:])
            allowed = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
            report.check("the granted call on the granted connection is allowed", is_allow(allowed), allowed[:160])
            allowed_id = decode(allowed).get("request_id")
            logged = [r for r in read_log(lay) if r.get("request_id") == allowed_id]
            report.check(
                "the allowed call is in the decision log under its request id",
                any(r.get("decision") == "ALLOW" for r in logged),
                f"request {allowed_id}",
            )
            report.check(
                "the decision log is owned by the host user, mode 0600",
                os.lstat(lay.log).st_uid == host_uid and mode_of(lay.log) == 0o600,
                f"mode={oct(mode_of(lay.log))}",
            )
            other_args = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "other"}}))
            report.check("the same connection with other arguments is denied", is_deny(other_args), other_args[:160])

            agent_b = Held(lay, python)
            try:
                agent_b.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "probe"}}))
                other_conn = newest_session_id(lay, python)
                different = other_conn is not None and other_conn != conn_a
                report.check("a second connection is a different session", different, f"connections {conn_a} and {other_conn}")
                spent_elsewhere = agent_b.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
                report.check("the second connection cannot use the first connection's grant", is_deny(spent_elsewhere), spent_elsewhere[:160])
            finally:
                agent_b.close()

            for key, value in (("now", "2000-01-01T00:00:00Z"), ("principal", "lab.demo.agent"), ("session_id", "x"), ("tool", "echo.ping"), ("approval_id", "x"), ("connection_id", 1)):
                reply = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}, key: value}))
                report.check(f"an extra request key '{key}' is denied", is_deny(reply), reply[:120])

            self_grant = agent_a.send(json.dumps({"op": "grant", "connection_id": conn_a, "tool_name": "echo.ping", "args": {"message": "x"}, "ttl_seconds": 60}))
            report.check("the agent cannot mint a grant over its own socket", is_deny(self_grant), self_grant[:120])

            unknown = grant(lay, python, 99999, {"message": "hi"}, ttl=60)
            report.check(
                "a grant to a connection that does not exist is refused by the host",
                unknown.returncode != 0 and "no such connection" in unknown.stderr,
                unknown.stderr.strip()[-120:],
            )

            expiry_grant = grant(lay, python, conn_a, {"message": "ttl"}, ttl=2)
            before_expiry = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "ttl"}}))
            time.sleep(3)
            after_expiry = agent_a.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "ttl"}}))
            report.check(
                "a grant stops working when its time runs out",
                expiry_grant.returncode == 0 and is_allow(before_expiry) and is_deny(after_expiry),
                f"before={before_expiry[:60]} after={after_expiry[:60]}",
            )

    finally:
        agent_a.close()

    nested: Any = "x"
    for _ in range(40):
        nested = [nested]
    deep_conn = Held(lay, python)
    try:
        deep_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "probe"}}))
        granted = _grant_newest(lay, python, {"message": "hi"}, 120)
        control = deep_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        deep = decode(deep_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi", "deep": nested}})))
        report.check(
            "JSON nested deeper than 32 is denied on a granted connection",
            granted and is_allow(control) and deep.get("reason_code") == "envelope_invalid" and "nesting" in deep.get("reason_detail", ""),
            str(deep.get("reason_detail")),
        )
    finally:
        deep_conn.close()

    flood_conn = Held(lay, python)
    try:
        flood_before = len(read_log(lay))
        flood = [flood_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}, "now": "x"})) for _ in range(60)]
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not any(r.get("reason_code") == "rate_limited" for r in read_log(lay)[flood_before:]):
            time.sleep(0.1)
        flood_lines = read_log(lay)[flood_before:]
        report.check(
            "a flood of unadmitted denials is coalesced in the log",
            all(is_deny(reply) for reply in flood) and any(r.get("reason_code") == "rate_limited" for r in flood_lines) and len(flood_lines) < 60,
            f"replies={len(flood)} log lines={len(flood_lines)}",
        )
    finally:
        flood_conn.close()

    oversize_conn = Held(lay, python)
    try:
        oversize_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "probe"}}))
        granted = _grant_newest(lay, python, {"message": "hi"}, 120)
        control = oversize_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        oversized = decode(oversize_conn.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "a" * 70000}})))
        report.check(
            "a request over 64KiB is denied on a granted connection",
            granted and is_allow(control) and oversized.get("reason_code") == "envelope_invalid" and "exceeds" in oversized.get("reason_detail", ""),
            str(oversized.get("reason_detail")),
        )
    finally:
        oversize_conn.close()

    fills = [Held(lay, python) for _ in range(8)]
    try:
        for held in fills:
            held.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        ninth = Held(lay, python)
        try:
            refused = ninth.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
            report.check(
                "a ninth connection is refused while eight are open",
                decode(refused).get("reason_code") == "connection_limit",
                refused[:120],
            )
        finally:
            ninth.close()
    finally:
        for held in fills:
            held.close()

    idle = as_user(AGENT_USER, lay, [python, "-c", _idle_script(str(lay.sock))], timeout=40)
    idle_elapsed, idle_reply = _timed(idle.stdout)
    report.check(
        "a connection with no bytes is closed after 5 seconds",
        idle_reply is not None and "idle_timeout" in idle_reply and 4.0 <= idle_elapsed <= 8.0,
        f"closed after {idle_elapsed}s with {idle_reply!r}",
    )

    deadline = as_user(AGENT_USER, lay, [python, "-c", _trickle_script(str(lay.sock))], timeout=60)
    deadline_elapsed, deadline_reply = _timed(deadline.stdout)
    report.check(
        "a connection that keeps trickling is closed at 30 seconds",
        deadline_reply is not None and "connection_deadline" in deadline_reply and 28.0 <= deadline_elapsed <= 36.0,
        f"closed after {deadline_elapsed}s with {deadline_reply!r}",
    )

    agent_c = Held(lay, python)
    try:
        agent_c.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
    finally:
        agent_c.close()

    client_checks(lay, python, report)

    code, err = host.stop()
    report.check("SIGTERM stops the host cleanly", code == 0 and "Traceback" not in err, f"exit={code}")


def _timed(stdout: str) -> tuple[float, str | None]:
    """Parse a probe line of the form ``<seconds> <reply>``."""
    head, _, rest = stdout.strip().partition(" ")
    try:
        return float(head), rest or None
    except ValueError:
        return -1.0, None


def _idle_script(sock: str) -> str:
    return (
        "import socket,time\n"
        f"s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect({sock!r})\n"
        "s.settimeout(20)\n"
        "start=time.monotonic(); data=b''\n"
        "try:\n"
        "    data=s.recv(4096)\n"
        "except OSError:\n"
        "    pass\n"
        "print(round(time.monotonic()-start,2), data.decode('utf-8','replace').strip() or 'EOF')\n"
    )


def _trickle_script(sock: str) -> str:
    # A failed send means the host may already have written its reply and
    # closed; the reply is still readable, so recv runs after it either way.
    return (
        "import socket,time\n"
        f"s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect({sock!r})\n"
        "s.settimeout(2)\n"
        "start=time.monotonic(); end=start+40\n"
        "data=b''\n"
        "while time.monotonic()<end:\n"
        "    try:\n"
        "        s.sendall(b' ')\n"
        "    except OSError:\n"
        "        pass\n"
        "    try:\n"
        "        chunk=s.recv(4096)\n"
        "    except socket.timeout:\n"
        "        chunk=None\n"
        "    except OSError:\n"
        "        break\n"
        "    if chunk==b'':\n"
        "        break\n"
        "    if chunk:\n"
        "        data+=chunk\n"
        "        break\n"
        "    time.sleep(2)\n"
        "print(round(time.monotonic()-start,2), data.decode('utf-8','replace').strip() or 'EOF')\n"
    )


def _invoke_script(path: str, host_uid: int) -> str:
    return (
        "import json\n"
        "from pep.host.client import invoke\n"
        f"print(json.dumps(invoke({path!r}, 'echo.ping', {{'message': 'hi'}}, host_uid={host_uid})))\n"
    )


def client_checks(lay: Layout, python: str, report: Report) -> None:
    host_uid = pwd.getpwnam(HOST_USER).pw_uid
    reached = as_user(AGENT_USER, lay, [python, "-c", _invoke_script(str(lay.sock), host_uid)], timeout=20)
    reply = decode(reached.stdout.strip())
    report.check(
        "the shipped client reaches the host and is denied without a grant",
        reply.get("decision") == "DENY" and reply.get("reason_code") not in {"host_unattested", "host_unreachable"},
        str(reply.get("reason_code")),
    )
    wrong = as_user(AGENT_USER, lay, [python, "-c", _invoke_script(str(lay.sock), host_uid + 1)], timeout=20)
    report.check(
        "the shipped client refuses a socket owned by another user",
        decode(wrong.stdout.strip()).get("reason_code") == "host_unattested",
        wrong.stdout.strip()[:120] or wrong.stderr.strip()[-120:],
    )
    link = Path("/tmp/acl-pep-check-link")
    link.unlink(missing_ok=True)
    as_user(AGENT_USER, lay, ["ln", "-s", str(lay.sock), str(link)])
    via_link = as_user(AGENT_USER, lay, [python, "-c", _invoke_script(str(link), host_uid)], timeout=20)
    link.unlink(missing_ok=True)
    report.check(
        "the shipped client refuses a socket path that is a symlink",
        decode(via_link.stdout.strip()).get("reason_code") == "host_unattested",
        via_link.stdout.strip()[:120] or via_link.stderr.strip()[-120:],
    )
    held = Held(lay, python, via_client=True)
    try:
        before = held.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "client"}}))
        _grant_newest(lay, python, {"message": "client"}, 60)
        after = held.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "client"}}))
        report.check(
            "a held client connection is allowed once the operator grants it",
            is_deny(before) and is_allow(after),
            f"before={before[:60]} after={after[:60]}",
        )
    finally:
        held.close()


def scenario_peer(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    host_uid = pwd.getpwnam(HOST_USER).pw_uid
    agent_uid = int(AGENT_UID or pwd.getpwnam(AGENT_USER).pw_uid)
    foreign = "4242"
    if int(foreign) in {0, host_uid, agent_uid}:
        foreign = str(max(host_uid, agent_uid) + 1)
    _uid_flag, _uid, gid_flag, gid = agent_allow_args()
    host = Host(lay, python, extra=("--allow-uid", foreign, gid_flag, gid))
    if not host.wait_ready():
        report.check("peer scenario: host starts", False)
        host.stop()
        return
    agent = Held(lay, python)
    try:
        reply = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("a peer outside --allow-uid is refused", decode(reply).get("reason_code") == "peer_rejected", reply[:120])
    finally:
        agent.close()
    host.stop()


def scenario_flush(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    host = Host(lay, python)
    if not host.wait_ready():
        report.check("flush scenario: host starts", False)
        host.stop()
        return
    agent = Held(lay, python)
    try:
        for _ in range(60):
            agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}, "now": "x"}))
    finally:
        agent.close()
    host.stop()
    records = read_log(lay)
    logged = sum(1 for r in records if r.get("reason_code") == "envelope_invalid")
    counted = sum(r.get("suppressed_count", 0) for r in records if r.get("reason_code") == "rate_limited")
    report.check(
        "stopping the host writes every counted denial to the log",
        counted > 0 and logged + counted == 60,
        f"logged={logged} counted={counted}",
    )


def scenario_runtime_halt(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    host = Host(lay, python)
    if not host.wait_ready():
        report.check("runtime halt scenario: host starts", False)
        host.stop()
        return
    agent = Held(lay, python)
    try:
        agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        _grant_newest(lay, python, {"message": "hi"}, 120)
        baseline = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("baseline before the halt file is removed: allowed", is_allow(baseline), baseline[:80])
        removed = as_user(HOST_USER, lay, ["rm", "-f", str(lay.halt)])
        after = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check(
            "removing the halt file while running denies the next call",
            removed.returncode == 0 and is_deny(after) and host.alive(),
            after[:120],
        )
    finally:
        agent.close()
    host.stop()


def scenario_halt(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    host = Host(lay, python)
    if not host.wait_ready():
        report.check("halt scenario: host starts", False)
        host.stop()
        return
    agent = Held(lay, python)
    try:
        agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        _grant_newest(lay, python, {"message": "hi"}, 120)
        before = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("baseline: granted call is allowed before the kill", is_allow(before), before[:120])

        killed = host_python(lay, python, "kill", "--halt", str(lay.halt))
        report.check("the operator kill command succeeds", killed.returncode == 0, killed.stderr.strip()[-120:])
        after_kill = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("a kill denies a granted call that has not entered the tool", is_deny(after_kill), after_kill[:120])
        report.check("the host process stays up after a kill", host.alive(), "")

        reinit = host_python(lay, python, "init-halt", "--halt", str(lay.halt))
        still = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        report.check("init-halt does not clear a kill", is_deny(still), f"init rc={reinit.returncode} reply={still[:80]}")
    finally:
        agent.close()
    host.stop()

    host = Host(lay, python)
    if host.wait_ready():
        agent = Held(lay, python)
        try:
            agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
            granted = _grant_newest(lay, python, {"message": "hi"}, 120)
            restarted = agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
            report.check("a kill survives a restart", granted and is_deny(restarted), f"granted={granted} {restarted[:100]}")
        finally:
            agent.close()
    else:
        report.check("a kill survives a restart", False, "host did not start")
    host.stop()

    host_python(lay, python, "init-halt", "--halt", str(lay.halt))
    lay.halt.unlink()
    host = Host(lay, python)
    started = host.wait_ready()
    report.check("a missing halt file is halted, not active, on start", started and _denied_on_start(lay, python, host), "")
    host.stop()

    reset_state(lay, python)
    lay.halt.write_text("not json {{{", encoding="utf-8")
    os.chown(lay.halt, pwd.getpwnam(HOST_USER).pw_uid, pwd.getpwnam(HOST_USER).pw_gid)
    os.chmod(lay.halt, 0o600)
    host = Host(lay, python)
    started = host.wait_ready()
    report.check("a damaged halt file is halted on start", started and _denied_on_start(lay, python, host), "")
    host.stop()


def _denied_on_start(lay: Layout, python: str, host: Host) -> bool:
    agent = Held(lay, python)
    try:
        agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}}))
        granted = _grant_newest(lay, python, {"message": "hi"}, 120)
        return granted and is_deny(agent.send(json.dumps({"tool_name": "echo.ping", "args": {"message": "hi"}})))
    finally:
        agent.close()


def _start_refused(lay: Layout, python: str) -> tuple[int | None, str]:
    """Start the host and return its exit status and stderr. None when it did not exit."""
    host = Host(lay, python)
    try:
        _, err = host.proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        host.stop()
        return None, "host did not exit"
    LIVE_HOSTS.remove(host)
    return host.proc.returncode, err


def scenario_startup(lay: Layout, python: str, report: Report) -> None:
    reset_state(lay, python)
    os.chmod(lay.run, 0o2770)
    code, err = _start_refused(lay, python)
    report.check(
        "a socket directory that group members can write is refused at start",
        code == 1 and "writable by group or other" in err and not lay.sock.exists(),
        f"exit={code} {err.strip()[-100:]}",
    )
    os.chmod(lay.run, 0o2750)

    reset_state(lay, python)
    os.chmod(lay.state, 0o755)
    code, err = _start_refused(lay, python)
    report.check(
        "a state directory that others can read is refused at start",
        code == 1 and "accessible to group or other" in err,
        f"exit={code} {err.strip()[-100:]}",
    )
    os.chmod(lay.state, 0o700)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live check of the reference host deployment.")
    parser.add_argument("--source", type=Path, default=HERE.parents[1], help="Repository root that contains pep/.")
    parser.add_argument("--code-dir", type=Path, default=Path("/opt/acl-pep-check/src"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/acl-pep-check"))
    parser.add_argument("--run-dir", type=Path, default=Path("/run/acl-pep-check"))
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--allow-uid",
        type=int,
        default=None,
        help="User id of the agent. Must be the acl-agent user. The host is started with this id.",
    )
    parser.add_argument(
        "--allow-gid",
        type=int,
        default=None,
        help="Group id of the agent. Must be the acl-agent group. The host is started with this id.",
    )
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("run as root: the check creates users and switches to them")
    lay = Layout(code=args.code_dir, state=args.state_dir, run=args.run_dir)
    report = Report()
    global AGENT_UID, AGENT_GID
    try:
        provision(lay, args.source)
        agent = pwd.getpwnam(AGENT_USER)
        if args.allow_uid is not None and args.allow_uid != agent.pw_uid:
            print(
                f"pep live check: --allow-uid {args.allow_uid} is not the {AGENT_USER} user ({agent.pw_uid})",
                file=sys.stderr,
            )
            return 2
        if args.allow_gid is not None and args.allow_gid != agent.pw_gid:
            print(
                f"pep live check: --allow-gid {args.allow_gid} is not the {AGENT_USER} group ({agent.pw_gid})",
                file=sys.stderr,
            )
            return 2
        AGENT_UID = str(agent.pw_uid)
        AGENT_GID = str(agent.pw_gid)
        scenario_main(lay, args.python, report)
        scenario_halt(lay, args.python, report)
        scenario_startup(lay, args.python, report)
        scenario_peer(lay, args.python, report)
        scenario_flush(lay, args.python, report)
        scenario_runtime_halt(lay, args.python, report)
    finally:
        for host in list(LIVE_HOSTS):
            host.stop()
    print(f"\n{report.total - report.failed} of {report.total} claims pass")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
