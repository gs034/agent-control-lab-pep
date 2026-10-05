# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0005: execute the sealed copy whose digest the PEP checked.

Each test is a row of the ADR-0005 acceptance table. Tests named
``*_residual`` record a case the helper does not close.
"""

from __future__ import annotations

import errno
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import pep.implementation as implementation
from pep.evaluate import PepRuntime
from pep.gate import begin_invoke, complete_invoke, gated_invoke
from pep.implementation import (
    ImplementationUnavailable,
    combined_digest,
    executable_digest,
    open_executable,
)
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="sealed memfd exec is Linux only (ADR-0005)")

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
HOST = "lab.demo.agent"
ARGS = {"message": "hello"}
MISMATCH = ReasonCode.APPROVAL_IMPLEMENTATION_MISMATCH


def _envelope(approval_id):
    return {
        "tool_name": "echo.ping",
        "args": dict(ARGS),
        "capability_token": None,
        "caller_identity": HOST,
        "request_id": "test-execute-digested",
        "approval_id": approval_id,
    }


def _runtime() -> PepRuntime:
    return PepRuntime(policy=DEMO_POLICY)


def _bound_grant(runtime, digest):
    return runtime.issue_approval(
        tool_name="echo.ping", args=dict(ARGS), ttl_seconds=60, now=NOW, principal=HOST, implementation_digest=digest
    )


def _write(path: Path, text: str, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


@pytest.fixture
def programs(tmp_path, monkeypatch):
    """Two Python programs named ``labtool``; ``order`` puts one first on PATH."""
    dirs = {label: _write(tmp_path / label / "labtool", f"print({label!r})\n").parent for label in ("program-a", "program-b")}

    def order(first: str) -> None:
        second = "program-b" if first == "program-a" else "program-a"
        monkeypatch.setenv("PATH", os.pathsep.join([str(dirs[first]), str(dirs[second]), os.environ["PATH"]]))

    order("program-a")
    return dirs, order


def _gate(runtime, grant, program, tool):
    return gated_invoke(
        _envelope(grant.approval_id),
        tool,
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: program.digest,
    )


def _run_python(program) -> str:
    return program.run(interpreter=sys.executable, capture_output=True, text=True, check=True).stdout.strip()


def test_path_swap_after_the_entry_check_runs_the_digested_program(programs):
    _, order = programs
    runtime = _runtime()
    grant = _bound_grant(runtime, executable_digest("labtool"))

    with open_executable("labtool") as program:

        def tool() -> str:
            order("program-b")
            return _run_python(program)

        decision, result = _gate(runtime, grant, program, tool)

    assert decision.verdict == "ALLOW"
    assert result == "program-a"


def test_symlink_retarget_after_open_runs_the_digested_program(tmp_path, monkeypatch):
    a = _write(tmp_path / "a" / "labtool", "print('program-a')\n")
    b = _write(tmp_path / "b" / "labtool", "print('program-b')\n")
    link = tmp_path / "bin" / "labtool"
    link.parent.mkdir()
    link.symlink_to(a)
    monkeypatch.setenv("PATH", f"{link.parent}{os.pathsep}{os.environ['PATH']}")
    runtime = _runtime()
    grant = _bound_grant(runtime, executable_digest("labtool"))

    with open_executable("labtool") as program:
        link.unlink()
        link.symlink_to(b)
        decision, result = _gate(runtime, grant, program, lambda: _run_python(program))

    assert decision.verdict == "ALLOW"
    assert result == "program-a"


def test_in_place_write_after_open_runs_the_digested_program(programs):
    dirs, _ = programs
    runtime = _runtime()
    grant = _bound_grant(runtime, executable_digest("labtool"))

    with open_executable("labtool") as program:
        with open(dirs["program-a"] / "labtool", "r+", encoding="utf-8") as original:
            original.write("print('program-b')\n")
        decision, result = _gate(runtime, grant, program, lambda: _run_python(program))

    assert decision.verdict == "ALLOW"
    assert result == "program-a"


def test_file_replaced_between_which_and_open_denies_at_consume(programs):
    runtime = _runtime()
    grant = _bound_grant(runtime, executable_digest("labtool"))
    calls: list[str] = []

    def replace(real: Path) -> None:
        real.write_text("print('program-b')\n", encoding="utf-8")

    with open_executable("labtool", _before_open=replace) as program:
        decision, result = _gate(runtime, grant, program, lambda: calls.append("entered"))

    assert decision.receipt.reason_code == MISMATCH
    assert result is None and calls == []
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_file_rewritten_after_the_copy_is_not_what_gets_digested(programs):
    runtime = _runtime()
    minted = executable_digest("labtool")
    grant = _bound_grant(runtime, minted)

    def rewrite(real: Path) -> None:
        real.write_text("print('program-b')\n", encoding="utf-8")

    with open_executable("labtool", _after_copy=rewrite) as program:
        assert program.digest == minted
        decision, result = _gate(runtime, grant, program, lambda: _run_python(program))

    assert decision.verdict == "ALLOW"
    assert result == "program-a"


def test_digest_matches_executable_digest_for_an_unchanged_program(programs):
    with open_executable("labtool") as program:
        assert program.digest == executable_digest("labtool")
        assert program.real_path.name == "labtool"


def test_the_sealed_copy_refuses_write_grow_and_shrink(programs):
    with open_executable("labtool") as program:
        fd = program.fileno()
        for change in (lambda: os.pwrite(fd, b"x", 0), lambda: os.ftruncate(fd, 0), lambda: os.ftruncate(fd, 1 << 20)):
            with pytest.raises(PermissionError):
                change()


@pytest.fixture
def interpreters(tmp_path, monkeypatch):
    """Two interpreters named ``labpy`` and a script whose shebang finds one on PATH."""
    dirs = {}
    for label in ("interp-a", "interp-b"):
        dirs[label] = _write(tmp_path / label / "labpy", f"#!/bin/sh\necho {label}\n").parent
    script = _write(tmp_path / "scripts" / "labscript", "#!/usr/bin/env labpy\nprint('script')\n")

    def order(first: str) -> None:
        second = "interp-b" if first == "interp-a" else "interp-a"
        path = [str(dirs[first]), str(dirs[second]), str(script.parent), os.environ["PATH"]]
        monkeypatch.setenv("PATH", os.pathsep.join(path))

    order("interp-a")
    return order


def test_env_shebang_without_a_pinned_interpreter_is_residual(interpreters):
    """ADR-0005 residual: the script is sealed, but env still finds its interpreter on PATH."""
    with open_executable("labscript") as script:
        interpreters("interp-b")
        result = script.run(capture_output=True, text=True, check=True)

    assert result.stdout.strip() == "interp-b"


def test_pinned_interpreter_runs_under_a_combined_digest(interpreters):
    runtime = _runtime()
    grant = _bound_grant(runtime, combined_digest(executable_digest("labscript"), executable_digest("labpy")))

    with open_executable("labscript") as script, open_executable("labpy") as interpreter:
        interpreters("interp-b")
        interpreter.real_path.write_text("#!/bin/sh\necho interp-tampered\n", encoding="utf-8")
        decision, result = gated_invoke(
            _envelope(grant.approval_id),
            lambda: script.run(interpreter=interpreter, capture_output=True, text=True, check=True).stdout.strip(),
            runtime=runtime,
            now=NOW,
            principal=HOST,
            implementation_observer=lambda: combined_digest(script, interpreter),
        )

    assert decision.verdict == "ALLOW"
    assert result == "interp-a"


def test_interpreter_changed_after_mint_denies_under_a_combined_digest(interpreters):
    runtime = _runtime()
    grant = _bound_grant(runtime, combined_digest(executable_digest("labscript"), executable_digest("labpy")))
    interpreters("interp-b")
    calls: list[str] = []

    with open_executable("labscript") as script, open_executable("labpy") as interpreter:
        decision, result = gated_invoke(
            _envelope(grant.approval_id),
            lambda: calls.append("entered"),
            runtime=runtime,
            now=NOW,
            principal=HOST,
            implementation_observer=lambda: combined_digest(script, interpreter),
        )

    assert decision.receipt.reason_code == MISMATCH
    assert result is None and calls == []
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


def test_missing_memfd_create_is_unavailable(programs, monkeypatch):
    monkeypatch.delattr(os, "memfd_create")
    with pytest.raises(ImplementationUnavailable):
        open_executable("labtool")


def test_missing_proc_self_fd_is_unavailable(programs, monkeypatch, tmp_path):
    monkeypatch.setattr(implementation, "_PROC_FD", str(tmp_path / "no-proc"))
    with pytest.raises(ImplementationUnavailable):
        open_executable("labtool")


@pytest.mark.parametrize("code", [errno.EPERM, errno.EACCES])
def test_kernel_refusing_an_executable_memfd_is_unavailable(programs, monkeypatch, code):
    def refuse(name, flags=0):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(os, "memfd_create", refuse)
    with pytest.raises(ImplementationUnavailable):
        open_executable("labtool")


def test_refused_fchmod_is_unavailable_and_closes_the_memfd(programs, monkeypatch):
    before = len(os.listdir("/proc/self/fd"))

    def refuse(fd, mode):
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", refuse)
    with pytest.raises(ImplementationUnavailable):
        open_executable("labtool")
    assert len(os.listdir("/proc/self/fd")) == before


def test_kernel_without_mfd_exec_falls_back_and_still_works(programs, monkeypatch):
    real = os.memfd_create
    calls: list[int] = []

    def old_kernel(name, flags=0):
        calls.append(flags)
        if flags & 0x10:
            raise OSError(errno.EINVAL, "Invalid argument")
        return real(name, flags)

    monkeypatch.setattr(os, "memfd_create", old_kernel)
    with open_executable("labtool") as program:
        assert _run_python(program) == "program-a"
    assert len(calls) == 2 and calls[0] & 0x10 and not calls[1] & 0x10


@pytest.mark.parametrize("refused", [{"executable": "/bin/true"}, {"shell": True}, {"shell": False}])
def test_run_refuses_shell_and_executable(programs, refused):
    with open_executable("labtool") as program:
        with pytest.raises(TypeError):
            program.run(**refused)


def test_caller_pass_fds_are_kept_alongside_the_handle(tmp_path, monkeypatch):
    checker = _write(
        tmp_path / "bin" / "fdcheck",
        "import os, sys\nprint(all(os.path.exists(f'/proc/self/fd/{n}') for n in sys.argv[1:]))\n",
    )
    monkeypatch.setenv("PATH", f"{checker.parent}{os.pathsep}{os.environ['PATH']}")
    read_end, write_end = os.pipe()
    try:
        with open_executable("fdcheck") as program:
            result = program.run(
                [str(read_end), str(program.fileno())],
                interpreter=sys.executable,
                pass_fds=(read_end,),
                capture_output=True,
                text=True,
                check=True,
            )
    finally:
        os.close(read_end)
        os.close(write_end)

    assert result.stdout.strip() == "True"


def test_repeated_handles_do_not_leak_fds(programs):
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(100):
        with open_executable("labtool"):
            pass
    assert len(os.listdir("/proc/self/fd")) == before


def test_closed_handle_cannot_run(programs):
    program = open_executable("labtool")
    program.close()
    with pytest.raises(ValueError):
        program.run()


def test_kill_between_admission_and_entry_is_the_fence(programs):
    runtime = _runtime()
    grant = _bound_grant(runtime, executable_digest("labtool"))
    calls: list[str] = []

    with open_executable("labtool") as program:
        pending = begin_invoke(
            _envelope(grant.approval_id),
            runtime=runtime,
            now=NOW,
            principal=HOST,
            implementation_observer=lambda: program.digest,
        )
        assert pending.decision.verdict == "ALLOW"
        runtime.kill()
        decision, result = complete_invoke(pending, lambda: calls.append(_run_python(program)))

    assert decision.receipt.reason_code == ReasonCode.LATE_EFFECT_FENCE
    assert result is None and calls == []


@pytest.mark.parametrize("bad", [(), ("md5:abc",), ("sha256:short",), (7,)])
def test_combined_digest_rejects_bad_parts(bad):
    with pytest.raises(ValueError):
        combined_digest(*bad)
