# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ADR-0004 host-side helpers, and the acceptance rows that use them."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from pep.approval import STATE_DIGEST_RE
from pep.evaluate import PepRuntime
from pep.gate import gated_invoke
from pep.implementation import callable_digest, executable_digest
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
HOST = "lab.demo.agent"
ARGS = {"message": "hello"}

posix_only = pytest.mark.skipif(os.name == "nt", reason="executable resolution here relies on POSIX exec bits")


def _write_program(directory, label):
    directory.mkdir(exist_ok=True)
    script = directory / "labtool"
    script.write_text(f"print({label!r})\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def _search_path(*dirs):
    return os.pathsep.join(str(d) for d in dirs)


def _envelope(approval_id):
    return {
        "tool_name": "echo.ping",
        "args": dict(ARGS),
        "capability_token": None,
        "caller_identity": HOST,
        "request_id": "test-implementation-helpers",
        "approval_id": approval_id,
    }


def _bound_grant(runtime, digest):
    return runtime.issue_approval(
        tool_name="echo.ping", args=dict(ARGS), ttl_seconds=60, now=NOW, principal=HOST, implementation_digest=digest
    )


@posix_only
def test_executable_digest_tracks_resolution_and_content(tmp_path):
    first = _write_program(tmp_path / "a", "program-a")
    _write_program(tmp_path / "b", "program-b")
    a_then_b = _search_path(tmp_path / "a", tmp_path / "b")
    b_then_a = _search_path(tmp_path / "b", tmp_path / "a")

    digest = executable_digest("labtool", path=a_then_b)
    assert STATE_DIGEST_RE.fullmatch(digest)
    assert executable_digest("labtool", path=a_then_b) == digest
    assert executable_digest("labtool", path=b_then_a) != digest

    first.write_text("print('program-a, edited')\n", encoding="utf-8")
    assert executable_digest("labtool", path=a_then_b) != digest


@posix_only
def test_executable_digest_follows_symlinks(tmp_path):
    """Both targets have identical bytes, so only the resolved path tells them apart."""
    a = _write_program(tmp_path / "a", "same program")
    b = _write_program(tmp_path / "b", "same program")
    assert a.read_bytes() == b.read_bytes()
    link_dir = tmp_path / "bin"
    link_dir.mkdir()
    link = link_dir / "labtool"
    link.symlink_to(a)
    before = executable_digest("labtool", path=str(link_dir))

    link.unlink()
    link.symlink_to(b)

    assert executable_digest("labtool", path=str(link_dir)) != before


def test_executable_digest_raises_when_the_name_does_not_resolve(tmp_path):
    with pytest.raises(FileNotFoundError):
        executable_digest("labtool", path=str(tmp_path))


def _handler_one():
    return "one"


def _handler_two():
    return "two"


class _Tool:
    def run(self):
        return "ran"


def test_callable_digest_distinguishes_handlers_and_is_stable():
    assert STATE_DIGEST_RE.fullmatch(callable_digest(_handler_one))
    assert callable_digest(_handler_one) == callable_digest(_handler_one)
    assert callable_digest(_handler_one) != callable_digest(_handler_two)
    assert callable_digest(_Tool().run) == callable_digest(_Tool.run)


def test_callable_digest_covers_the_code_not_just_the_name():
    def handler():
        return "one"

    first = callable_digest(handler)

    def handler():  # noqa: F811 - same module and qualified name, different body
        return "two"

    assert handler.__qualname__.endswith("handler")
    assert callable_digest(handler) != first


def test_callable_digest_refuses_callables_without_python_code():
    with pytest.raises(TypeError):
        callable_digest(len)


def test_swapped_in_process_handler_denies_without_spending():
    """ADR-0004 row: a host registry entry is replaced between mint and consume."""
    runtime = PepRuntime(policy=DEMO_POLICY)
    registry = {"echo.ping": _handler_one}
    grant = _bound_grant(runtime, callable_digest(registry["echo.ping"]))
    registry["echo.ping"] = _handler_two

    decision, result = gated_invoke(
        _envelope(grant.approval_id),
        lambda: registry["echo.ping"](),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: callable_digest(registry["echo.ping"]),
    )

    assert decision.receipt.reason_code == ReasonCode.APPROVAL_IMPLEMENTATION_MISMATCH
    assert result is None
    assert not runtime.approvals.lookup(grant.approval_id).consumed()


@posix_only
def test_path_reorder_denies_with_executable_digest_end_to_end(tmp_path, monkeypatch):
    """The ``PATH`` residual case, bound with the helper the ADR names."""
    _write_program(tmp_path / "a", "program-a")
    _write_program(tmp_path / "b", "program-b")
    monkeypatch.setenv("PATH", _search_path(tmp_path / "a", tmp_path / "b"))
    runtime = PepRuntime(policy=DEMO_POLICY)
    grant = _bound_grant(runtime, executable_digest("labtool"))
    monkeypatch.setenv("PATH", _search_path(tmp_path / "b", tmp_path / "a"))
    calls = []

    decision, result = gated_invoke(
        _envelope(grant.approval_id),
        lambda: calls.append("entered"),
        runtime=runtime,
        now=NOW,
        principal=HOST,
        implementation_observer=lambda: executable_digest("labtool"),
    )

    assert decision.receipt.reason_code == ReasonCode.APPROVAL_IMPLEMENTATION_MISMATCH
    assert result is None and calls == []
    assert not runtime.approvals.lookup(grant.approval_id).consumed()
