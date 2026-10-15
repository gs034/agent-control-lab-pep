# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Durable kill/suspend store survives process restart (new PepRuntime)."""

from __future__ import annotations

import os
from pathlib import Path

from pep.evaluate import PepRuntime, evaluate
from pep.halt import HaltMode, HaltState, HaltStore, HaltStoreError
from pep.policy import DEMO_POLICY
from pep.reasons import ReasonCode

# ADR-0003: the principal the test host attests; a listed holder of lab.cap.echo.demo.
HOST = "lab.demo.agent"


def _allowable():
    return {
        "tool_name": "echo.ping",
        "args": {"message": "hello"},
        "capability_token": "lab.cap.echo.demo",
        "caller_identity": "lab.demo.agent",
        "request_id": "test-halt-store",
    }


def test_kill_survives_new_runtime_on_same_file(tmp_path: Path):
    store = HaltStore(tmp_path / "halt.json")
    first = PepRuntime(policy=DEMO_POLICY, halt_store=store)
    first.kill()
    assert first.kill_active is True

    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(tmp_path / "halt.json"))
    decision = evaluate(_allowable(), runtime=restarted, principal=HOST)
    assert restarted.kill_active is True
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE
    assert decision.to_dict()["negative_controls_observed"]["tool_invoke_executed"] is False


def test_resume_cannot_clear_persisted_kill(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.kill()
    first.resume()
    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    restarted.resume()
    decision = evaluate(_allowable(), runtime=restarted, principal=HOST)
    assert restarted.kill_active is True
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_suspend_survives_restart_and_resume_restores(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.suspend()
    mid = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    denied = evaluate(_allowable(), runtime=mid, principal=HOST)
    assert denied.verdict == "DENY"
    assert denied.receipt.reason_code == ReasonCode.SUSPEND_ACTIVE
    mid.resume()
    after = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    allowed = evaluate(_allowable(), runtime=after, principal=HOST)
    assert after.mode.value == "active"
    assert allowed.verdict == "ALLOW"
    assert allowed.receipt.reason_code == ReasonCode.ALLOWED


def test_unavailable_survives_restart(tmp_path: Path):
    path = tmp_path / "halt.json"
    first = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    first.mark_unavailable()
    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    decision = evaluate(_allowable(), runtime=restarted, principal=HOST)
    assert restarted.available is False
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_corrupt_halt_file_fails_closed(tmp_path: Path):
    path = tmp_path / "halt.json"
    path.write_text("{not-json", encoding="utf-8")
    runtime = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(path))
    decision = evaluate(_allowable(), runtime=runtime, principal=HOST)
    assert runtime.kill_active or runtime.available is False
    assert decision.verdict == "DENY"
    assert decision.receipt.reason_code == ReasonCode.KILL_ACTIVE


def test_missing_halt_file_is_active(tmp_path: Path):
    store = HaltStore(tmp_path / "missing.json")
    assert store.read().mode is HaltMode.ACTIVE
    runtime = PepRuntime(policy=DEMO_POLICY, halt_store=store)
    decision = evaluate(_allowable(), runtime=runtime, principal=HOST)
    assert decision.verdict == "ALLOW"


def test_store_write_cannot_clear_kill(tmp_path: Path):
    store = HaltStore(tmp_path / "halt.json")
    store.write(HaltState(mode=HaltMode.KILLED))
    written = store.write(HaltState(mode=HaltMode.ACTIVE))
    assert written.mode is HaltMode.KILLED


def test_halt_write_fsyncs_before_replace(tmp_path: Path, monkeypatch):
    order: list[str] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def fsync(fd: int) -> None:
        order.append("fsync")
        real_fsync(fd)

    def replace(src, dst) -> None:
        order.append("replace")
        real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    HaltStore(tmp_path / "halt.json").write(HaltState(mode=HaltMode.ACTIVE))
    assert order == ["fsync", "replace", "fsync"]


def test_halt_write_uses_a_unique_temp_name(tmp_path: Path, monkeypatch):
    import tempfile

    created: list[str] = []
    real = tempfile.mkstemp

    def spy(*args, **kwargs):
        fd, name = real(*args, **kwargs)
        created.append(name)
        return fd, name

    monkeypatch.setattr(tempfile, "mkstemp", spy)
    store = HaltStore(tmp_path / "halt.json")
    store.write(HaltState(mode=HaltMode.ACTIVE))
    store.write(HaltState(mode=HaltMode.SUSPENDED))
    assert len(created) == 2
    assert len(set(created)) == 2
    assert all(not name.endswith("halt.json.tmp") for name in created)


def _kill_lands_mid_write(monkeypatch, halt: Path) -> dict:
    """Run ``pep.host kill`` in another thread between a gate write's read and its rename.

    The next ``HaltStore.write`` after this is armed reads the file, then the
    patched merge starts the kill and gives it a second to land before the
    gate writes. Without a cross-writer lock the kill lands in that second
    and the gate's rename replaces it. With the lock the kill waits and lands
    after the gate's rename.
    """
    import threading

    import pep.halt as halt_module
    from pep.host.haltfile import write_killed

    real_merge = halt_module._merge_sticky_kill
    box: dict = {"armed": True}
    landed = threading.Event()

    def kill() -> None:
        try:
            box["kill"] = write_killed(halt)
        except (HaltStoreError, OSError) as exc:  # recorded for the assertion
            box["kill_error"] = exc
        finally:
            landed.set()

    def merge_after_kill(current, requested):  # type: ignore[no-untyped-def]
        if box.pop("armed", False):
            box["thread"] = threading.Thread(target=kill, daemon=True)
            box["thread"].start()
            box["landed_before_rename"] = landed.wait(timeout=1.0)
        return real_merge(current, requested)

    monkeypatch.setattr(halt_module, "_merge_sticky_kill", merge_after_kill)
    return box


def _private_halt(tmp_path: Path) -> Path:
    directory = tmp_path / "halt"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    return directory / "halt.json"


def test_empty_or_whitespace_halt_file_is_corrupt_not_active(tmp_path: Path):
    """Mutation audit 2026-10-14-host, M12: bytes that do not parse as an active
    record are halted. Emptiness is corruption, never an active state."""
    from pep.host.haltfile import CORRUPT, read_fail_closed

    halt = _private_halt(tmp_path)
    for raw in (b"", b"   \n\t"):
        halt.write_bytes(raw)
        os.chmod(halt, 0o600)
        state, observed = read_fail_closed(halt)
        assert observed == CORRUPT, raw
        assert state.mode is HaltMode.KILLED, raw
        assert state.available is False, raw


def test_gate_resume_write_does_not_overwrite_a_concurrent_kill(tmp_path: Path, monkeypatch):
    from pep.host.haltfile import KILLED, init_active, read_fail_closed

    halt = _private_halt(tmp_path)
    init_active(halt)
    gate = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(halt), persist_on_load=False)
    gate.suspend()
    box = _kill_lands_mid_write(monkeypatch, halt)
    gate.resume()
    box["thread"].join(timeout=10)
    assert "kill_error" not in box
    assert box["landed_before_rename"] is False
    state, observed = read_fail_closed(halt)
    assert observed == KILLED
    assert state.mode is HaltMode.KILLED
    restarted = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(halt), persist_on_load=False)
    assert restarted.kill_active is True


def test_gate_suspend_write_does_not_overwrite_a_concurrent_kill(tmp_path: Path, monkeypatch):
    from pep.host.haltfile import KILLED, init_active, read_fail_closed

    halt = _private_halt(tmp_path)
    init_active(halt)
    gate = PepRuntime(policy=DEMO_POLICY, halt_store=HaltStore(halt), persist_on_load=False)
    box = _kill_lands_mid_write(monkeypatch, halt)
    gate.suspend()
    box["thread"].join(timeout=10)
    assert "kill_error" not in box
    _state, observed = read_fail_closed(halt)
    assert observed == KILLED


def test_halt_lock_file_is_private_and_a_symlink_is_refused(tmp_path: Path):
    import pytest

    halt = _private_halt(tmp_path)
    store = HaltStore(halt)
    store.write(HaltState(mode=HaltMode.ACTIVE))
    assert store.lock_path.is_file()
    assert (store.lock_path.stat().st_mode & 0o777) == 0o600
    store.lock_path.unlink()
    store.lock_path.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(HaltStoreError):
        store.write(HaltState(mode=HaltMode.KILLED))
    assert not (tmp_path / "elsewhere").exists()


def test_a_held_halt_lock_fails_the_write_after_the_bounded_wait(tmp_path: Path, monkeypatch):
    import fcntl

    import pytest

    import pep.halt as halt_module

    halt = _private_halt(tmp_path)
    store = HaltStore(halt)
    store.write(HaltState(mode=HaltMode.ACTIVE))
    monkeypatch.setattr(halt_module, "LOCK_WAIT_SECONDS", 0.2)
    fd = os.open(store.lock_path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(HaltStoreError, match="the write did not happen"):
            HaltStore(halt).write(HaltState(mode=HaltMode.SUSPENDED))
    finally:
        os.close(fd)
    assert HaltStore(halt).read().mode is HaltMode.ACTIVE


def test_kill_fails_loudly_when_the_lock_wait_expires(tmp_path: Path, monkeypatch, capsys):
    import fcntl

    import pytest

    import pep.halt as halt_module
    from pep.host.__main__ import main
    from pep.host.haltfile import ACTIVE, init_active, read_fail_closed, write_killed

    halt = _private_halt(tmp_path)
    init_active(halt)
    monkeypatch.setattr(halt_module, "LOCK_WAIT_SECONDS", 0.2)
    fd = os.open(HaltStore(halt).lock_path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(HaltStoreError, match="kill did not land"):
            write_killed(halt)
        code = main(["kill", "--halt", str(halt)])
        err = capsys.readouterr().err
    finally:
        os.close(fd)
    assert code == 1
    assert "kill did not land" in err
    assert "still held" in err
    _state, observed = read_fail_closed(halt)
    assert observed == ACTIVE
