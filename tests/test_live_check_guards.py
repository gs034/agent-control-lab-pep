# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Guards in the live check that run as root: delete only under its own roots."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "reference_host_check" / "live_check.py"
_spec = importlib.util.spec_from_file_location("live_check", _SCRIPT)
live_check = importlib.util.module_from_spec(_spec)
sys.modules["live_check"] = live_check
_spec.loader.exec_module(live_check)

ROOTS = list(live_check.DEFAULT_ROOTS)


@pytest.mark.parametrize("path", ["/", "/etc", "/var/lib", "/var/lib/acl-pep-check-other", "relative/path", "/opt"])
def test_paths_outside_the_check_roots_are_refused(path: str):
    assert not live_check.path_is_allowed(Path(path), ROOTS)


@pytest.mark.parametrize("path", ["/var/lib/acl-pep-check", "/run/acl-pep-check", "/opt/acl-pep-check/src"])
def test_the_check_roots_are_allowed(path: str):
    assert live_check.path_is_allowed(Path(path), ROOTS)


def test_a_symlink_into_a_check_root_is_refused(tmp_path: Path):
    scratch = tmp_path / "scratch" / "root"
    scratch.mkdir(parents=True)
    link = scratch / "link"
    link.symlink_to("/etc")
    assert not live_check.path_is_allowed(link, [scratch])
    assert live_check.path_is_allowed(scratch / "real", [scratch])


def test_a_shallow_scratch_root_is_ignored():
    assert not live_check.path_is_allowed(Path("/tmp/anything"), [Path("/tmp")])
    assert not live_check.path_is_allowed(Path("/etc"), [Path("/")])


def test_safe_rmtree_refuses_outside_the_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "keep"
    target.mkdir()
    monkeypatch.setattr(live_check, "ALLOWED_ROOTS", ROOTS)
    with pytest.raises(SystemExit):
        live_check.safe_rmtree(target)
    assert target.exists()


def test_without_yes_nothing_runs(capsys: pytest.CaptureFixture[str]):
    assert live_check.main(["--source", "."]) == 2
    assert "Do not run it on a shared or production host" in capsys.readouterr().err
