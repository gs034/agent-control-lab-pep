# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Lab-only brand wall: tree stays clean; planted keep-out tokens fail."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lab_brand_wall.py"
WRAPPER = ROOT / "scripts" / "check_lab_only.sh"


def _run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd or ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _path_without_rg() -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = "/usr/bin:/bin"
    return env


def test_current_tree_is_lab_only():
    proc = _run(env=_path_without_rg())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout


def test_planted_word_token_fails(tmp_path: Path):
    token = base64.b64decode("QUVHSVM=").decode("ascii")
    (tmp_path / "planted.txt").write_text(f"noise {token} noise\n", encoding="utf-8")
    proc = _run("--root", str(tmp_path), "--skip-git", env=_path_without_rg())
    assert proc.returncode == 1
    assert "keep-out" in proc.stdout


def test_planted_path_segment_fails(tmp_path: Path):
    segment = base64.b64decode("dGhpbmttb25leQ==").decode("ascii")
    nested = tmp_path / segment
    nested.mkdir()
    (nested / "readme.txt").write_text("lab\n", encoding="utf-8")
    proc = _run("--root", str(tmp_path), "--skip-git", env=_path_without_rg())
    assert proc.returncode == 1
    assert "path:" in proc.stdout


def test_wrapper_is_stdlib_python_without_rg():
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'which("rg")' not in source
    assert "command -v rg" not in source
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert "lab_brand_wall.py" in wrapper
    assert "command -v rg" not in wrapper
    proc = subprocess.run(
        ["bash", str(WRAPPER)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=_path_without_rg(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean" in proc.stdout
