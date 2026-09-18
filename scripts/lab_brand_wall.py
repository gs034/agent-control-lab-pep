#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Lab-only keep-out wall.

Fails if commercial or bank brand tokens, SKU language, or those source
paths appear in the checkout, file paths, current branch name, or commit
subjects on this branch. The keep-out list is packed so this tree stays
Lab-branded.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Packed keep-out list. Do not decode into comments or docs.
_WORD = (
    "QUVHSVM=",
    "Q2FwU2NvcGU=",
    "QUdG",
    "Q3lnbmV0UXVhbnQ=",
    "U2lnbmV0",
    "U2lnbmV0UXVhbnQ=",
    "RXhjYWxpVkFS",
    "QUlQVEg=",
    "dGhpbmttb25leQ==",
    "RmFsY29u",
    "UElQRUxJTkU=",
    "Q1E=",
)
_PHRASE = (
    "Q3lnbmV0IFF1YW50",
    "U2lnbmV0IFF1YW50",
    "VGhpbmsgTW9uZXk=",
    "SVAtdHJhbnNmZXI=",
    "YWNxdWlyZWQtZnJvbQ==",
)
_PATH_PART = (
    "Y3lnbmV0cXVhbnQ=",
    "dGhpbmttb25leQ==",
)

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".eggs",
        "*.egg-info",
        "dist",
        "build",
        "htmlcov",
        ".mypy_cache",
    }
)


def _decode(packed: tuple[str, ...]) -> list[str]:
    return [base64.b64decode(item).decode("ascii") for item in packed]


def _which_rg() -> str | None:
    from shutil import which

    return which("rg")


def _rg(root: Path, pattern: str, *, word: bool) -> list[str]:
    rg = _which_rg()
    if rg is None:
        raise RuntimeError("rg (ripgrep) is required for the Lab brand wall")
    cmd = [
        rg,
        "-n",
        "-i",
        "--hidden",
        "--no-heading",
        "--color",
        "never",
        "--glob",
        "!.git/**",
        "--glob",
        "!.venv/**",
        "--glob",
        "!**/.pytest_cache/**",
        "--glob",
        "!**/__pycache__/**",
        "--glob",
        "!**/*.egg-info/**",
    ]
    if word:
        cmd.append("-w")
    else:
        cmd.append("-F")
    cmd.extend(["--", pattern, str(root)])
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        err = proc.stderr.strip() or f"rg exited {proc.returncode}"
        raise RuntimeError(err)
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _path_hits(root: Path) -> list[str]:
    parts = [item.lower() for item in _decode(_PATH_PART)]
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIR_NAMES and not name.endswith(".egg-info")]
        rel_dir = Path(dirpath).resolve().relative_to(root.resolve())
        chunks = [p.lower() for p in rel_dir.parts]
        for name in filenames:
            rel = rel_dir / name if rel_dir != Path(".") else Path(name)
            segs = chunks + [name.lower()]
            if any(part in segs or part in str(rel).replace("\\", "/").lower() for part in parts):
                hits.append(f"path:{rel.as_posix()}")
    return hits


def _text_hits(label: str, text: str) -> list[str]:
    hits: list[str] = []
    if not text:
        return hits
    for token in _decode(_WORD):
        if re.search(rf"(?i)\b{re.escape(token)}\b", text):
            hits.append(f"{label}: word-token")
            break
    for phrase in _decode(_PHRASE):
        if phrase.lower() in text.lower():
            hits.append(f"{label}: phrase-token")
            break
    return hits


def _git_output(root: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _git_ref_hits(root: Path) -> list[str]:
    hits: list[str] = []
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME") or ""
    if not branch:
        branch = _git_output(root, ["branch", "--show-current"]).strip()
    hits.extend(_text_hits("branch", branch))

    subjects = ""
    for base in ("origin/main", "main"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", base],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            subjects = _git_output(root, ["log", f"{base}..HEAD", "--format=%s%n%b"])
            break
    if not subjects:
        subjects = _git_output(root, ["log", "-1", "--format=%s%n%b"])
    hits.extend(_text_hits("commit", subjects))
    return hits


def scan(root: Path, *, include_git: bool = True) -> list[str]:
    hits: list[str] = []
    for token in _decode(_WORD):
        hits.extend(_rg(root, token, word=True))
    for phrase in _decode(_PHRASE):
        hits.extend(_rg(root, phrase, word=False))
    hits.extend(_path_hits(root))
    if include_git:
        hits.extend(_git_ref_hits(root))
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lab-only brand wall")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--skip-git", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        hits = scan(root, include_git=not args.skip_git)
    except RuntimeError as exc:
        print(f"LAB BRAND WALL ERROR: {exc}", file=sys.stderr)
        return 2
    if hits:
        print("LAB BRAND WALL: commercial/bank keep-out hit. Lab-only artefacts only.")
        for line in hits:
            print(line)
        return 1
    print("LAB BRAND WALL: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
