# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Hostile-reviewer check: this is not an LLM monitor + HITL path."""

from __future__ import annotations

import ast
from pathlib import Path

PEP_DIR = Path(__file__).resolve().parents[1] / "pep"

BANNED_MODULES = {
    "openai",
    "anthropic",
    "litellm",
    "together",
    "cohere",
    "requests",
    "httpx",
    "aiohttp",
    "urllib",
    "urllib3",
    "huggingface_hub",
}

BANNED_NAMES = {
    "judge",
    "llm",
    "cot",
    "transcript",
    "hitl",
    "monitor_score",
    "ask_model",
}


def test_pep_sources_have_no_model_or_http_imports():
    for path in PEP_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in BANNED_MODULES, f"{path.name} imports {alias.name}"
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in BANNED_MODULES, f"{path.name} imports {node.module}"


def test_evaluate_defines_no_judge_entrypoints():
    source = (PEP_DIR / "evaluate.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {node.name.lower() for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert "evaluate" in {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    for banned in BANNED_NAMES:
        assert banned not in names


def test_evaluate_docstring_states_trust_domain():
    text = (PEP_DIR / "evaluate.py").read_text(encoding="utf-8")
    assert "Trust domain" in text
    assert "not an LLM" in text.lower() or "no LLM" in text
    assert "evaluate()" in text
