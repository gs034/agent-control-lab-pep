# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Request envelope for the reference host.

The agent may send ``tool_name`` and ``args`` only. Any other key is
rejected. The host does not read a clock, a principal, a session id, or a
callable from this object.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from pep.envelope import PROSE_COAX_KEYS, TOOL_NAME_RE

HOST_KEYS = frozenset({"args", "tool_name"})
MAX_REQUEST_BYTES = 65_536
MAX_JSON_DEPTH = 32


class ProtocolError(ValueError):
    """The request is not a host envelope. ``checks`` are what ran."""

    def __init__(self, reason: str, detail: str, checks: list[dict[str, str]]) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.checks = checks


def parse_host_request(raw: bytes | str | Any) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    """Return ``(tool_name, args, checks)`` or raise ``ProtocolError``."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_REQUEST_BYTES:
            raise ProtocolError(
                "envelope_invalid",
                "request exceeds the host limit",
                [{"name": "json_object", "outcome": "deny"}],
            )
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError(
                "envelope_invalid",
                "request is not utf-8",
                [{"name": "json_object", "outcome": "deny"}],
            ) from exc
        body = _decode_json(text)
    elif isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ProtocolError(
                "envelope_invalid",
                "request exceeds the host limit",
                [{"name": "json_object", "outcome": "deny"}],
            )
        body = _decode_json(raw)
    elif isinstance(raw, Mapping):
        body = _copy_mapping(raw)
    else:
        raise ProtocolError(
            "envelope_invalid",
            "request must be a JSON object",
            [{"name": "json_object", "outcome": "deny"}],
        )
    return _interpret(body)


def _decode_json(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        raise ProtocolError(
            "envelope_invalid",
            "request is empty",
            [{"name": "json_object", "outcome": "deny"}],
        )
    if _nesting_exceeds(stripped, MAX_JSON_DEPTH):
        raise ProtocolError(
            "envelope_invalid",
            "request nesting exceeds the host limit",
            [{"name": "json_object", "outcome": "deny"}],
        )
    try:
        return json.loads(stripped, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError, RecursionError, OverflowError, MemoryError) as exc:
        raise ProtocolError(
            "envelope_invalid",
            "json decode failed",
            [{"name": "json_object", "outcome": "deny"}],
        ) from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys rejected")
    return dict(pairs)


def _nesting_exceeds(text: str, limit: int) -> bool:
    """True when ``[`` / ``{`` nesting is deeper than ``limit``.

    ``json.loads`` raises ``RecursionError`` on a deep array and that used
    to kill the connection with no reply. The depth is counted here, outside
    the parser, and strings are skipped so a bracket inside a string does
    not count.
    """
    depth = 0
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char in "[{":
            depth += 1
            if depth > limit:
                return True
            continue
        if char in "]}":
            depth = max(0, depth - 1)
    return False


def _copy_mapping(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Copy a dict from an in-process test without calling any value."""
    try:
        keys = list(raw.keys())
    except Exception as exc:
        raise ProtocolError(
            "envelope_invalid",
            f"request is not a JSON object: {exc}",
            [{"name": "json_object", "outcome": "deny"}],
        ) from exc
    if any(not isinstance(key, str) for key in keys):
        raise ProtocolError(
            "envelope_invalid",
            "request keys must be strings",
            [{"name": "json_object", "outcome": "pass"}, {"name": "envelope_keys", "outcome": "deny"}],
        )
    if len(keys) != len(set(keys)):
        raise ProtocolError(
            "envelope_invalid",
            "duplicate keys rejected",
            [{"name": "json_object", "outcome": "deny"}],
        )
    body: dict[str, Any] = {}
    for key in keys:
        body[key] = raw[key]
    return body


def _interpret(body: Any) -> tuple[str, dict[str, Any], list[dict[str, str]]]:
    if not isinstance(body, dict):
        raise ProtocolError(
            "envelope_invalid",
            "request must be a JSON object",
            [{"name": "json_object", "outcome": "deny"}],
        )
    checks: list[dict[str, str]] = [{"name": "json_object", "outcome": "pass"}]
    extra = set(body) - HOST_KEYS
    coax = extra & PROSE_COAX_KEYS
    if coax:
        checks.append({"name": "envelope_keys", "outcome": "deny", "detail": "policy-coax key"})
        raise ProtocolError(
            "agent_prose_rejected",
            f"policy-coax key rejected: {sorted(coax)}",
            checks,
        )
    if extra:
        checks.append(
            {
                "name": "envelope_keys",
                "outcome": "deny",
                "detail": "unknown keys: " + ", ".join(sorted(extra)),
            }
        )
        raise ProtocolError(
            "envelope_invalid",
            f"unknown envelope keys rejected: {sorted(extra)}",
            checks,
        )
    checks.append({"name": "envelope_keys", "outcome": "pass"})
    tool_name = body.get("tool_name")
    if not isinstance(tool_name, str) or not TOOL_NAME_RE.fullmatch(tool_name):
        checks.append({"name": "tool_name", "outcome": "deny"})
        raise ProtocolError(
            "envelope_invalid",
            "tool_name is missing or malformed",
            checks,
        )
    checks.append({"name": "tool_name", "outcome": "pass"})
    args = body.get("args")
    if not isinstance(args, dict) or any(not isinstance(key, str) for key in args):
        checks.append({"name": "args_json", "outcome": "deny"})
        raise ProtocolError("envelope_invalid", "args must be a JSON object", checks)
    try:
        encoded = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
            checks.append({"name": "args_json", "outcome": "deny"})
            raise ProtocolError("envelope_invalid", "request exceeds the host limit", checks)
        args = json.loads(encoded)
    except ProtocolError:
        raise
    except (TypeError, ValueError, RecursionError, OverflowError, MemoryError) as exc:
        checks.append({"name": "args_json", "outcome": "deny"})
        raise ProtocolError(
            "envelope_invalid",
            f"args are not JSON values: {exc}",
            checks,
        ) from exc
    if not isinstance(args, dict):
        checks.append({"name": "args_json", "outcome": "deny"})
        raise ProtocolError("envelope_invalid", "args must be a JSON object", checks)
    checks.append({"name": "args_json", "outcome": "pass"})
    return tool_name, args, checks
