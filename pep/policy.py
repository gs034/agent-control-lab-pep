# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Static stub allowlist. Policy is frozen bytes; agents cannot rewrite it.

Allowlist is ``echo.ping`` only (Agent Control Lab public stub). Envelope
``policy_context`` is fixture metadata, not a policy rewrite channel.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

from pep.canonical import canonical_bytes

POLICY_ID = "acl-pep-stub-allowlist-v0"
POLICY_VERSION = "0.1.0-stub"

# Demo catalog only. Not a production control plane.
STUB_POLICY_DOCUMENT: dict[str, Any] = {
    "policy_id": POLICY_ID,
    "policy_version": POLICY_VERSION,
    "fail_closed": True,
    "allowed_tools": {
        "echo.ping": {
            "required_capability": "lab.cap.echo.demo",
            "args_schema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                    "argv": {"type": "array"},
                    "cwd": {"type": "string"},
                    "network": {"type": "boolean"},
                    "env_allowlist": {"type": "array"},
                },
                "additionalProperties": False,
            },
        }
    },
    "capability_tokens": {
        "lab.cap.echo.demo": {
            "tools": ["echo.ping"],
            "expires_at": "2099-01-01T00:00:00+00:00",
        },
        "lab.cap.echo.expired": {
            "tools": ["echo.ping"],
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
    },
}


@dataclass(frozen=True, slots=True)
class PolicyStore:
    """Immutable policy bytes. Digests are taken from the original encoding."""

    raw_bytes: bytes
    digest: str
    document: Mapping[str, Any]

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> PolicyStore:
        raw = canonical_bytes(document)
        parsed = _freeze(json_loads_from_bytes(raw))
        return cls(raw_bytes=raw, digest=hashlib.sha256(raw).hexdigest(), document=parsed)

    @classmethod
    def empty(cls) -> PolicyStore:
        raw = b""
        return cls(raw_bytes=raw, digest=hashlib.sha256(raw).hexdigest(), document=MappingProxyType({}))

    @property
    def version(self) -> str:
        value = self.document.get("policy_version", POLICY_VERSION)
        return str(value) if value else POLICY_VERSION

    def current_digest(self) -> str:
        return hashlib.sha256(self.raw_bytes).hexdigest()

    def bytes_unchanged(self) -> bool:
        return self.current_digest() == self.digest

    def allowed_tools(self) -> Mapping[str, Any]:
        tools = self.document.get("allowed_tools", {})
        if not isinstance(tools, Mapping):
            return MappingProxyType({})
        return tools

    def capability(self, token: str) -> Mapping[str, Any] | None:
        tokens = self.document.get("capability_tokens", {})
        if not isinstance(tokens, Mapping):
            return None
        rec = tokens.get(token)
        if not isinstance(rec, Mapping):
            return None
        return rec


def json_loads_from_bytes(raw: bytes) -> Any:
    import json

    return json.loads(raw.decode("utf-8"))


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def parse_expiry(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def args_match_schema(args: Mapping[str, Any], schema: Mapping[str, Any]) -> bool:
    """Tiny JSON Schema object subset. Unknown schema shapes fail closed."""
    if schema.get("type") != "object":
        return False
    if not isinstance(args, Mapping):
        return False
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return False
    if schema.get("additionalProperties", True) is False:
        if set(args) - set(properties):
            return False
    required = schema.get("required", [])
    if isinstance(required, (list, tuple)):
        for key in required:
            if key not in args:
                return False
    type_map: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "object": Mapping,
        "array": (list, tuple),
    }
    for key, val in args.items():
        spec = properties.get(key)
        if not isinstance(spec, Mapping) or "type" not in spec:
            continue
        expected = type_map.get(str(spec["type"]))
        if expected is None:
            return False
        if isinstance(val, bool) and expected is int:
            return False
        if not isinstance(val, expected):
            return False
        if expected is float and isinstance(val, bool):
            return False
    return True


DEMO_POLICY = PolicyStore.from_document(STUB_POLICY_DOCUMENT)
