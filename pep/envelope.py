# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Structured invoke envelope. Agent prose is untrusted data, never policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from pep.canonical import canonical_bytes
from pep.reasons import ReasonCode

# Structured field set. Anything else is an untrusted / coax channel.
STRUCTURED_KEYS = frozenset(
    {
        "tool_name",
        "args",
        "capability_token",
        "caller_identity",
        "request_id",
        "metadata",
        "untrusted_agent_text",
    }
)

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

# Keys that mean "treat this mapping as a policy-rewrite / please-allow attempt".
PROSE_COAX_KEYS = frozenset(
    {
        "please_allow",
        "ignore_previous_policy",
        "policy_override",
        "system",
        "system_prompt",
        "new_policy",
        "allow_all",
        "rewrite_policy",
    }
)


class EnvelopeError(ValueError):
    """Parse/shape failure or untrusted prose on the envelope."""

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class InvokeEnvelope:
    """The only input the PEP evaluates.

    ``metadata`` and ``untrusted_agent_text`` are explicit untrusted
    channels. They are never merged into policy. A non-empty value is a
    deny (``agent_prose_rejected``), not a judge-the-prose branch.
    """

    tool_name: str
    args: Mapping[str, Any]
    capability_token: str | None
    caller_identity: str
    request_id: str
    metadata: Mapping[str, Any] | None = None
    untrusted_agent_text: str | None = None

    def digest(self) -> str:
        import hashlib

        return hashlib.sha256(canonical_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "args": dict(self.args),
            "capability_token": self.capability_token,
            "caller_identity": self.caller_identity,
            "request_id": self.request_id,
            "metadata": None if self.metadata is None else dict(self.metadata),
            "untrusted_agent_text": self.untrusted_agent_text,
        }

    def has_untrusted_prose(self) -> bool:
        if self.untrusted_agent_text is not None and self.untrusted_agent_text != "":
            return True
        if self.metadata:
            return True
        return False


def parse_envelope(raw: Any) -> InvokeEnvelope:
    """Parse a structured envelope. Fail closed on shape or prose channels.

    A free-text string is not an envelope. Extra keys are not policy.
    """
    if raw is None:
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "envelope is null")

    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"json decode failed: {exc}") from exc

    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "envelope is empty string")
        if stripped[0] not in "{[":
            raise EnvelopeError(
                ReasonCode.AGENT_PROSE_REJECTED,
                "free-text payload is not a structured envelope",
            )
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"json decode failed: {exc}") from exc

    if isinstance(raw, InvokeEnvelope):
        _validate_parsed(raw)
        return raw

    if not isinstance(raw, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "envelope must be a JSON object")

    extra = set(raw.keys()) - STRUCTURED_KEYS
    if extra & PROSE_COAX_KEYS:
        raise EnvelopeError(
            ReasonCode.AGENT_PROSE_REJECTED,
            f"policy-coax key rejected: {sorted(extra & PROSE_COAX_KEYS)}",
        )
    if extra:
        raise EnvelopeError(
            ReasonCode.ENVELOPE_INVALID,
            f"non-structured envelope keys rejected: {sorted(extra)}",
        )

    tool_name = raw.get("tool_name")
    if not isinstance(tool_name, str) or not TOOL_NAME_RE.fullmatch(tool_name):
        if isinstance(tool_name, str) and any(ch.isspace() for ch in tool_name):
            raise EnvelopeError(
                ReasonCode.AGENT_PROSE_REJECTED,
                "tool_name is prose, not a structured tool id",
            )
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "tool_name is missing or malformed")

    args = raw.get("args")
    if not isinstance(args, Mapping) or isinstance(args, (str, bytes)):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "args must be a JSON object")
    if any(not isinstance(k, str) for k in args):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "args keys must be strings")
    if any(k in PROSE_COAX_KEYS for k in args):
        raise EnvelopeError(
            ReasonCode.AGENT_PROSE_REJECTED,
            "policy-coax key in args rejected",
        )
    try:
        json.dumps(dict(args))
    except (TypeError, ValueError) as exc:
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"args not JSON-serializable: {exc}") from exc

    token = raw.get("capability_token")
    if token is not None and not isinstance(token, str):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "capability_token must be string or null")
    if isinstance(token, str) and token == "":
        token = None

    caller = raw.get("caller_identity")
    if not isinstance(caller, str) or not IDENTITY_RE.fullmatch(caller):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "caller_identity is missing or malformed")

    request_id = raw.get("request_id", "unspecified")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "request_id is malformed")

    metadata = raw.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, Mapping):
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "metadata must be a JSON object")
        if metadata:
            raise EnvelopeError(
                ReasonCode.AGENT_PROSE_REJECTED,
                "non-empty metadata is untrusted agent prose, not policy",
            )

    untrusted = raw.get("untrusted_agent_text")
    if untrusted is not None:
        if not isinstance(untrusted, str):
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "untrusted_agent_text must be a string")
        if untrusted != "":
            raise EnvelopeError(
                ReasonCode.AGENT_PROSE_REJECTED,
                "untrusted_agent_text is not a policy channel",
            )

    envelope = InvokeEnvelope(
        tool_name=tool_name,
        args=dict(args),
        capability_token=token,
        caller_identity=caller,
        request_id=request_id,
        metadata=None if not metadata else dict(metadata),
        untrusted_agent_text=untrusted,
    )
    return envelope


def _validate_parsed(envelope: InvokeEnvelope) -> None:
    if envelope.has_untrusted_prose():
        raise EnvelopeError(
            ReasonCode.AGENT_PROSE_REJECTED,
            "untrusted agent prose present on structured envelope",
        )
    if not TOOL_NAME_RE.fullmatch(envelope.tool_name):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "tool_name is missing or malformed")
    if not IDENTITY_RE.fullmatch(envelope.caller_identity):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "caller_identity is missing or malformed")
    if not REQUEST_ID_RE.fullmatch(envelope.request_id):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "request_id is malformed")
    if not isinstance(envelope.args, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "args must be a JSON object")
