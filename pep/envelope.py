# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Structured invoke envelope. Agent prose is untrusted data, never policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from pep.canonical import sha256_prefixed
from pep.reasons import ReasonCode

# Flat unit-test envelope.
FLAT_KEYS = frozenset(
    {
        "tool_name",
        "args",
        "capability_token",
        "approval_id",
        "caller_identity",
        "request_id",
        "metadata",
        "untrusted_agent_text",
    }
)

# Lab eval envelope (eval/structured_envelope.example.json).
LAB_KEYS = frozenset(
    {
        "caller",
        "envelope_version",
        "invoke",
        "pep_eval_id",
        "policy_context",
        "untrusted_attachments",
    }
)

TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

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
        "monitor",
        "monitor_allow",
        "monitor_safe",
        "monitor_verdict",
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
    """Policy-relevant structured invoke. Prose attachments are not policy."""

    tool_name: str
    args: Mapping[str, Any]
    capability_token: str | None
    caller_identity: str
    request_id: str
    approval_id: str | None = None
    metadata: Mapping[str, Any] | None = None
    untrusted_agent_text: str | None = None
    source: Mapping[str, Any] | None = None

    def digest(self) -> str:
        payload: Any = dict(self.source) if self.source is not None else self.to_dict()
        return sha256_prefixed(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "args": dict(self.args),
            "capability_token": self.capability_token,
            "approval_id": self.approval_id,
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

    Lab envelopes (``invoke.tool_name``) are the official eval input.
    ``policy_context`` is ignored as a rewrite channel. ``untrusted_attachments``
    is recorded only as a reference — the PEP does not load that file as policy.
    """
    raw = _coerce_mapping(raw)

    if isinstance(raw, InvokeEnvelope):
        _validate_parsed(raw)
        return raw

    if not isinstance(raw, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "envelope must be a JSON object")

    if "invoke" in raw:
        return _parse_lab_envelope(raw)
    return _parse_flat_envelope(raw)


def _coerce_mapping(raw: Any) -> Any:
    if raw is None:
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "envelope is null")

    if isinstance(raw, (bytes, bytearray)):
        try:
            return json.loads(raw.decode("utf-8"))
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
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"json decode failed: {exc}") from exc

    return raw


def _parse_lab_envelope(raw: Mapping[str, Any]) -> InvokeEnvelope:
    extra = set(raw.keys()) - LAB_KEYS
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

    invoke = raw.get("invoke")
    if not isinstance(invoke, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "invoke must be a JSON object")

    tool_name = invoke.get("tool_name")
    _require_tool_name(tool_name)

    schema = invoke.get("schema_fields")
    if schema is None:
        schema = {}
    if not isinstance(schema, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "schema_fields must be a JSON object")

    token = _optional_string(schema.get("capability_token"), "capability_token")
    approval = _optional_string(schema.get("approval_id"), "approval_id")

    args: dict[str, Any] = {}
    if "argv" in invoke:
        if not isinstance(invoke["argv"], list):
            raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "argv must be a JSON array")
        args["argv"] = list(invoke["argv"])
    for key in ("cwd", "network", "env_allowlist"):
        if key in schema:
            args[key] = schema[key]
    _require_json_args(args)

    caller = raw.get("caller")
    if not isinstance(caller, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "caller must be a JSON object")
    identity = caller.get("identity")
    if not isinstance(identity, str) or not IDENTITY_RE.fullmatch(identity):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "caller.identity is missing or malformed")

    request_id = raw.get("pep_eval_id", "unspecified")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "pep_eval_id is malformed")

    attachments = raw.get("untrusted_attachments")
    if attachments is not None and not isinstance(attachments, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "untrusted_attachments must be a JSON object")

    # policy_context is fixture metadata. It is not loaded as PEP policy.
    context = raw.get("policy_context")
    if context is not None and not isinstance(context, Mapping):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "policy_context must be a JSON object")

    return InvokeEnvelope(
        tool_name=str(tool_name),
        args=args,
        capability_token=token,
        approval_id=approval,
        caller_identity=identity,
        request_id=request_id,
        source=dict(raw),
    )


def _parse_flat_envelope(raw: Mapping[str, Any]) -> InvokeEnvelope:
    extra = set(raw.keys()) - FLAT_KEYS
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
    _require_tool_name(tool_name)

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
    _require_json_args(dict(args))

    token = _optional_string(raw.get("capability_token"), "capability_token")
    approval = _optional_string(raw.get("approval_id"), "approval_id")

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

    return InvokeEnvelope(
        tool_name=str(tool_name),
        args=dict(args),
        capability_token=token,
        approval_id=approval,
        caller_identity=caller,
        request_id=request_id,
        metadata=None if not metadata else dict(metadata),
        untrusted_agent_text=untrusted,
        source=dict(raw),
    )


def _optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"{field} must be string or null")
    if value == "":
        return None
    return value


def _require_tool_name(tool_name: Any) -> None:
    if not isinstance(tool_name, str) or not TOOL_NAME_RE.fullmatch(tool_name):
        if isinstance(tool_name, str) and any(ch.isspace() for ch in tool_name):
            raise EnvelopeError(
                ReasonCode.AGENT_PROSE_REJECTED,
                "tool_name is prose, not a structured tool id",
            )
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, "tool_name is missing or malformed")


def _require_json_args(args: dict[str, Any]) -> None:
    try:
        json.dumps(args)
    except (TypeError, ValueError) as exc:
        raise EnvelopeError(ReasonCode.ENVELOPE_INVALID, f"args not JSON-serializable: {exc}") from exc


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
