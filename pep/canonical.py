# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Deterministic JSON bytes for digests and HMAC attestation."""

from __future__ import annotations

import json
from typing import Any


def canonical_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(value: Any) -> bytes:
    return canonical_dumps(value).encode("utf-8")
