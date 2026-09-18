# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Deterministic JSON bytes for envelope hashes.

Canonicalisation (this stub)
----------------------------
Parsed JSON is re-encoded as UTF-8 with lexicographic ``sort_keys``,
compact separators ``(",", ":")``, and ``ensure_ascii=True``. That is a
JCS / RFC 8785 subset sufficient for this reference PEP.

``envelope_hash`` is ``sha256:`` plus hex(SHA-256(canonical bytes)).

The Deep Research example receipt hashes the on-disk pretty-printed file
bytes of ``eval/structured_envelope.example.json``. Live receipts hash the
canonical form above, so the digest may differ; the prefix stays ``sha256:``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_bytes(value: Any) -> bytes:
    return canonical_dumps(value).encode("utf-8")


def sha256_prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
