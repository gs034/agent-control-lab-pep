# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Optional host-side helpers for ADR-0004 implementation digests.

The PEP compares opaque ``sha256:`` digests and never resolves anything
itself. These helpers are one way for a host to compute a digest at mint and
again in its observer. ``evaluate`` does not call them, and they are not a
definition of implementation identity.
"""

from __future__ import annotations

import hashlib
import marshal
import shutil
from collections.abc import Callable
from pathlib import Path


def executable_digest(name: str, path: str | None = None) -> str:
    """Digest of the program ``name`` resolves to: its real path plus its bytes.

    ``path`` is a search path in ``PATH`` format; ``None`` uses the process
    ``PATH``. Symlinks are followed, so retargeting a link changes the digest.
    A name that does not resolve raises ``FileNotFoundError``, which an
    observer turns into a fail-closed mismatch.
    """
    resolved = shutil.which(name, path=path)
    if resolved is None:
        raise FileNotFoundError(f"executable not found: {name}")
    real = Path(resolved).resolve()
    return _digest(str(real).encode("utf-8") + b"\0" + real.read_bytes())


def callable_digest(fn: Callable[..., object]) -> str:
    """Digest of an in-process callable: module, qualified name and code object.

    The code object is serialised with ``marshal``, so the digest is stable
    within one interpreter version, not across versions. Closure cell values,
    globals and anything the code imports at call time are not covered.
    A bound method digests as its function. Callables without a Python
    code object raise ``TypeError``.
    """
    code = getattr(fn, "__code__", None)
    if code is None:
        raise TypeError(f"callable has no Python code object: {fn!r}")
    header = f"{fn.__module__}\0{fn.__qualname__}\0".encode("utf-8")
    return _digest(header + marshal.dumps(code))


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
