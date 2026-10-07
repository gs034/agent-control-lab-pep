# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Reference host for the Policy Enforcement Point (PEP).

A separate process. The agent reaches it only with a request envelope.
This package is a reference prototype, not a measured attack-success
reduction and not a product. See ADR-0007.
"""

from pep.host.server import ReferenceHost

__all__ = ["ReferenceHost"]
