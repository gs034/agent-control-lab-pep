#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Lab-only keep-out: stdlib Python checker (no ripgrep).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${ROOT}/scripts/lab_brand_wall.py" "$@"
