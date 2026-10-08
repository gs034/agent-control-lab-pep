# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Directory checks for the reference host.

The host refuses a directory it does not own, a symlink, or a directory
another user can write. The halt file and the decision log live in a
directory with no group or other bits. The agent socket directory may
let the agent group traverse it, and must not let that group write it.

Only the directory itself is checked. A parent of that directory is not.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class PathGuardError(OSError):
    """The path is not safe for the host to use."""


def require_directory(path: Path, *, allow_group_traverse: bool) -> os.stat_result:
    """Return ``lstat`` of a directory this process may use.

    ``allow_group_traverse`` is for the agent socket directory: group and
    other may have read or execute, and must not have write. Otherwise the
    directory must be mode 0700 (owner bits only, plus optional setuid or
    setgid). A symlink is refused in either case.
    """
    path = Path(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise PathGuardError(f"directory unreadable: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PathGuardError(f"directory is missing or is a symlink: {path}")
    if info.st_uid != os.getuid():
        raise PathGuardError(f"directory is not owned by this user: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if (mode & 0o700) != 0o700:
        raise PathGuardError(f"directory is not writable by its owner: {path}")
    if allow_group_traverse:
        if mode & 0o022:
            raise PathGuardError(f"directory is writable by group or other: {path}")
    elif mode & 0o077:
        raise PathGuardError(f"directory is accessible to group or other: {path}")
    return info
