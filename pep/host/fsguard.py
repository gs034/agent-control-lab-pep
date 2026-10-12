# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Directory and file checks for the reference host.

The host refuses a directory it does not own, a symlink, or a directory
another user can write. The halt file, the decision log, and a policy
file loaded from disk live in a directory with no group or other bits.
The agent socket directory may let the agent group traverse it, and
must not let that group write it.

Only the directory itself is checked. A parent of that directory is not.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

# A policy file larger than this is refused. The halt reader uses the same bound.
PRIVATE_FILE_LIMIT = 1_048_576


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


def file_owner(info: os.stat_result) -> int:
    """User id that owns a file the host has already opened."""
    return int(info.st_uid)


def read_private_file(path: Path, *, limit: int = PRIVATE_FILE_LIMIT) -> bytes:
    """Read a regular file without following a symlink.

    The parent directory must be private to this user. The file must be
    a regular file owned by this user, readable by its owner, and not
    accessible to group or other. Any failure raises ``PathGuardError``.
    """
    path = Path(path)
    require_directory(path.parent, allow_group_traverse=False)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathGuardError(f"file is a symlink: {path}") from exc
        raise PathGuardError(f"file unreadable: {path}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PathGuardError(f"file is not a regular file: {path}")
        if file_owner(info) != os.getuid():
            raise PathGuardError(f"file is not owned by this user: {path}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o077:
            raise PathGuardError(f"file is accessible to group or other: {path}")
        if (mode & 0o400) == 0:
            raise PathGuardError(f"file is not readable by its owner: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise PathGuardError(f"file exceeds the read limit: {path}")
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)
