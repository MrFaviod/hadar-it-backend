"""One demo process per owned directory, enforced with an advisory file lock.

The demo contract says exactly one API process serves a demo directory: the
scheduler resets the whole dataset, so two processes would reset concurrently and
race each other's deletes and reseeds. A PID file alone cannot detect a live
process reliably; ``flock`` is released by the kernel when the process dies, so a
crash never leaves a stale block.
"""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

LOCK_FILE_NAME = "api.lock"


class DemoProcessConflict(RuntimeError):
    """Another process already serves this demo directory."""


class DemoDirectoryLock:
    """Advisory exclusive lock on ``<directory>/api.lock``."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.path = self.directory / LOCK_FILE_NAME
        self._fd: int | None = None

    def acquire(self) -> None:
        """Take the lock or raise without touching anything else."""
        if self._fd is not None:
            raise RuntimeError("demo directory lock is already held")
        if self.path.is_symlink():
            raise DemoProcessConflict(
                f"{self.path} is a link; the demo directory must be owned, not linked"
            )
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            raise DemoProcessConflict(
                f"another demo process already owns {self.directory}; stop it first "
                f"(recovery: python -m itsm.demo recover --directory {self.directory})"
            ) from None
        os.truncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()}\n".encode())
        self._fd = descriptor

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None
