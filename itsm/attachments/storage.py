"""Opaque-key blob storage; business services never interpret filesystem paths."""

from __future__ import annotations

import os
import re
import stat
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Protocol


class BlobStorage(Protocol):
    def put(self, key: str, data: bytes) -> None: ...
    def read(self, key: str, limit: int) -> bytes: ...
    def delete(self, key: str) -> None: ...


class LocalBlobStorage:
    """Directory-relative, non-following operations on server-generated UUID keys."""

    def __init__(self, root: Path):
        self.root = root

    @contextmanager
    def directory(self, *, create=False):
        # Open every path component without following symlinks, including parents.
        path = self.root.absolute()
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                if part in {".", ".."}:
                    raise OSError("invalid storage directory")
                if create:
                    with suppress(FileExistsError):
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _key(key: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{32}", key):
            raise OSError("invalid storage key")
        return key

    def put(self, key: str, data: bytes) -> None:
        key = self._key(key)
        with self.directory(create=True) as directory:
            fd = os.open(
                key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
            )
            try:
                with os.fdopen(fd, "wb") as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
            except BaseException:
                os.unlink(key, dir_fd=directory)
                raise

    def read(self, key: str, limit: int) -> bytes:
        with self.directory() as directory:
            fd = os.open(
                self._key(key), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
            )
            with os.fdopen(fd, "rb") as source:
                if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                    raise OSError("invalid stored object")
                data = source.read(limit + 1)
                if len(data) > limit:
                    raise OSError("stored object exceeds limit")
                return data

    def delete(self, key: str) -> None:
        with self.directory() as directory:
            os.unlink(self._key(key), dir_fd=directory)
