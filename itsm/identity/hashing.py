"""Argon2id password hashing and opaque token digests.

Passwords are never stored or logged in clear text. Session and machine tokens
are random opaque values; only their SHA-256 digest is persisted.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id with 64 MiB and three passes: at least twelve bcrypt-equivalent work
# factor and the current OWASP-recommended baseline.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


@lru_cache(maxsize=1)
def dummy_password_hash() -> str:
    """A real hash used to equalize timing for unknown or password-less accounts."""
    return _HASHER.hash("itsm-dummy-password-value")


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return ``True`` only for a matching password; never raises on bad input."""
    try:
        return _HASHER.verify(password_hash, password)
    except VerifyMismatchError, VerificationError, InvalidHashError:
        return False


def burn_password_check() -> None:
    """Spend the same work as a failed verification for non-existent accounts."""
    verify_password(dummy_password_hash(), "itsm-dummy-password-mismatch")


def hash_token(token: str) -> str:
    """Deterministic SHA-256 digest used to store opaque bearer/session tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
