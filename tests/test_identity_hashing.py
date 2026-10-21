"""Password hashing must be salted Argon2id, never reversible or comparable."""

from __future__ import annotations

from itsm.identity.hashing import hash_password, hash_token, verify_password


def test_password_hash_is_argon2id_and_verifies_the_original() -> None:
    digest = hash_password("correct horse battery staple")

    assert digest.startswith("$argon2id$")
    assert "correct horse" not in digest
    assert verify_password(digest, "correct horse battery staple") is True


def test_password_hash_rejects_a_different_password() -> None:
    digest = hash_password("correct horse battery staple")

    assert verify_password(digest, "correct horse battery stapl3") is False
    assert verify_password(digest, "") is False


def test_each_password_hash_uses_a_fresh_salt() -> None:
    first = hash_password("identical password value")
    second = hash_password("identical password value")

    assert first != second
    assert verify_password(first, "identical password value") is True
    assert verify_password(second, "identical password value") is True


def test_token_digest_is_deterministic_and_does_not_leak_the_token() -> None:
    token = "itsm_mk_example-token-value"

    digest = hash_token(token)

    assert digest == hash_token(token)
    assert len(digest) == 64
    assert token not in digest
    assert hash_token("another-token") != digest
