"""Unit tests for pure cryptographic operations."""

from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from vault import crypto


def test_round_trip(fast_kdf: dict[str, int]) -> None:
    """Verify that encrypted text can be decrypted back to its exact original form."""
    salt = crypto.generate_salt(16)
    key = crypto.derive_fernet_key("SecretMasterPassword123!", salt, fast_kdf)
    fernet = crypto.get_fernet(key)

    original_text = "MySuperSecretPassword_#@$%123"
    token = crypto.encrypt(fernet, original_text)
    assert token is not None
    assert isinstance(token, bytes)

    decrypted = crypto.decrypt(fernet, token)
    assert decrypted == original_text

    # None handling
    assert crypto.encrypt(fernet, None) is None
    assert crypto.decrypt(fernet, None) is None

    # Empty string handling
    empty_token = crypto.encrypt(fernet, "")
    assert crypto.decrypt(fernet, empty_token) == ""


def test_wrong_password_fails(fast_kdf: dict[str, int]) -> None:
    """Verify that decrypting with a key derived from the wrong password raises InvalidToken."""
    salt = crypto.generate_salt(16)
    key1 = crypto.derive_fernet_key("CorrectPassword123!", salt, fast_kdf)
    key2 = crypto.derive_fernet_key("IncorrectPassword999!", salt, fast_kdf)

    f1 = crypto.get_fernet(key1)
    f2 = crypto.get_fernet(key2)

    token = crypto.encrypt(f1, "SensitiveDataPayload")
    assert token is not None

    with pytest.raises(InvalidToken):
        crypto.decrypt(f2, token)


def test_different_salts_give_different_keys(fast_kdf: dict[str, int]) -> None:
    """Verify that identical passwords with different salts derive different cryptographic keys."""
    salt1 = crypto.generate_salt(16)
    salt2 = crypto.generate_salt(16)
    assert salt1 != salt2

    pwd = "SameMasterPassword123!"
    key1 = crypto.derive_key(pwd, salt1, fast_kdf)
    key2 = crypto.derive_key(pwd, salt2, fast_kdf)

    assert key1 != key2


def test_tampered_ciphertext_raises(fast_kdf: dict[str, int]) -> None:
    """Verify that tampering with any byte of the ciphertext causes decryption to fail."""
    salt = crypto.generate_salt(16)
    key = crypto.derive_fernet_key("ValidPassword123!", salt, fast_kdf)
    fernet = crypto.get_fernet(key)

    token = crypto.encrypt(fernet, "IntegrityProtectedText")
    assert token is not None

    # Flip one byte in the ciphertext payload
    tampered = bytearray(token)
    tampered[-5] = (tampered[-5] + 1) % 256
    tampered_bytes = bytes(tampered)

    with pytest.raises(InvalidToken):
        crypto.decrypt(fernet, tampered_bytes)


def test_same_text_encrypted_twice_gives_different_tokens(fast_kdf: dict[str, int]) -> None:
    """Verify that Fernet produces distinct ciphertexts for identical inputs due to random IV."""
    salt = crypto.generate_salt(16)
    key = crypto.derive_fernet_key("ValidPassword123!", salt, fast_kdf)
    fernet = crypto.get_fernet(key)

    plaintext = "IdenticalPlaintext"
    token1 = crypto.encrypt(fernet, plaintext)
    token2 = crypto.encrypt(fernet, plaintext)

    assert token1 != token2
    assert crypto.decrypt(fernet, token1) == plaintext
    assert crypto.decrypt(fernet, token2) == plaintext


def test_verification_token_works(fast_kdf: dict[str, int]) -> None:
    """Verify that verification token correctly identifies correct vs incorrect keys."""
    salt = crypto.generate_salt(16)
    correct_key = crypto.derive_fernet_key("CorrectPassword123!", salt, fast_kdf)
    wrong_key = crypto.derive_fernet_key("WrongPassword123!", salt, fast_kdf)

    correct_fernet = crypto.get_fernet(correct_key)
    wrong_fernet = crypto.get_fernet(wrong_key)

    token = crypto.create_verification_token(correct_fernet)

    assert crypto.verify_token(correct_fernet, token) is True
    assert crypto.verify_token(wrong_fernet, token) is False
    assert crypto.verify_token(correct_fernet, b"garbage_token_bytes") is False
