"""Pure cryptographic functions for key derivation, encryption, and verification."""

from __future__ import annotations

import base64
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vault.config import DEFAULT_KDF_PARAMS, VERIFICATION_TOKEN


def generate_salt(length: int = 16) -> bytes:
    """Generate cryptographically secure random salt bytes.

    Args:
        length: Salt length in bytes (default 16).

    Returns:
        Cryptographically secure random bytes.
    """
    return secrets.token_bytes(length)


def derive_key(password: str, salt: bytes, kdf_params: dict[str, Any] | None = None) -> bytes:
    """Derive a 32-byte raw cryptographic key from a password and salt using Scrypt.

    Args:
        password: Master or backup password string.
        salt: Unique salt bytes.
        kdf_params: Optional dict containing 'n', 'r', 'p', 'length'.

    Returns:
        32-byte derived key.
    """
    params = dict(DEFAULT_KDF_PARAMS)
    if kdf_params:
        params.update(kdf_params)

    kdf = Scrypt(
        salt=salt,
        length=int(params.get("length", 32)),
        n=int(params.get("n", 32768)),
        r=int(params.get("r", 8)),
        p=int(params.get("p", 1)),
    )
    return kdf.derive(password.encode("utf-8"))


def derive_fernet_key(password: str, salt: bytes, kdf_params: dict[str, Any] | None = None) -> bytes:
    """Derive a URL-safe base64-encoded 32-byte key suitable for Fernet symmetric encryption.

    Args:
        password: The password string.
        salt: The salt bytes.
        kdf_params: Optional Scrypt parameters.

    Returns:
        URL-safe base64-encoded key bytes for Fernet.
    """
    raw_key = derive_key(password, salt, kdf_params)
    return base64.urlsafe_b64encode(raw_key)


def get_fernet(fernet_key: bytes) -> Fernet:
    """Instantiate a Fernet cipher object from a base64-url encoded key.

    Args:
        fernet_key: Base64-url encoded 32-byte key.

    Returns:
        Fernet cipher instance.
    """
    return Fernet(fernet_key)


def encrypt(fernet: Fernet, data: str | bytes | None) -> bytes | None:
    """Encrypt plaintext string or bytes into a Fernet ciphertext token.

    Args:
        fernet: Fernet cipher instance.
        data: String, bytes, or None to encrypt.

    Returns:
        Encrypted bytes token, or None if data was None.
    """
    if data is None:
        return None
    raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
    return fernet.encrypt(raw_bytes)


def decrypt(fernet: Fernet, token: bytes | None) -> str | None:
    """Decrypt a Fernet ciphertext token back into a UTF-8 string.

    Args:
        fernet: Fernet cipher instance.
        token: Ciphertext bytes token, or None.

    Returns:
        Decrypted UTF-8 string, or None if token was None.

    Raises:
        InvalidToken: If decryption fails (corrupt token or wrong key).
    """
    if token is None:
        return None
    decrypted_bytes = fernet.decrypt(token)
    return decrypted_bytes.decode("utf-8")


def create_verification_token(fernet: Fernet) -> bytes:
    """Encrypt the standard verification constant token using the derived Fernet instance.

    Args:
        fernet: Fernet cipher instance.

    Returns:
        Encrypted verification token bytes.
    """
    return fernet.encrypt(VERIFICATION_TOKEN)


def verify_token(fernet: Fernet, token: bytes) -> bool:
    """Verify that a candidate Fernet instance can correctly decrypt the verification token.

    Args:
        fernet: Fernet cipher instance.
        token: Stored verification token bytes.

    Returns:
        True if the token successfully decrypts to the expected constant, False otherwise.
    """
    try:
        decrypted = fernet.decrypt(token)
        return decrypted == VERIFICATION_TOKEN
    except InvalidToken:
        return False
    except Exception:
        return False
