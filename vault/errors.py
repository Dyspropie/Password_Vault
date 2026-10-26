"""Custom exception classes for the Password Vault application."""

from __future__ import annotations


class VaultError(Exception):
    """Base exception for all vault-related errors."""


class VaultLockedError(VaultError):
    """Raised when an operation requiring an unlocked vault is attempted while locked."""


class VaultAlreadyExistsError(VaultError):
    """Raised when attempting to create a vault that already exists."""


class VaultNotFoundError(VaultError):
    """Raised when an operation is attempted on a non-existent vault."""


class InvalidMasterPasswordError(VaultError):
    """Raised when an incorrect master password is provided."""


class WeakPasswordError(VaultError):
    """Raised when a master password does not meet minimum strength/length requirements."""


class RetryDelayActiveError(VaultError):
    """Raised when an unlock attempt is blocked by an active rate-limiting retry delay."""

    def __init__(self, message: str, remaining_seconds: int) -> None:
        super().__init__(message)
        self.remaining_seconds = remaining_seconds


class EntryNotFoundError(VaultError):
    """Raised when a requested password entry is not found."""


class DuplicateEntryError(VaultError):
    """Raised when adding or updating an entry with an existing (site, username) pair."""


class CategoryNotFoundError(VaultError):
    """Raised when a specified category does not exist."""


class DuplicateCategoryError(VaultError):
    """Raised when creating a category that already exists."""


class BackupError(VaultError):
    """Raised when an encrypted backup or restore operation fails."""


class GeneratorError(VaultError):
    """Raised when password generator parameters are invalid."""


class DatabaseError(VaultError):
    """Raised when a database level operation fails."""
