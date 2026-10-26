"""Password Vault package."""

from __future__ import annotations

from vault.errors import (
    BackupError,
    CategoryNotFoundError,
    DatabaseError,
    DuplicateCategoryError,
    DuplicateEntryError,
    EntryNotFoundError,
    GeneratorError,
    InvalidMasterPasswordError,
    RetryDelayActiveError,
    VaultAlreadyExistsError,
    VaultError,
    VaultLockedError,
    VaultNotFoundError,
    WeakPasswordError,
)
from vault.service import VaultService

__all__ = [
    "VaultService",
    "VaultError",
    "VaultLockedError",
    "VaultAlreadyExistsError",
    "VaultNotFoundError",
    "InvalidMasterPasswordError",
    "WeakPasswordError",
    "RetryDelayActiveError",
    "EntryNotFoundError",
    "DuplicateEntryError",
    "CategoryNotFoundError",
    "DuplicateCategoryError",
    "BackupError",
    "GeneratorError",
    "DatabaseError",
]
