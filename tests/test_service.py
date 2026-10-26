"""Unit tests for VaultService lifecycle, security, encryption, and CRUD."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vault.errors import (
    DuplicateEntryError,
    InvalidMasterPasswordError,
    RetryDelayActiveError,
    VaultLockedError,
    WeakPasswordError,
)
from vault.service import VaultService


def test_create_lock_unlock(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify standard create, lock, and unlock lifecycle."""
    service = VaultService(test_db_path)
    assert service.vault_exists() is False
    assert service.is_unlocked() is False

    # Enforce minimum master password length (12 characters)
    with pytest.raises(WeakPasswordError):
        service.create_vault("Short1!", kdf_params=fast_kdf)

    password = "MasterPassword123!"
    service.create_vault(password, kdf_params=fast_kdf)
    assert service.vault_exists() is True
    assert service.is_unlocked() is True

    # Lock vault
    service.lock()
    assert service.is_unlocked() is False

    # Unlock with correct password
    service.unlock(password)
    assert service.is_unlocked() is True


def test_wrong_password_unlock(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that wrong master password raises InvalidMasterPasswordError."""
    service = VaultService(test_db_path)
    service.create_vault("CorrectPassword123!", kdf_params=fast_kdf)
    service.lock()

    with pytest.raises(InvalidMasterPasswordError):
        service.unlock("IncorrectPass123!")

    assert service.is_unlocked() is False


def test_locked_service_refuses_operations(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that every protected method raises VaultLockedError when locked."""
    service = VaultService(test_db_path)
    service.create_vault("MasterPassword123!", kdf_params=fast_kdf)
    service.lock()

    with pytest.raises(VaultLockedError):
        service.add_entry("github.com", "user", "pass")

    with pytest.raises(VaultLockedError):
        service.update_entry(1, "github.com", "user", "pass")

    with pytest.raises(VaultLockedError):
        service.delete_entry(1)

    with pytest.raises(VaultLockedError):
        service.list_entries()

    with pytest.raises(VaultLockedError):
        service.get_secret(1)

    with pytest.raises(VaultLockedError):
        service.toggle_favorite(1)

    with pytest.raises(VaultLockedError):
        service.list_categories()

    with pytest.raises(VaultLockedError):
        service.change_master_password("MasterPassword123!", "NewPassword123!")

    with pytest.raises(VaultLockedError):
        service.export_backup("BackupPassword123!", test_db_path.parent / "backup.vbak")

    with pytest.raises(VaultLockedError):
        service.find_duplicates()


def test_retry_delay_logic(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify exponential rate-limiting delays after 3 consecutive failed unlocks."""
    service = VaultService(test_db_path)
    service.create_vault("ValidMasterPass123!", kdf_params=fast_kdf)
    service.lock()

    assert service.seconds_until_retry() == 0

    # Attempt 1 fail -> no delay
    with pytest.raises(InvalidMasterPasswordError):
        service.unlock("WrongPassword1!")
    assert service.seconds_until_retry() == 0

    # Attempt 2 fail -> no delay
    with pytest.raises(InvalidMasterPasswordError):
        service.unlock("WrongPassword2!")
    assert service.seconds_until_retry() == 0

    # Attempt 3 fail -> 2s delay enforced
    with pytest.raises(InvalidMasterPasswordError):
        service.unlock("WrongPassword3!")

    remaining = service.seconds_until_retry()
    assert remaining > 0

    # Calling unlock during active backoff raises RetryDelayActiveError
    with pytest.raises(RetryDelayActiveError) as exc_info:
        service.unlock("AnyPassword123!")
    assert exc_info.value.remaining_seconds > 0

    # Advance time artificially to clear delay
    future_time = service._next_retry_at + 1.0
    with patch("time.monotonic", return_value=future_time):
        assert service.seconds_until_retry() == 0
        service.unlock("ValidMasterPass123!")
        assert service.is_unlocked() is True


def test_duplicate_entry_prevention(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that DuplicateEntryError is raised when adding or updating duplicate site + username."""
    service = VaultService(test_db_path)
    service.create_vault("MasterPassword123!", kdf_params=fast_kdf)

    entry1_id = service.add_entry("github.com", username="alice", password="pwd1")
    assert entry1_id > 0

    # Same site, same username (case-insensitive) -> DuplicateEntryError
    with pytest.raises(DuplicateEntryError):
        service.add_entry("GitHub.com", username="Alice", password="pwd2")

    # Same site, different username -> Allowed
    entry2_id = service.add_entry("github.com", username="bob", password="pwd3")
    assert entry2_id > 0

    # Updating entry2 to match entry1 -> DuplicateEntryError
    with pytest.raises(DuplicateEntryError):
        service.update_entry(entry2_id, site="github.com", username="alice", password="pwd3")


def test_password_history_tracking(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that updating an entry's password records previous passwords in password_history."""
    service = VaultService(test_db_path)
    service.create_vault("MasterPassword123!", kdf_params=fast_kdf)

    entry_id = service.add_entry("example.com", username="user", password="OriginalPassword1!")

    # Verify initial history is empty
    assert len(service.get_password_history(entry_id)) == 0

    # Update with new password
    service.update_entry(entry_id, site="example.com", username="user", password="SecondPassword2@")
    history1 = service.get_password_history(entry_id)
    assert len(history1) == 1
    assert history1[0]["password"] == "OriginalPassword1!"

    # Update again
    service.update_entry(entry_id, site="example.com", username="user", password="ThirdPassword3#")
    history2 = service.get_password_history(entry_id)
    assert len(history2) == 2
    assert history2[0]["password"] == "SecondPassword2@"
    assert history2[1]["password"] == "OriginalPassword1!"

    # Current secret is third password
    assert service.get_secret(entry_id)["password"] == "ThirdPassword3#"


def test_change_master_password_and_rollback_on_failure(test_db_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify master password change re-encrypts all entries and safely rolls back on failure."""
    service = VaultService(test_db_path)
    service.create_vault("InitialMasterPass123!", kdf_params=fast_kdf)

    # Add entries
    e1 = service.add_entry("site1.com", username="user1", password="SecretPassword1!", notes="Note 1")
    e2 = service.add_entry("site2.com", username="user2", password="SecretPassword2!", notes="Note 2")

    # Update e1 to create password history
    service.update_entry(e1, site="site1.com", username="user1", password="UpdatedPassword1!", notes="Note 1")

    # 1. Successful change master password
    new_pwd = "BrandNewMasterPass123!"
    service.change_master_password("InitialMasterPass123!", new_pwd, kdf_params=fast_kdf)

    # Re-lock and unlock with new password
    service.lock()
    with pytest.raises(InvalidMasterPasswordError):
        service.unlock("InitialMasterPass123!")

    service.unlock(new_pwd)
    assert service.is_unlocked() is True

    # Check entries and history are intact and readable
    assert service.get_secret(e1)["password"] == "UpdatedPassword1!"
    assert service.get_secret(e2)["password"] == "SecretPassword2!"
    history = service.get_password_history(e1)
    assert len(history) == 1
    assert history[0]["password"] == "SecretPassword1!"

    # 2. Forced failure test: simulate error during transaction
    failing_pwd = "FailingMasterPass123!"
    with patch.object(service.db, "transaction", side_effect=RuntimeError("Simulated write failure")):
        with pytest.raises(RuntimeError):
            service.change_master_password(new_pwd, failing_pwd, kdf_params=fast_kdf)

    # Verify rollback: new_pwd still works, failing_pwd does not
    service.lock()
    service.unlock(new_pwd)
    assert service.is_unlocked() is True
    assert service.get_secret(e1)["password"] == "UpdatedPassword1!"
