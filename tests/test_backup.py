"""Unit tests for encrypted backup (.vbak) and CSV import/export."""

from __future__ import annotations

from pathlib import Path

import pytest

from vault import backup
from vault.errors import BackupError
from vault.service import VaultService


def test_backup_round_trip(tmp_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that entries can be exported to .vbak and decrypted back intact."""
    entries = [
        {
            "site": "github.com",
            "url": "https://github.com",
            "category": "Development",
            "username": "dev_user",
            "password": "s3cr3tPassword!",
            "notes": "SSH key stored in ~/.ssh",
            "favorite": True,
        },
        {
            "site": "amazon.com",
            "url": "https://amazon.com",
            "category": "Shopping",
            "username": "shopper@mail.com",
            "password": "AmzP@ssw0rd999",
            "notes": "",
            "favorite": False,
        },
    ]

    backup_path = tmp_path / "test_backup.vbak"
    password = "BackupEncryptionPassword123!"

    backup.export_backup(entries, password, backup_path, kdf_params=fast_kdf)
    assert backup_path.is_file()

    restored = backup.read_backup(backup_path, password)
    assert len(restored) == 2
    assert restored[0]["site"] == "github.com"
    assert restored[0]["password"] == "s3cr3tPassword!"
    assert restored[1]["site"] == "amazon.com"
    assert restored[1]["username"] == "shopper@mail.com"


def test_backup_wrong_password_raises(tmp_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that attempting to restore a backup with an incorrect password raises BackupError."""
    entries = [{"site": "example.com", "password": "pass"}]
    backup_path = tmp_path / "protected.vbak"

    backup.export_backup(entries, "CorrectBackupPass123!", backup_path, kdf_params=fast_kdf)

    with pytest.raises(BackupError):
        backup.read_backup(backup_path, "WrongBackupPass123!")


def test_backup_corrupted_file_raises(tmp_path: Path) -> None:
    """Verify that attempting to restore an invalid or tampered backup file raises BackupError."""
    corrupt_path = tmp_path / "corrupt.vbak"
    corrupt_path.write_text("{This is not valid JSON!}", encoding="utf-8")

    with pytest.raises(BackupError):
        backup.read_backup(corrupt_path, "AnyPassword123!")

    # Missing required keys
    corrupt_path.write_text('{"version": 1, "data": "abc"}', encoding="utf-8")
    with pytest.raises(BackupError):
        backup.read_backup(corrupt_path, "AnyPassword123!")


def test_service_backup_duplicate_skipping(test_db_path: Path, tmp_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that importing a backup skips entries that match an existing site and username."""
    service = VaultService(test_db_path)
    service.create_vault("VaultMasterPass123!", kdf_params=fast_kdf)

    # Pre-existing entry
    service.add_entry("github.com", username="alice", password="existing_pass")

    # Create backup containing one duplicate and one new entry
    backup_entries = [
        {"site": "github.com", "username": "alice", "password": "new_pass_ignored"},
        {"site": "gitlab.com", "username": "bob", "password": "gitlab_pass"},
    ]
    backup_file = tmp_path / "merge.vbak"
    backup.export_backup(backup_entries, "BackupPass123!", backup_file, kdf_params=fast_kdf)

    imported, skipped = service.import_backup("BackupPass123!", backup_file)
    assert imported == 1
    assert skipped == 1

    entries = service.list_entries()
    assert len(entries) == 2
    sites = {e["site"] for e in entries}
    assert sites == {"github.com", "gitlab.com"}


def test_csv_import_chrome_and_firefox(test_db_path: Path, tmp_path: Path, fast_kdf: dict[str, int]) -> None:
    """Verify that both Chrome and Firefox CSV export formats are auto-detected and imported."""
    service = VaultService(test_db_path)
    service.create_vault("VaultMasterPass123!", kdf_params=fast_kdf)

    # 1. Chrome CSV format
    chrome_csv = tmp_path / "chrome_export.csv"
    chrome_csv.write_text(
        "name,url,username,password,note\n"
        "Google,https://accounts.google.com,test@gmail.com,ChromePass123!,Personal account\n"
        "Twitter,https://twitter.com,tw_handle,TweetPass456!,\n",
        encoding="utf-8",
    )

    imported, skipped = service.import_csv(chrome_csv)
    assert imported == 2
    assert skipped == 0

    # 2. Firefox CSV format
    firefox_csv = tmp_path / "firefox_export.csv"
    firefox_csv.write_text(
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
        "https://reddit.com,reddit_user,RedditPass789!,,,uuid-1234,1600000000,1600000000,1600000000\n",
        encoding="utf-8",
    )

    imported_ff, skipped_ff = service.import_csv(firefox_csv)
    assert imported_ff == 1
    assert skipped_ff == 0

    entries = service.list_entries()
    assert len(entries) == 3
