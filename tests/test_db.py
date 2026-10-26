"""Unit tests for the raw SQLite database layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from vault.db import Database


def test_schema_creation(test_db_path: Path) -> None:
    """Verify that init_schema creates all required tables, columns, and indexes."""
    db = Database(test_db_path)
    db.init_schema()

    conn = db.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        assert "meta" in tables
        assert "categories" in tables
        assert "entries" in tables
        assert "password_history" in tables

        cursor.execute("PRAGMA user_version;")
        assert cursor.fetchone()[0] == 1
    finally:
        conn.close()


def test_crud_operations(test_db_path: Path) -> None:
    """Verify CRUD operations for categories, entries, and metadata."""
    db = Database(test_db_path)
    db.init_schema()

    # Meta CRUD
    db.set_meta("test_key", b"test_value")
    assert db.get_meta("test_key") == b"test_value"
    assert db.has_meta("test_key") is True
    assert db.has_meta("non_existent") is False

    # Category CRUD
    cat_id = db.create_category("Personal")
    assert cat_id > 0
    cat_row = db.get_category_by_id(cat_id)
    assert cat_row is not None
    assert cat_row["name"] == "Personal"

    db.update_category(cat_id, "Personal Accounts")
    assert db.get_category_by_id(cat_id)["name"] == "Personal Accounts"

    # Entry CRUD
    entry_id = db.create_entry(
        site="github.com",
        password_enc=b"enc_pwd_blob",
        url="https://github.com",
        category_id=cat_id,
        username_enc=b"enc_user_blob",
        notes_enc=b"enc_notes_blob",
        favorite=0,
        created_at="2026-10-26T12:00:00Z",
        updated_at="2026-10-26T12:00:00Z",
    )
    assert entry_id > 0

    entry = db.get_entry(entry_id)
    assert entry is not None
    assert entry["site"] == "github.com"
    assert entry["url"] == "https://github.com"
    assert entry["category_name"] == "Personal Accounts"
    assert entry["password_enc"] == b"enc_pwd_blob"
    assert entry["favorite"] == 0

    # Update entry
    db.update_entry(
        entry_id=entry_id,
        site="github.com",
        password_enc=b"new_enc_pwd",
        url="https://github.com/login",
        category_id=cat_id,
        username_enc=b"enc_user_blob",
        notes_enc=b"updated_notes",
        favorite=1,
        updated_at="2026-10-26T12:05:00Z",
    )
    updated = db.get_entry(entry_id)
    assert updated["password_enc"] == b"new_enc_pwd"
    assert updated["url"] == "https://github.com/login"
    assert updated["favorite"] == 1

    # List entries
    entries = db.list_entries(category_id=cat_id, favorites_only=True)
    assert len(entries) == 1
    assert entries[0]["id"] == entry_id

    # Delete entry
    db.delete_entry(entry_id)
    assert db.get_entry(entry_id) is None


def test_cascade_delete(test_db_path: Path) -> None:
    """Verify that deleting an entry cascades and deletes all associated password history rows."""
    db = Database(test_db_path)
    db.init_schema()

    entry_id = db.create_entry(
        site="example.com",
        password_enc=b"initial_enc_pwd",
        created_at="2026-10-26T12:00:00Z",
        updated_at="2026-10-26T12:00:00Z",
    )

    # Insert 2 password history entries
    db.create_history_entry(entry_id, b"old_pwd_1", "2026-10-26T12:01:00Z")
    db.create_history_entry(entry_id, b"old_pwd_2", "2026-10-26T12:02:00Z")

    assert len(db.get_history_entries(entry_id)) == 2

    # Delete the parent entry
    db.delete_entry(entry_id)

    # Verify history is automatically deleted via cascade
    assert len(db.get_history_entries(entry_id)) == 0


def test_sql_injection_and_special_characters_safety(test_db_path: Path) -> None:
    """Verify that site names containing quotes, semicolons, and SQL syntax are safely stored."""
    db = Database(test_db_path)
    db.init_schema()

    malicious_site = "site'; DROP TABLE entries; SELECT * FROM meta WHERE '1'='1"
    entry_id = db.create_entry(
        site=malicious_site,
        password_enc=b"safe_pwd",
        url="https://site.com/?q=a';b=c;",
        created_at="2026-10-26T12:00:00Z",
        updated_at="2026-10-26T12:00:00Z",
    )

    row = db.get_entry(entry_id)
    assert row is not None
    assert row["site"] == malicious_site
    assert row["url"] == "https://site.com/?q=a';b=c;"

    # Assert tables were not dropped
    conn = db.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM entries;")
        assert cursor.fetchone()[0] == 1
    finally:
        conn.close()


def test_migration_hook(test_db_path: Path) -> None:
    """Verify that migrate hook detects user_version 0 and upgrades schema properly."""
    db = Database(test_db_path)
    conn = db.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version;")
        assert cursor.fetchone()[0] == 0

        db.migrate(conn)

        cursor.execute("PRAGMA user_version;")
        assert cursor.fetchone()[0] == 1

        # Calling migrate again should be an idempotent no-op
        db.migrate(conn)
        cursor.execute("PRAGMA user_version;")
        assert cursor.fetchone()[0] == 1
    finally:
        conn.close()
