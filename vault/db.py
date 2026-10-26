"""Database layer for raw SQLite operations.

Treats encrypted fields as opaque blobs and has no knowledge of cryptographic keys.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from vault.errors import DatabaseError

CURRENT_SCHEMA_VERSION = 1


class Database:
    """Manages SQLite connections, transactions, schema versioning, and CRUD operations."""

    def __init__(self, db_path: Path | str) -> None:
        """Initialize the Database instance.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection.

        Enforces foreign keys, secure delete, and returns Row objects.
        """
        try:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=15.0,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA secure_delete = ON;")
            return conn
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}") from e

    @contextmanager
    def _scope(self, conn: sqlite3.Connection | None) -> Generator[sqlite3.Connection, None, None]:
        """Scope helper for write operations.

        If conn is provided, executes within the caller's transaction without committing or closing.
        If conn is None, acquires a fresh connection with an autocommit transaction block and closes it.
        """
        if conn is not None:
            yield conn
        else:
            c = self.get_connection()
            try:
                with c:
                    yield c
            finally:
                c.close()

    @contextmanager
    def _read_scope(self, conn: sqlite3.Connection | None) -> Generator[sqlite3.Connection, None, None]:
        """Scope helper for read-only operations."""
        if conn is not None:
            yield conn
        else:
            c = self.get_connection()
            try:
                yield c
            finally:
                c.close()

    @contextmanager
    def transaction(self, conn: sqlite3.Connection | None = None) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for an atomic database transaction.

        If a connection is provided, operates on it without closing it.
        Otherwise, manages a fresh connection and closes it upon exit.
        """
        close_on_exit = False
        if conn is None:
            conn = self.get_connection()
            close_on_exit = True

        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise DatabaseError(f"Transaction failed: {e}") from e
        finally:
            if close_on_exit:
                conn.close()

    def init_schema(self) -> None:
        """Initialize or migrate the database schema to the latest version."""
        conn = self.get_connection()
        try:
            with conn:
                self.migrate(conn)
        finally:
            conn.close()

    def migrate(self, conn: sqlite3.Connection) -> None:
        """Run schema migrations based on PRAGMA user_version.

        Args:
            conn: An active SQLite connection.
        """
        cursor = conn.cursor()
        cursor.execute("PRAGMA user_version;")
        version = cursor.fetchone()[0]

        if version == 0:
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS categories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                );

                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT NOT NULL,
                    url TEXT,
                    category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                    username_enc BLOB,
                    password_enc BLOB NOT NULL,
                    notes_enc BLOB,
                    favorite INTEGER DEFAULT 0,
                    created_at TEXT,
                    updated_at TEXT,
                    last_used_at TEXT
                );

                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                    password_enc BLOB NOT NULL,
                    changed_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_entries_site ON entries(site);
                CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category_id);
                CREATE INDEX IF NOT EXISTS idx_history_entry_id ON password_history(entry_id);

                PRAGMA user_version = 1;
                """
            )

    # --- Meta Table Operations ---

    def get_meta(self, key: str, conn: sqlite3.Connection | None = None) -> bytes | None:
        """Retrieve a value by key from the meta table."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute("SELECT value FROM meta WHERE key = ?;", (key,))
            row = cursor.fetchone()
            return row["value"] if row else None

    def set_meta(self, key: str, value: bytes, conn: sqlite3.Connection | None = None) -> None:
        """Insert or replace a key-value pair in the meta table."""
        with self._scope(conn) as c:
            c.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                (key, value),
            )

    def has_meta(self, key: str) -> bool:
        """Check if a key exists in the meta table."""
        return self.get_meta(key) is not None

    # --- Category Operations ---

    def create_category(self, name: str, conn: sqlite3.Connection | None = None) -> int:
        """Create a new category and return its ID."""
        try:
            with self._scope(conn) as c:
                cursor = c.cursor()
                cursor.execute("INSERT INTO categories (name) VALUES (?);", (name,))
                return cursor.lastrowid
        except sqlite3.IntegrityError as e:
            raise DatabaseError(f"Category '{name}' already exists.") from e

    def get_categories(self, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
        """List all categories sorted by name."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute("SELECT id, name FROM categories ORDER BY name COLLATE NOCASE ASC;")
            return cursor.fetchall()

    def get_category_by_id(self, category_id: int, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
        """Retrieve a category by ID."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute("SELECT id, name FROM categories WHERE id = ?;", (category_id,))
            return cursor.fetchone()

    def get_category_by_name(self, name: str, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
        """Retrieve a category by name (case-insensitive)."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute("SELECT id, name FROM categories WHERE LOWER(name) = LOWER(?);", (name.strip(),))
            return cursor.fetchone()

    def update_category(self, category_id: int, name: str, conn: sqlite3.Connection | None = None) -> None:
        """Update a category name."""
        try:
            with self._scope(conn) as c:
                c.execute("UPDATE categories SET name = ? WHERE id = ?;", (name, category_id))
        except sqlite3.IntegrityError as e:
            raise DatabaseError(f"Category '{name}' already exists.") from e

    def delete_category(self, category_id: int, conn: sqlite3.Connection | None = None) -> None:
        """Delete a category. Associated entries will have their category_id set to NULL."""
        with self._scope(conn) as c:
            c.execute("DELETE FROM categories WHERE id = ?;", (category_id,))

    # --- Entry Operations ---

    def create_entry(
        self,
        site: str,
        password_enc: bytes,
        url: str | None = None,
        category_id: int | None = None,
        username_enc: bytes | None = None,
        notes_enc: bytes | None = None,
        favorite: int = 0,
        created_at: str = "",
        updated_at: str = "",
        last_used_at: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        """Insert a new password entry and return its ID."""
        with self._scope(conn) as c:
            cursor = c.cursor()
            cursor.execute(
                """
                INSERT INTO entries (
                    site, url, category_id, username_enc, password_enc,
                    notes_enc, favorite, created_at, updated_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    site,
                    url,
                    category_id,
                    username_enc,
                    password_enc,
                    notes_enc,
                    favorite,
                    created_at,
                    updated_at,
                    last_used_at,
                ),
            )
            return cursor.lastrowid

    def update_entry(
        self,
        entry_id: int,
        site: str,
        password_enc: bytes,
        url: str | None = None,
        category_id: int | None = None,
        username_enc: bytes | None = None,
        notes_enc: bytes | None = None,
        favorite: int = 0,
        updated_at: str = "",
        conn: sqlite3.Connection | None = None,
    ) -> None:
        """Update an existing password entry."""
        with self._scope(conn) as c:
            c.execute(
                """
                UPDATE entries SET
                    site = ?,
                    url = ?,
                    category_id = ?,
                    username_enc = ?,
                    password_enc = ?,
                    notes_enc = ?,
                    favorite = ?,
                    updated_at = ?
                WHERE id = ?;
                """,
                (
                    site,
                    url,
                    category_id,
                    username_enc,
                    password_enc,
                    notes_enc,
                    favorite,
                    updated_at,
                    entry_id,
                ),
            )

    def update_entry_last_used(self, entry_id: int, last_used_at: str, conn: sqlite3.Connection | None = None) -> None:
        """Update the last_used_at timestamp for an entry."""
        with self._scope(conn) as c:
            c.execute("UPDATE entries SET last_used_at = ? WHERE id = ?;", (last_used_at, entry_id))

    def set_favorite(self, entry_id: int, favorite: int, conn: sqlite3.Connection | None = None) -> None:
        """Set the favorite status for an entry."""
        with self._scope(conn) as c:
            c.execute("UPDATE entries SET favorite = ? WHERE id = ?;", (favorite, entry_id))

    def delete_entry(self, entry_id: int, conn: sqlite3.Connection | None = None) -> None:
        """Delete an entry. Cascade delete ensures password_history entries are also removed."""
        with self._scope(conn) as c:
            c.execute("DELETE FROM entries WHERE id = ?;", (entry_id,))

    def get_entry(self, entry_id: int, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
        """Retrieve an entry by ID joined with its category name."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute(
                """
                SELECT e.*, c.name AS category_name
                FROM entries e
                LEFT JOIN categories c ON e.category_id = c.id
                WHERE e.id = ?;
                """,
                (entry_id,),
            )
            return cursor.fetchone()

    def list_entries(
        self,
        category_id: int | None = None,
        favorites_only: bool = False,
        conn: sqlite3.Connection | None = None,
    ) -> list[sqlite3.Row]:
        """List entries matching optional category and favorite filters."""
        with self._read_scope(conn) as c:
            query = """
                SELECT e.id, e.site, e.url, e.category_id, e.username_enc,
                       e.favorite, e.created_at, e.updated_at, e.last_used_at,
                       c.name AS category_name
                FROM entries e
                LEFT JOIN categories c ON e.category_id = c.id
                WHERE 1=1
            """
            params: list[Any] = []
            if category_id is not None:
                query += " AND e.category_id = ?"
                params.append(category_id)
            if favorites_only:
                query += " AND e.favorite = 1"

            query += " ORDER BY LOWER(e.site) ASC, e.id ASC;"
            cursor = c.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def get_all_entries_raw(self, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
        """Retrieve all entries in the database including all encrypted fields."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute(
                """
                SELECT e.*, c.name AS category_name
                FROM entries e
                LEFT JOIN categories c ON e.category_id = c.id
                ORDER BY e.id ASC;
                """
            )
            return cursor.fetchall()

    # --- Password History Operations ---

    def create_history_entry(
        self,
        entry_id: int,
        password_enc: bytes,
        changed_at: str,
        conn: sqlite3.Connection | None = None,
    ) -> int:
        """Record an archived password in password_history."""
        with self._scope(conn) as c:
            cursor = c.cursor()
            cursor.execute(
                "INSERT INTO password_history (entry_id, password_enc, changed_at) VALUES (?, ?, ?);",
                (entry_id, password_enc, changed_at),
            )
            return cursor.lastrowid

    def get_history_entries(self, entry_id: int, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
        """List password history for a given entry, sorted latest first."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute(
                "SELECT id, entry_id, password_enc, changed_at FROM password_history WHERE entry_id = ? ORDER BY changed_at DESC, id DESC;",
                (entry_id,),
            )
            return cursor.fetchall()

    def get_all_history_raw(self, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
        """Retrieve all password history records across all entries."""
        with self._read_scope(conn) as c:
            cursor = c.cursor()
            cursor.execute("SELECT id, entry_id, password_enc, changed_at FROM password_history ORDER BY id ASC;")
            return cursor.fetchall()

    def update_history_password_enc(self, history_id: int, password_enc: bytes, conn: sqlite3.Connection | None = None) -> None:
        """Update encrypted password for a history item (used during master password re-encryption)."""
        with self._scope(conn) as c:
            c.execute("UPDATE password_history SET password_enc = ? WHERE id = ?;", (password_enc, history_id))

    # --- Backup & Replication Helpers ---

    def backup_to(self, target_conn: sqlite3.Connection) -> None:
        """Create a safety copy or backup of the current database using SQLite's backup API."""
        source_conn = self.get_connection()
        try:
            source_conn.backup(target_conn)
        finally:
            source_conn.close()

    def restore_from(self, source_conn: sqlite3.Connection) -> None:
        """Restore the current database from a source connection using SQLite's backup API."""
        target_conn = self.get_connection()
        try:
            source_conn.backup(target_conn)
        finally:
            target_conn.close()
