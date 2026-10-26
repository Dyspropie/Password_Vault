"""High-level VaultService orchestrating database and cryptographic operations."""

from __future__ import annotations

import datetime
import json
import math
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from vault import backup, crypto
from vault.config import (
    DEFAULT_AUTOLOCK_MINUTES,
    DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_KDF_PARAMS,
    DEFAULT_LOCK_ON_MINIMIZE,
    MIN_MASTER_PASSWORD_LENGTH,
    get_default_db_path,
)
from vault.db import Database
from vault.errors import (
    CategoryNotFoundError,
    DuplicateCategoryError,
    DuplicateEntryError,
    EntryNotFoundError,
    InvalidMasterPasswordError,
    RetryDelayActiveError,
    VaultAlreadyExistsError,
    VaultLockedError,
    VaultNotFoundError,
    WeakPasswordError,
)


def _utc_now_iso() -> str:
    """Return current UTC time formatted as ISO-8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class VaultService:
    """Core application service managing vault lifecycle, data encryption, and storage."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize VaultService with a database path.

        Args:
            db_path: Path to the SQLite database file (defaults to config location).
        """
        self.db_path = Path(db_path) if db_path is not None else get_default_db_path()
        self.db = Database(self.db_path)

        self._fernet: Fernet | None = None
        self._fail_count: int = 0
        self._next_retry_at: float = 0.0

    # --- Vault Lifecycle & Authentication ---

    def vault_exists(self) -> bool:
        """Check if an initialized vault database exists with required metadata."""
        if not self.db_path.exists():
            return False
        try:
            salt = self.db.get_meta("salt")
            token = self.db.get_meta("verification_token")
            return salt is not None and token is not None
        except Exception:
            return False

    def is_unlocked(self) -> bool:
        """Return True if the vault is unlocked and encryption key is resident in memory."""
        return self._fernet is not None

    def seconds_until_retry(self) -> int:
        """Return the number of seconds remaining before unlock attempts are permitted."""
        now = time.monotonic()
        if self._next_retry_at > now:
            return max(0, int(math.ceil(self._next_retry_at - now)))
        return 0

    def lock(self) -> None:
        """Lock the vault, discarding the resident key and sensitive state from memory."""
        self._fernet = None

    def _require_unlocked(self) -> Fernet:
        """Assert the vault is unlocked and return the active Fernet cipher."""
        if self._fernet is None:
            raise VaultLockedError("Vault is locked. Unlock the vault to perform this operation.")
        return self._fernet

    def create_vault(self, master_password: str, kdf_params: dict[str, Any] | None = None) -> None:
        """Create and initialize a new password vault.

        Args:
            master_password: The user's master password (minimum 12 characters).
            kdf_params: Optional custom Scrypt parameters.

        Raises:
            WeakPasswordError: If password is less than 12 characters.
            VaultAlreadyExistsError: If a vault already exists at db_path.
        """
        if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters."
            )

        if self.vault_exists():
            raise VaultAlreadyExistsError("A vault already exists at this location.")

        self.db.init_schema()

        active_kdf = dict(kdf_params or DEFAULT_KDF_PARAMS)
        salt = crypto.generate_salt(16)
        fernet_key = crypto.derive_fernet_key(master_password, salt, active_kdf)
        fernet = crypto.get_fernet(fernet_key)
        verification_token = crypto.create_verification_token(fernet)

        with self.db.transaction() as conn:
            self.db.set_meta("salt", salt, conn=conn)
            self.db.set_meta("kdf_params", json.dumps(active_kdf).encode("utf-8"), conn=conn)
            self.db.set_meta("verification_token", verification_token, conn=conn)
            self.db.set_meta("autolock_minutes", str(DEFAULT_AUTOLOCK_MINUTES).encode("utf-8"), conn=conn)
            self.db.set_meta("clipboard_clear_seconds", str(DEFAULT_CLIPBOARD_CLEAR_SECONDS).encode("utf-8"), conn=conn)
            self.db.set_meta("lock_on_minimize", ("1" if DEFAULT_LOCK_ON_MINIMIZE else "0").encode("utf-8"), conn=conn)

        self._fernet = fernet
        self._fail_count = 0
        self._next_retry_at = 0.0

    def unlock(self, master_password: str) -> None:
        """Authenticate with master password and unlock the vault.

        Enforces exponential rate limiting after 3 consecutive failures.

        Args:
            master_password: Master password candidate.

        Raises:
            RetryDelayActiveError: If an unlock attempt is blocked by rate-limiting.
            VaultNotFoundError: If no vault exists to unlock.
            InvalidMasterPasswordError: If the master password is incorrect.
        """
        retry_delay = self.seconds_until_retry()
        if retry_delay > 0:
            raise RetryDelayActiveError(
                f"Too many failed unlock attempts. Please wait {retry_delay} seconds.",
                remaining_seconds=retry_delay,
            )

        if not self.vault_exists():
            raise VaultNotFoundError("No password vault found.")

        salt = self.db.get_meta("salt")
        token = self.db.get_meta("verification_token")
        kdf_json = self.db.get_meta("kdf_params")

        if not salt or not token:
            raise VaultNotFoundError("Vault metadata is incomplete or corrupted.")

        kdf_params = json.loads(kdf_json.decode("utf-8")) if kdf_json else DEFAULT_KDF_PARAMS

        fernet_key = crypto.derive_fernet_key(master_password, salt, kdf_params)
        candidate_fernet = crypto.get_fernet(fernet_key)

        if not crypto.verify_token(candidate_fernet, token):
            self._fail_count += 1
            if self._fail_count >= 3:
                # 3 failures -> 2s, 4 failures -> 4s, 5 failures -> 8s, doubling up to 60s
                delay = min(60, 2 ** (self._fail_count - 2))
                self._next_retry_at = time.monotonic() + delay
            raise InvalidMasterPasswordError("Invalid master password.")

        # Unlock successful
        self._fernet = candidate_fernet
        self._fail_count = 0
        self._next_retry_at = 0.0

    def _get_stored_kdf_params(self) -> dict[str, Any]:
        """Retrieve stored KDF parameters from metadata."""
        kdf_json = self.db.get_meta("kdf_params")
        if kdf_json:
            try:
                return json.loads(kdf_json.decode("utf-8"))
            except Exception:
                pass
        return dict(DEFAULT_KDF_PARAMS)

    # --- Entry Operations ---

    def _check_duplicate(self, site: str, username: str, exclude_id: int | None = None) -> None:
        """Check for existing entries with identical site and username (case-insensitive)."""
        fernet = self._require_unlocked()
        clean_site = site.strip().lower()
        clean_user = username.strip().lower()

        raw_entries = self.db.get_all_entries_raw()
        for row in raw_entries:
            if exclude_id is not None and row["id"] == exclude_id:
                continue
            if row["site"].strip().lower() == clean_site:
                existing_user = (crypto.decrypt(fernet, row["username_enc"]) or "").strip().lower()
                if existing_user == clean_user:
                    raise DuplicateEntryError(
                        f"An entry for site '{site}' with username '{username}' already exists."
                    )

    def add_entry(
        self,
        site: str,
        username: str = "",
        password: str = "",
        url: str = "",
        category_id: int | None = None,
        notes: str = "",
        favorite: bool = False,
    ) -> int:
        """Create a new encrypted password entry.

        Args:
            site: Name/identifier of the service or website.
            username: Plaintext username/login.
            password: Plaintext password.
            url: Plaintext URL.
            category_id: Foreign key ID to categories table, or None.
            notes: Plaintext notes.
            favorite: Boolean favorite flag.

        Returns:
            The newly created entry ID.

        Raises:
            DuplicateEntryError: If an entry with same site and username exists.
        """
        fernet = self._require_unlocked()
        site_clean = site.strip()
        if not site_clean:
            raise ValueError("Site name is required.")

        self._check_duplicate(site_clean, username)

        username_enc = crypto.encrypt(fernet, username) if username else None
        password_enc = crypto.encrypt(fernet, password) or b""
        notes_enc = crypto.encrypt(fernet, notes) if notes else None

        now = _utc_now_iso()
        return self.db.create_entry(
            site=site_clean,
            url=url.strip() if url else None,
            category_id=category_id,
            username_enc=username_enc,
            password_enc=password_enc,
            notes_enc=notes_enc,
            favorite=1 if favorite else 0,
            created_at=now,
            updated_at=now,
        )

    def update_entry(
        self,
        entry_id: int,
        site: str,
        username: str = "",
        password: str = "",
        url: str = "",
        category_id: int | None = None,
        notes: str = "",
        favorite: bool = False,
    ) -> None:
        """Update an existing password entry.

        If the password has changed, archives the previous password into password_history.

        Args:
            entry_id: Target entry ID.
            site: Updated site name.
            username: Updated username.
            password: Updated password.
            url: Updated URL.
            category_id: Updated category ID.
            notes: Updated notes.
            favorite: Updated favorite flag.
        """
        fernet = self._require_unlocked()
        existing = self.db.get_entry(entry_id)
        if not existing:
            raise EntryNotFoundError(f"Entry with ID {entry_id} not found.")

        site_clean = site.strip()
        if not site_clean:
            raise ValueError("Site name is required.")

        self._check_duplicate(site_clean, username, exclude_id=entry_id)

        now = _utc_now_iso()

        # Check if password changed; if so, archive old password into password_history
        old_password = crypto.decrypt(fernet, existing["password_enc"]) or ""
        if password != old_password:
            self.db.create_history_entry(
                entry_id=entry_id,
                password_enc=existing["password_enc"],
                changed_at=now,
            )

        username_enc = crypto.encrypt(fernet, username) if username else None
        password_enc = crypto.encrypt(fernet, password) or b""
        notes_enc = crypto.encrypt(fernet, notes) if notes else None

        self.db.update_entry(
            entry_id=entry_id,
            site=site_clean,
            password_enc=password_enc,
            url=url.strip() if url else None,
            category_id=category_id,
            username_enc=username_enc,
            notes_enc=notes_enc,
            favorite=1 if favorite else 0,
            updated_at=now,
        )

    def delete_entry(self, entry_id: int) -> None:
        """Delete an entry and its associated password history via cascade."""
        self._require_unlocked()
        existing = self.db.get_entry(entry_id)
        if not existing:
            raise EntryNotFoundError(f"Entry with ID {entry_id} not found.")
        self.db.delete_entry(entry_id)

    def list_entries(
        self,
        search: str = "",
        category_id: int | None = None,
        favorites_only: bool = False,
    ) -> list[dict[str, Any]]:
        """List entries with decrypted usernames, applying optional filters.

        Does not return passwords or notes in memory.

        Args:
            search: Case-insensitive search query matching site, URL, or username.
            category_id: Optional category ID filter.
            favorites_only: If True, returns only favorite entries.

        Returns:
            List of entry dictionaries formatted for display.
        """
        fernet = self._require_unlocked()
        rows = self.db.list_entries(category_id=category_id, favorites_only=favorites_only)

        search_clean = search.strip().lower()
        results: list[dict[str, Any]] = []

        for row in rows:
            username = crypto.decrypt(fernet, row["username_enc"]) if row["username_enc"] else ""
            site = row["site"] or ""
            url = row["url"] or ""

            if search_clean:
                matches_site = search_clean in site.lower()
                matches_url = search_clean in url.lower()
                matches_user = search_clean in (username or "").lower()
                if not (matches_site or matches_url or matches_user):
                    continue

            results.append({
                "id": row["id"],
                "site": site,
                "url": url,
                "category_id": row["category_id"],
                "category_name": row["category_name"] or "None",
                "username": username,
                "favorite": bool(row["favorite"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_used_at": row["last_used_at"],
            })

        return results

    def get_secret(self, entry_id: int) -> dict[str, str]:
        """Fetch and decrypt the password and notes for a specific entry.

        Updates last_used_at timestamp.

        Args:
            entry_id: Target entry ID.

        Returns:
            Dict containing decrypted 'password' and 'notes'.
        """
        fernet = self._require_unlocked()
        row = self.db.get_entry(entry_id)
        if not row:
            raise EntryNotFoundError(f"Entry with ID {entry_id} not found.")

        password = crypto.decrypt(fernet, row["password_enc"]) or ""
        notes = crypto.decrypt(fernet, row["notes_enc"]) if row["notes_enc"] else ""

        now = _utc_now_iso()
        self.db.update_entry_last_used(entry_id, now)

        return {"password": password, "notes": notes}

    def get_entry_details(self, entry_id: int) -> dict[str, Any]:
        """Retrieve complete decrypted entry details for editing dialogs.

        Args:
            entry_id: Target entry ID.

        Returns:
            Dictionary with all entry fields decrypted.
        """
        fernet = self._require_unlocked()
        row = self.db.get_entry(entry_id)
        if not row:
            raise EntryNotFoundError(f"Entry with ID {entry_id} not found.")

        username = crypto.decrypt(fernet, row["username_enc"]) if row["username_enc"] else ""
        password = crypto.decrypt(fernet, row["password_enc"]) or ""
        notes = crypto.decrypt(fernet, row["notes_enc"]) if row["notes_enc"] else ""

        return {
            "id": row["id"],
            "site": row["site"],
            "url": row["url"] or "",
            "category_id": row["category_id"],
            "category_name": row["category_name"] or "",
            "username": username,
            "password": password,
            "notes": notes,
            "favorite": bool(row["favorite"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_used_at": row["last_used_at"],
        }

    def toggle_favorite(self, entry_id: int) -> bool:
        """Toggle favorite state of an entry and return the new boolean state."""
        self._require_unlocked()
        row = self.db.get_entry(entry_id)
        if not row:
            raise EntryNotFoundError(f"Entry with ID {entry_id} not found.")
        new_state = 0 if row["favorite"] else 1
        self.db.set_favorite(entry_id, new_state)
        return bool(new_state)

    def get_password_history(self, entry_id: int) -> list[dict[str, str]]:
        """Retrieve decrypted password history for an entry.

        Args:
            entry_id: Target entry ID.

        Returns:
            List of history records with decrypted password and changed_at.
        """
        fernet = self._require_unlocked()
        rows = self.db.get_history_entries(entry_id)
        history: list[dict[str, str]] = []
        for r in rows:
            pwd = crypto.decrypt(fernet, r["password_enc"]) or ""
            history.append({
                "password": pwd,
                "changed_at": r["changed_at"],
            })
        return history

    def find_duplicates(self) -> list[list[dict[str, Any]]]:
        """Find groups of entries that share identical site and username combinations."""
        fernet = self._require_unlocked()
        raw_entries = self.db.get_all_entries_raw()

        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in raw_entries:
            user = (crypto.decrypt(fernet, row["username_enc"]) or "").strip().lower()
            key = (row["site"].strip().lower(), user)
            groups.setdefault(key, []).append({
                "id": row["id"],
                "site": row["site"],
                "username": user,
                "url": row["url"],
            })

        return [group for group in groups.values() if len(group) > 1]

    # --- Categories CRUD ---

    def list_categories(self) -> list[dict[str, Any]]:
        """List all defined categories."""
        self._require_unlocked()
        rows = self.db.get_categories()
        return [{"id": r["id"], "name": r["name"]} for r in rows]

    def add_category(self, name: str) -> int:
        """Add a new category name.

        Args:
            name: Category name string.

        Returns:
            New category ID.
        """
        self._require_unlocked()
        clean = name.strip()
        if not clean:
            raise ValueError("Category name cannot be empty.")
        existing = self.db.get_category_by_name(clean)
        if existing:
            raise DuplicateCategoryError(f"Category '{clean}' already exists.")
        return self.db.create_category(clean)

    def update_category(self, category_id: int, name: str) -> None:
        """Update a category name."""
        self._require_unlocked()
        clean = name.strip()
        if not clean:
            raise ValueError("Category name cannot be empty.")
        existing = self.db.get_category_by_id(category_id)
        if not existing:
            raise CategoryNotFoundError(f"Category with ID {category_id} not found.")
        self.db.update_category(category_id, clean)

    def delete_category(self, category_id: int) -> None:
        """Delete a category (associated entries have their category set to NULL)."""
        self._require_unlocked()
        existing = self.db.get_category_by_id(category_id)
        if not existing:
            raise CategoryNotFoundError(f"Category with ID {category_id} not found.")
        self.db.delete_category(category_id)

    def get_or_create_category(self, name: str) -> int:
        """Get an existing category ID by name or create a new one."""
        self._require_unlocked()
        clean = name.strip()
        if not clean:
            raise ValueError("Category name cannot be empty.")
        existing = self.db.get_category_by_name(clean)
        if existing:
            return existing["id"]
        return self.db.create_category(clean)

    # --- Settings Operations ---

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Retrieve a string/int/bool setting from the meta table."""
        val = self.db.get_meta(key)
        if val is None:
            return default
        text = val.decode("utf-8")
        if isinstance(default, bool):
            return text in ("1", "true", "True")
        if isinstance(default, int):
            try:
                return int(text)
            except ValueError:
                return default
        return text

    def set_setting(self, key: str, value: Any) -> None:
        """Store a setting in the meta table."""
        if isinstance(value, bool):
            val_bytes = ("1" if value else "0").encode("utf-8")
        else:
            val_bytes = str(value).encode("utf-8")
        self.db.set_meta(key, val_bytes)

    # --- Master Password Re-encryption ---

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
        kdf_params: dict[str, Any] | None = None,
    ) -> None:
        """Change the master password by re-encrypting all entries in a single atomic transaction.

        Verifies the old password, creates an in-memory safety backup via SQLite backup API,
        derives the new key with a new salt, re-encrypts all entries and history rows, and
        updates metadata. If any error occurs, rolls back and restores from safety backup.

        Args:
            old_password: The current master password.
            new_password: The new master password (minimum 12 chars).
            kdf_params: Optional Scrypt parameters.
        """
        current_fernet = self._require_unlocked()

        if len(new_password) < MIN_MASTER_PASSWORD_LENGTH:
            raise WeakPasswordError(
                f"New master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters."
            )

        # 1. Verify old password against stored token
        stored_salt = self.db.get_meta("salt")
        stored_token = self.db.get_meta("verification_token")
        stored_kdf = self._get_stored_kdf_params()

        if not stored_salt or not stored_token:
            raise VaultNotFoundError("Metadata missing or corrupted.")

        verify_key = crypto.derive_fernet_key(old_password, stored_salt, stored_kdf)
        verify_fernet = crypto.get_fernet(verify_key)
        if not crypto.verify_token(verify_fernet, stored_token):
            raise InvalidMasterPasswordError("Current master password is incorrect.")

        # 2. Create in-memory safety copy using SQLite backup API
        safety_conn = sqlite3.connect(":memory:")
        self.db.backup_to(safety_conn)

        try:
            # 3. Derive new Fernet key with fresh salt
            new_salt = crypto.generate_salt(16)
            new_kdf = dict(kdf_params or stored_kdf)
            new_fernet_key = crypto.derive_fernet_key(new_password, new_salt, new_kdf)
            new_fernet = crypto.get_fernet(new_fernet_key)
            new_token = crypto.create_verification_token(new_fernet)

            # 4. Read and decrypt all existing data using current_fernet
            raw_entries = self.db.get_all_entries_raw()
            decrypted_entries = []
            for r in raw_entries:
                u = crypto.decrypt(current_fernet, r["username_enc"]) if r["username_enc"] else None
                p = crypto.decrypt(current_fernet, r["password_enc"]) or ""
                n = crypto.decrypt(current_fernet, r["notes_enc"]) if r["notes_enc"] else None
                decrypted_entries.append((r["id"], u, p, n))

            raw_history = self.db.get_all_history_raw()
            decrypted_history = []
            for h in raw_history:
                p = crypto.decrypt(current_fernet, h["password_enc"]) or ""
                decrypted_history.append((h["id"], p))

            # 5. In ONE atomic transaction, update metadata and all re-encrypted records
            with self.db.transaction() as conn:
                self.db.set_meta("salt", new_salt, conn=conn)
                self.db.set_meta("kdf_params", json.dumps(new_kdf).encode("utf-8"), conn=conn)
                self.db.set_meta("verification_token", new_token, conn=conn)

                for entry_id, u, p, n in decrypted_entries:
                    new_u = crypto.encrypt(new_fernet, u) if u else None
                    new_p = crypto.encrypt(new_fernet, p) or b""
                    new_n = crypto.encrypt(new_fernet, n) if n else None
                    conn.execute(
                        "UPDATE entries SET username_enc = ?, password_enc = ?, notes_enc = ? WHERE id = ?;",
                        (new_u, new_p, new_n, entry_id),
                    )

                for hist_id, p in decrypted_history:
                    new_hp = crypto.encrypt(new_fernet, p) or b""
                    conn.execute(
                        "UPDATE password_history SET password_enc = ? WHERE id = ?;",
                        (new_hp, hist_id),
                    )

            # Successful re-encryption: switch to new Fernet key
            self._fernet = new_fernet

        except Exception:
            # Restore from safety copy
            try:
                self.db.restore_from(safety_conn)
            except Exception:
                pass
            raise
        finally:
            safety_conn.close()

    # --- Backup, CSV & Portability ---

    def export_backup(
        self,
        backup_password: str,
        output_path: Path | str,
        kdf_params: dict[str, Any] | None = None,
    ) -> None:
        """Export all entries into an encrypted .vbak file."""
        fernet = self._require_unlocked()
        raw_entries = self.db.get_all_entries_raw()

        decrypted_list: list[dict[str, Any]] = []
        for r in raw_entries:
            decrypted_list.append({
                "site": r["site"],
                "url": r["url"] or "",
                "category": r["category_name"] or "",
                "username": crypto.decrypt(fernet, r["username_enc"]) if r["username_enc"] else "",
                "password": crypto.decrypt(fernet, r["password_enc"]) or "",
                "notes": crypto.decrypt(fernet, r["notes_enc"]) if r["notes_enc"] else "",
                "favorite": bool(r["favorite"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "last_used_at": r["last_used_at"],
            })

        backup.export_backup(decrypted_list, backup_password, output_path, kdf_params)

    def import_backup(self, backup_password: str, backup_path: Path | str) -> tuple[int, int]:
        """Restore entries from an encrypted .vbak file in a single transaction.

        Skips duplicate entries by (site, username).

        Args:
            backup_password: The password protecting the backup file.
            backup_path: Path to the .vbak file.

        Returns:
            Tuple of (imported_count, skipped_count).
        """
        fernet = self._require_unlocked()
        entries = backup.read_backup(backup_path, backup_password)

        raw_existing = self.db.get_all_entries_raw()
        existing_keys: set[tuple[str, str]] = set()
        for r in raw_existing:
            user = (crypto.decrypt(fernet, r["username_enc"]) or "").strip().lower()
            existing_keys.add((r["site"].strip().lower(), user))

        imported = 0
        skipped = 0
        now = _utc_now_iso()

        with self.db.transaction() as conn:
            for item in entries:
                site = item.get("site", "").strip()
                if not site:
                    skipped += 1
                    continue
                username = item.get("username", "")
                key = (site.lower(), username.strip().lower())
                if key in existing_keys:
                    skipped += 1
                    continue

                category_name = item.get("category", "") or item.get("category_name", "")
                cat_id = None
                if category_name:
                    cat_row = self.db.get_category_by_name(category_name, conn=conn)
                    if cat_row:
                        cat_id = cat_row["id"]
                    else:
                        cat_id = self.db.create_category(category_name.strip(), conn=conn)

                u_enc = crypto.encrypt(fernet, username) if username else None
                p_enc = crypto.encrypt(fernet, item.get("password", "")) or b""
                n_enc = crypto.encrypt(fernet, item.get("notes", "")) if item.get("notes") else None

                self.db.create_entry(
                    site=site,
                    url=item.get("url"),
                    category_id=cat_id,
                    username_enc=u_enc,
                    password_enc=p_enc,
                    notes_enc=n_enc,
                    favorite=1 if item.get("favorite") else 0,
                    created_at=item.get("created_at") or now,
                    updated_at=item.get("updated_at") or now,
                    last_used_at=item.get("last_used_at"),
                    conn=conn,
                )
                existing_keys.add(key)
                imported += 1

        return imported, skipped

    def import_csv(self, csv_path: Path | str) -> tuple[int, int]:
        """Import entries from a CSV file in a single transaction.

        Skips duplicate entries by (site, username).

        Args:
            csv_path: Path to the CSV file.

        Returns:
            Tuple of (imported_count, skipped_count).
        """
        fernet = self._require_unlocked()
        entries = backup.import_csv(csv_path)

        raw_existing = self.db.get_all_entries_raw()
        existing_keys: set[tuple[str, str]] = set()
        for r in raw_existing:
            user = (crypto.decrypt(fernet, r["username_enc"]) or "").strip().lower()
            existing_keys.add((r["site"].strip().lower(), user))

        imported = 0
        skipped = 0
        now = _utc_now_iso()

        with self.db.transaction() as conn:
            for item in entries:
                site = item.get("site", "").strip()
                if not site:
                    skipped += 1
                    continue
                username = item.get("username", "")
                key = (site.lower(), username.strip().lower())
                if key in existing_keys:
                    skipped += 1
                    continue

                category_name = item.get("category", "")
                cat_id = None
                if category_name:
                    cat_row = self.db.get_category_by_name(category_name, conn=conn)
                    if cat_row:
                        cat_id = cat_row["id"]
                    else:
                        cat_id = self.db.create_category(category_name.strip(), conn=conn)

                u_enc = crypto.encrypt(fernet, username) if username else None
                p_enc = crypto.encrypt(fernet, item.get("password", "")) or b""
                n_enc = crypto.encrypt(fernet, item.get("notes", "")) if item.get("notes") else None

                self.db.create_entry(
                    site=site,
                    url=item.get("url"),
                    category_id=cat_id,
                    username_enc=u_enc,
                    password_enc=p_enc,
                    notes_enc=n_enc,
                    favorite=1 if item.get("favorite") else 0,
                    created_at=now,
                    updated_at=now,
                    conn=conn,
                )
                existing_keys.add(key)
                imported += 1

        return imported, skipped

    def export_csv(self, output_path: Path | str) -> None:
        """Export all vault entries to an unencrypted CSV file.

        Args:
            output_path: Path to target CSV file.
        """
        fernet = self._require_unlocked()
        raw_entries = self.db.get_all_entries_raw()

        decrypted_list: list[dict[str, Any]] = []
        for r in raw_entries:
            decrypted_list.append({
                "site": r["site"],
                "url": r["url"] or "",
                "category": r["category_name"] or "",
                "username": crypto.decrypt(fernet, r["username_enc"]) if r["username_enc"] else "",
                "password": crypto.decrypt(fernet, r["password_enc"]) or "",
                "notes": crypto.decrypt(fernet, r["notes_enc"]) if r["notes_enc"] else "",
                "favorite": bool(r["favorite"]),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })

        backup.export_csv(decrypted_list, output_path)
