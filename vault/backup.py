"""Encrypted backup (.vbak) and CSV import/export functions."""

from __future__ import annotations

import base64
import csv
import json
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import InvalidToken

from vault import crypto
from vault.config import DEFAULT_KDF_PARAMS
from vault.errors import BackupError


def export_backup(
    entries: list[dict],
    backup_password: str,
    output_path: Path | str,
    kdf_params: dict | None = None,
) -> None:
    """Export entries into an encrypted .vbak file.

    Derives a fresh key from the backup_password and a new salt using Scrypt,
    then encrypts the JSON payload with Fernet.

    Args:
        entries: Decrypted entry dictionaries.
        backup_password: Password chosen to secure the backup file.
        output_path: Destination path for the .vbak file.
        kdf_params: Optional Scrypt parameters.

    Raises:
        BackupError: If file writing or encryption fails.
    """
    try:
        salt = crypto.generate_salt(16)
        active_kdf = dict(kdf_params or DEFAULT_KDF_PARAMS)
        fernet_key = crypto.derive_fernet_key(backup_password, salt, active_kdf)
        fernet = crypto.get_fernet(fernet_key)

        payload_bytes = json.dumps(entries, ensure_ascii=False).encode("utf-8")
        encrypted_token = fernet.encrypt(payload_bytes)

        envelope = {
            "version": 1,
            "kdf": active_kdf,
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": encrypted_token.decode("ascii"),
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
    except Exception as e:
        raise BackupError(f"Failed to export backup: {e}") from e


def read_backup(backup_path: Path | str, backup_password: str) -> list[dict]:
    """Read and decrypt an encrypted .vbak file.

    Args:
        backup_path: Path to the .vbak file.
        backup_password: Password used when the backup was created.

    Returns:
        List of decrypted entry dictionaries.

    Raises:
        BackupError: If password is wrong or file is corrupt/invalid.
    """
    path = Path(backup_path)
    if not path.is_file():
        raise BackupError(f"Backup file does not exist: {backup_path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except Exception as e:
        raise BackupError(f"Corrupt backup file: could not parse JSON: {e}") from e

    if not isinstance(envelope, dict) or not all(k in envelope for k in ("version", "salt", "data")):
        raise BackupError("Corrupt backup file: missing required envelope fields.")

    try:
        salt = base64.b64decode(envelope["salt"])
    except Exception as e:
        raise BackupError("Corrupt backup file: invalid salt encoding.") from e

    kdf = envelope.get("kdf", DEFAULT_KDF_PARAMS)
    data_token = envelope["data"].encode("ascii")

    try:
        fernet_key = crypto.derive_fernet_key(backup_password, salt, kdf)
        fernet = crypto.get_fernet(fernet_key)
        decrypted_bytes = fernet.decrypt(data_token)
    except InvalidToken as e:
        raise BackupError("Incorrect backup password or corrupted backup file.") from e
    except Exception as e:
        raise BackupError(f"Failed to decrypt backup: {e}") from e

    try:
        entries = json.loads(decrypted_bytes.decode("utf-8"))
        if not isinstance(entries, list):
            raise BackupError("Corrupt backup file: data is not an entries list.")
        return entries
    except Exception as e:
        raise BackupError(f"Failed to parse decrypted entries: {e}") from e


def export_csv(entries: list[dict], output_path: Path | str) -> None:
    """Export entries to a plaintext CSV file.

    Args:
        entries: Decrypted entry dictionaries.
        output_path: Destination path for the CSV.

    Raises:
        BackupError: If CSV writing fails.
    """
    fieldnames = [
        "site",
        "url",
        "username",
        "password",
        "notes",
        "category",
        "favorite",
        "created_at",
        "updated_at",
    ]
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for entry in entries:
                row = {
                    "site": entry.get("site", ""),
                    "url": entry.get("url", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "notes": entry.get("notes", ""),
                    "category": entry.get("category", "") or entry.get("category_name", ""),
                    "favorite": 1 if entry.get("favorite") else 0,
                    "created_at": entry.get("created_at", ""),
                    "updated_at": entry.get("updated_at", ""),
                }
                writer.writerow(row)
    except Exception as e:
        raise BackupError(f"Failed to export CSV: {e}") from e


def import_csv(csv_path: Path | str) -> list[dict]:
    """Parse and normalize entries from a CSV file.

    Auto-detects Chrome and Firefox password export formats as well as generic CSV.

    Args:
        csv_path: Path to the CSV file to import.

    Returns:
        List of normalized entry dictionaries.

    Raises:
        BackupError: If file is empty or cannot be parsed.
    """
    path = Path(csv_path)
    if not path.is_file():
        raise BackupError(f"CSV file does not exist: {csv_path}")

    try:
        # Support utf-8-sig to automatically handle BOM
        with open(path, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header_row = next(reader, None)
            if not header_row:
                raise BackupError("CSV file is empty.")

            # Map normalized lower-case column headers to their index
            col_map: dict[str, int] = {}
            for idx, col in enumerate(header_row):
                clean_col = col.strip().lower()
                if clean_col not in col_map:
                    col_map[clean_col] = idx

            # Determine column positions
            # Site / Name
            site_idx = (
                col_map.get("site")
                if "site" in col_map
                else col_map.get("name")
                if "name" in col_map
                else col_map.get("title")
            )

            # URL
            url_idx = col_map.get("url")

            # Username
            user_idx = (
                col_map.get("username")
                if "username" in col_map
                else col_map.get("user")
                if "user" in col_map
                else col_map.get("login")
            )

            # Password
            pwd_idx = (
                col_map.get("password")
                if "password" in col_map
                else col_map.get("pass")
            )

            # Notes
            note_idx = (
                col_map.get("notes")
                if "notes" in col_map
                else col_map.get("note")
            )

            # Category
            cat_idx = (
                col_map.get("category")
                if "category" in col_map
                else col_map.get("folder")
            )

            if pwd_idx is None and url_idx is None and user_idx is None:
                raise BackupError("Could not recognize valid password export columns in CSV header.")

            entries: list[dict] = []
            for row in reader:
                if not row or all(not cell.strip() for cell in row):
                    continue

                def get_cell(idx: int | None) -> str:
                    if idx is not None and 0 <= idx < len(row):
                        return row[idx].strip()
                    return ""

                raw_site = get_cell(site_idx)
                raw_url = get_cell(url_idx)
                username = get_cell(user_idx)
                password = get_cell(pwd_idx)
                notes = get_cell(note_idx)
                category = get_cell(cat_idx)

                # If site is missing, derive domain name from url
                site = raw_site
                if not site and raw_url:
                    parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
                    site = parsed.netloc or parsed.path

                if not site:
                    site = "Unknown Site"

                entries.append({
                    "site": site,
                    "url": raw_url,
                    "username": username,
                    "password": password,
                    "notes": notes,
                    "category": category,
                    "favorite": False,
                })

            return entries
    except BackupError:
        raise
    except Exception as e:
        raise BackupError(f"Failed to read CSV: {e}") from e
