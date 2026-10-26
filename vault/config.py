"""Configuration, paths, constants, and environment overrides for Password Vault."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Verification token encrypted and stored in metadata to verify master password
VERIFICATION_TOKEN: bytes = b"VAULT_VERIFICATION_TOKEN_V1"

# Minimum length for master passwords
MIN_MASTER_PASSWORD_LENGTH: int = 12

# Default Scrypt key derivation function parameters (RFC 7914 compliant)
# n = 2**15 (32768), r = 8, p = 1, key_length = 32
DEFAULT_KDF_PARAMS: dict[str, int] = {
    "n": 32768,
    "r": 8,
    "p": 1,
    "length": 32,
}

# Fast KDF params for test suites (n = 2**12 = 4096)
FAST_KDF_PARAMS: dict[str, int] = {
    "n": 4096,
    "r": 8,
    "p": 1,
    "length": 32,
}

# Application setting defaults
DEFAULT_AUTOLOCK_MINUTES: int = 5
DEFAULT_CLIPBOARD_CLEAR_SECONDS: int = 15
DEFAULT_LOCK_ON_MINIMIZE: bool = False

# Database file name
DB_FILE_NAME: str = "vault.db"


def get_data_dir() -> Path:
    """Resolve and return the application data directory.

    Order of precedence:
    1. PASSWORD_VAULT_DIR environment variable (used by tests & custom setups)
    2. Windows: %APPDATA%/PasswordVault
    3. macOS: ~/Library/Application Support/PasswordVault
    4. Linux: $XDG_DATA_HOME/PasswordVault or ~/.local/share/PasswordVault

    The directory is automatically created if it does not exist.
    """
    env_dir = os.environ.get("PASSWORD_VAULT_DIR")
    if env_dir:
        path = Path(env_dir).expanduser().resolve()
    elif sys.platform == "win32":
        app_data = os.environ.get("APPDATA")
        if app_data:
            path = Path(app_data) / "PasswordVault"
        else:
            path = Path.home() / "AppData" / "Roaming" / "PasswordVault"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "PasswordVault"
    else:
        # Linux / Unix
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            path = Path(xdg_data) / "PasswordVault"
        else:
            path = Path.home() / ".local" / "share" / "PasswordVault"

    path.mkdir(parents=True, exist_ok=True)
    return path


def get_default_db_path() -> Path:
    """Return the default database path inside the application data directory."""
    return get_data_dir() / DB_FILE_NAME
