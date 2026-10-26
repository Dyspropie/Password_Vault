"""Entry point for the Password Vault desktop application."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure root package directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ui.app import VaultApp


def main() -> None:
    """Launch the Password Vault application."""
    app = VaultApp()
    app.run()


if __name__ == "__main__":
    main()
