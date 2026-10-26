"""Pytest configuration and global fixtures for Password Vault tests."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Ensure global test data directory is isolated from user machine
_GLOBAL_TEST_DIR = tempfile.mkdtemp(prefix="pv_test_env_")
os.environ["PASSWORD_VAULT_DIR"] = _GLOBAL_TEST_DIR


@pytest.fixture(scope="session", autouse=True)
def cleanup_global_test_env() -> Generator[None, None, None]:
    """Tear down temporary test directory after test session completes."""
    yield
    try:
        shutil.rmtree(_GLOBAL_TEST_DIR, ignore_errors=True)
    except Exception:
        pass


@pytest.fixture
def fast_kdf() -> dict[str, int]:
    """Fast Scrypt parameters (n=2**12) for performant testing."""
    return {"n": 4096, "r": 8, "p": 1, "length": 32}


@pytest.fixture
def test_db_path(tmp_path: Path) -> Path:
    """Provide a path to a test database file inside tmp_path."""
    return tmp_path / "test_vault.db"
