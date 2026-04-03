"""Shared fixtures for Familiar tests."""

import tempfile
from pathlib import Path

import pytest

from familiar.memory import Memory


@pytest.fixture()
def memory(tmp_path):
    """Return a Memory instance backed by a temporary SQLite database."""
    db_path = tmp_path / "test_familiar.db"
    mem = Memory(db_path=db_path)
    yield mem
    mem.close()
