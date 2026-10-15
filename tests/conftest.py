"""Shared fixtures: isolated database and app client per test."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Configure the environment BEFORE importing the app (settings are cached).
_TMP = Path(tempfile.mkdtemp(prefix="phantom-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP / 'default.db'}"
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("AI_PROVIDER", "")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402

from app.database import Base, dispose_engine, get_engine, set_engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture()
def app_client():
    """App + TestClient against a fresh per-test SQLite database."""
    dispose_engine()
    test_db = Path(tempfile.mkdtemp(prefix="phantom-app-")) / "test.db"
    engine = create_engine(
        f"sqlite:///{test_db}", connect_args={"check_same_thread": False}
    )
    set_engine(engine)
    Base.metadata.create_all(engine)
    app = create_app()
    with TestClient(app) as client:
        yield client
    dispose_engine()
