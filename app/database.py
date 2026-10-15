"""Database engine, session management, and the declarative base.

Local-first SQLite by default (PRD §7.1). The engine is created lazily so tests
can install their own engine with set_engine() before anything touches the DB.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""


def utcnow() -> datetime:
    """Naive UTC timestamp, the canonical form for stored timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        # FastAPI TestClient may use multiple threads for one connection.
        return {"connect_args": {"check_same_thread": False}}
    return {}


def get_engine() -> Engine:
    global _engine, _session_factory
    if _engine is None:
        url = get_settings().database_url
        _engine = create_engine(url, **_engine_kwargs(url))
        _session_factory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def set_engine(engine: Engine) -> None:
    """Install a specific engine (used by the test suite)."""
    global _engine, _session_factory
    dispose_engine()
    _engine = engine
    _session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None


def get_db() -> Iterator[Session]:
    get_engine()
    assert _session_factory is not None
    db = _session_factory()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables from model metadata.

    Convenience for development and tests; Alembic migrations are the canonical
    way to create and evolve the schema (see migrations/).
    """
    from app import models  # noqa: F401  (imports register model metadata)

    Base.metadata.create_all(get_engine())
