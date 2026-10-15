"""Configuration guards (SECRET_KEY policy) and engine lifecycle."""

from __future__ import annotations

import pytest

from app.config import Settings, get_settings


@pytest.fixture()
def fresh_settings(monkeypatch):
    """Yield a callable that rebuilds get_settings() with the given env."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)

    def rebuild(**env):
        for key, value in env.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        get_settings.cache_clear()
        return get_settings()

    yield rebuild
    get_settings.cache_clear()


def test_production_without_secret_key_is_rejected(fresh_settings):
    with pytest.raises(RuntimeError, match="SECRET_KEY must be set"):
        fresh_settings(ENVIRONMENT="production", SECRET_KEY=None)


def test_production_with_secret_key_is_accepted(fresh_settings):
    settings = fresh_settings(ENVIRONMENT="production", SECRET_KEY="a" * 48)
    assert settings.is_production is True
    assert settings.secret_key == "a" * 48


def test_development_without_key_generates_ephemeral(fresh_settings):
    settings = fresh_settings(ENVIRONMENT="development", SECRET_KEY=None)
    assert settings.secret_key  # generated
    assert len(settings.secret_key) >= 32


def test_ephemeral_keys_differ_per_rebuild(fresh_settings):
    first = fresh_settings(ENVIRONMENT="development", SECRET_KEY=None).secret_key
    get_settings.cache_clear()
    second = fresh_settings(ENVIRONMENT="development", SECRET_KEY=None).secret_key
    assert first != second


def test_is_production_is_case_insensitive():
    assert Settings(environment="PRODUCTION", secret_key="x" * 8).is_production


def test_engine_dispose_and_reset_roundtrip(tmp_path):
    from sqlalchemy import create_engine

    from app.database import dispose_engine, get_engine, get_db, set_engine

    first = create_engine(f"sqlite:///{tmp_path / 'a.db'}")
    set_engine(first)
    assert get_engine() is first
    dispose_engine()

    second = create_engine(f"sqlite:///{tmp_path / 'b.db'}")
    set_engine(second)  # set_engine disposes any prior engine first
    assert get_engine() is second
    dispose_engine()
    assert get_engine() is not second  # lazily rebuilt from settings


def test_get_db_closes_session(tmp_path):
    """get_db's finally block must close the session it yielded."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.database import dispose_engine, get_db, set_engine

    engine = create_engine(f"sqlite:///{tmp_path / 'c.db'}")
    set_engine(engine)

    gen = get_db()
    session = next(gen)
    assert isinstance(session, Session)

    close_calls = []
    original_close = session.close

    def spy_close():
        close_calls.append(True)
        original_close()

    session.close = spy_close  # type: ignore[method-assign]

    with pytest.raises(StopIteration):
        gen.send(None)  # exhaust the generator -> finally: db.close()

    assert close_calls == [True]
    dispose_engine()
