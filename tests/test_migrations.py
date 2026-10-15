"""Alembic migrations apply and revert cleanly (PRD §7.1)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def alembic_cfg(tmp_path: Path) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{tmp_path / 'migrations.db'}")
    return cfg


def _tables(db_path: Path) -> set[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return {row[0] for row in rows}


def _columns(db_path: Path, table: str) -> set[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in rows}


def test_upgrade_creates_schema(alembic_cfg: Config, tmp_path: Path):
    db_path = tmp_path / "migrations.db"
    command.upgrade(alembic_cfg, "head")

    tables = _tables(db_path)
    assert {"alembic_version", "analyses", "findings"} <= tables

    analysis_cols = _columns(db_path, "analyses")
    assert {
        "id",
        "analysis_type",
        "target_label",
        "status",
        "created_at",
        "completed_at",
        "summary",
        "provider_used",
        "ai_consent_given",
        "consent_recorded_at",
    } <= analysis_cols

    finding_cols = _columns(db_path, "findings")
    assert {
        "id",
        "analysis_id",
        "title",
        "category",
        "severity",
        "confidence",
        "evidence",
        "explanation",
        "recommendation",
        "source_type",
        "line_start",
        "line_end",
    } <= finding_cols


def test_downgrade_removes_schema(alembic_cfg: Config, tmp_path: Path):
    db_path = tmp_path / "migrations.db"
    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "base")
    assert "analyses" not in _tables(db_path)
    assert "findings" not in _tables(db_path)
