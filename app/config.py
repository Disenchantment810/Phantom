"""Application configuration, loaded from environment variables and an optional .env file.

Secrets are never hard-coded: see .env.example and the README. In production an
explicit SECRET_KEY is required; in development an ephemeral key is generated so
the app still runs, with a warning that tokens reset on restart.
"""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

APP_NAME = "PHANTOM"
APP_VERSION = "0.1.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # development | production
    environment: str = "development"

    # Used to sign CSRF tokens. Must be set via ENVIRONMENT/SECRET_KEY in production.
    secret_key: str = ""

    # Local-first SQLite by default; keep the URL generic so PostgreSQL works later.
    database_url: str = "sqlite:///./phantom.db"

    # Hard cap for any single request body (forms, uploads) in bytes.
    max_body_bytes: int = 1_048_576

    # Per-upload cap used by the code/log workflows (Phases 2-3).
    upload_max_bytes: int = 524_288

    # Empty string = AI assistance disabled (PRD FR-11). When set, a hosted
    # provider adapter is offered behind an explicit consent gate (Phase 4).
    ai_provider: str = ""
    ai_model: str = ""
    # NAME of the environment variable that holds the API key. The key itself
    # is never read into settings or stored anywhere.
    ai_api_key_env: str = "AI_API_KEY"
    ai_base_url: str = "https://api.openai.com/v1"

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.secret_key:
        if settings.is_production:
            raise RuntimeError(
                "SECRET_KEY must be set via environment or .env when ENVIRONMENT=production."
            )
        settings.secret_key = secrets.token_urlsafe(48)
        logger.warning(
            "SECRET_KEY is not set; generated an ephemeral key. "
            "CSRF tokens will be invalidated on restart. Set SECRET_KEY in .env."
        )
    return settings
