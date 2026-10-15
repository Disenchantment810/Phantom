"""Analysis model (PRD §8): one row per user-run analysis.

Privacy note: target_label holds a short human label (URL or file name), never
the full raw input. Raw source code and logs are not persisted by default.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, utcnow


class AnalysisType(str, enum.Enum):
    WEBSITE_CHECK = "website_check"
    CODE_REVIEW = "code_review"
    LOG_ANALYSIS = "log_analysis"


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


def _enum(enum_cls: type[enum.Enum], length: int) -> Enum:
    """Non-native enum: a plain VARCHAR + CHECK constraint, portable across DBs."""
    return Enum(
        enum_cls,
        native_enum=False,
        length=length,
        validate_strings=True,
        values_callable=lambda e: [member.value for member in e],
    )


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_type: Mapped[AnalysisType] = mapped_column(_enum(AnalysisType, 32), nullable=False)
    target_label: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(
        _enum(AnalysisStatus, 32), nullable=False, default=AnalysisStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # AI metadata (populated in Phase 4). provider_used names the provider only,
    # never credentials (FR-13).
    provider_used: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ai_consent_given: Mapped[bool] = mapped_column(nullable=False, default=False)
    consent_recorded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="analysis", cascade="all, delete-orphan"
    )
