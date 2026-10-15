"""Finding model (PRD §8): an individual result inside an Analysis.

Every finding keeps its evidence (FR-08) and states where it came from
(a deterministic rule or AI-assisted interpretation).
"""

from __future__ import annotations

import enum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.analysis import _enum


class Severity(str, enum.Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Confidence(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class FindingSource(str, enum.Enum):
    RULE = "rule"
    AI_ASSISTED = "ai_assisted"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general")
    severity: Mapped[Severity] = mapped_column(
        _enum(Severity, 16), nullable=False, default=Severity.INFORMATIONAL
    )
    confidence: Mapped[Confidence] = mapped_column(
        _enum(Confidence, 16), nullable=False, default=Confidence.LOW
    )

    # Observed excerpt or value that supports the finding (FR-08).
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    source_type: Mapped[FindingSource] = mapped_column(
        _enum(FindingSource, 16), nullable=False, default=FindingSource.RULE
    )

    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    analysis: Mapped["Analysis"] = relationship(back_populates="findings")  # noqa: F821
