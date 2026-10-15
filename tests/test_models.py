"""Model behaviour: PRD §8 data model, defaults, enum integrity, cascades."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from app.database import Base
from app.models import (
    Analysis,
    AnalysisStatus,
    AnalysisType,
    Confidence,
    Finding,
    FindingSource,
    Severity,
)


@pytest.fixture()
def db(tmp_path: Path) -> Session:
    engine = create_engine(
        f"sqlite:///{tmp_path / 'models.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def _sample_analysis() -> Analysis:
    return Analysis(analysis_type=AnalysisType.WEBSITE_CHECK, target_label="https://example.com")


def test_analysis_defaults(db: Session):
    analysis = _sample_analysis()
    db.add(analysis)
    db.commit()

    assert analysis.id is not None
    assert analysis.status is AnalysisStatus.PENDING
    assert analysis.created_at is not None
    assert analysis.completed_at is None
    assert analysis.ai_consent_given is False
    assert analysis.provider_used is None


def test_finding_roundtrip_with_evidence(db: Session):
    analysis = _sample_analysis()
    analysis.findings.append(
        Finding(
            title="Missing Content-Security-Policy",
            category="headers",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence="No Content-Security-Policy header was observed in the response.",
            recommendation="Add a Content-Security-Policy header.",
            source_type=FindingSource.RULE,
        )
    )
    db.add(analysis)
    db.commit()

    stored = db.query(Analysis).one()
    finding = stored.findings[0]
    assert finding.analysis_id == stored.id
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH
    assert finding.source_type is FindingSource.RULE
    assert "Content-Security-Policy" in finding.evidence  # FR-08
    assert finding.line_start is None


def test_severity_ordering_values(db: Session):
    assert [s.value for s in Severity] == [
        "Informational",
        "Low",
        "Medium",
        "High",
        "Critical",
    ]


def test_invalid_enum_value_is_rejected(db: Session):
    analysis = _sample_analysis()
    db.add(analysis)
    db.flush()
    finding = Finding(
        analysis_id=analysis.id,
        title="bad severity",
        evidence="e",
        severity="bogus",  # type: ignore[arg-type]
    )
    db.add(finding)
    with pytest.raises(StatementError, match="not among the defined enum values"):
        db.flush()


def test_deleting_analysis_deletes_findings(db: Session):
    analysis = _sample_analysis()
    analysis.findings.append(
        Finding(title="t", evidence="e", severity=Severity.LOW, confidence=Confidence.LOW)
    )
    db.add(analysis)
    db.commit()

    assert db.query(Finding).count() == 1
    db.delete(analysis)
    db.commit()
    assert db.query(Finding).count() == 0


def test_consent_metadata_roundtrip(db: Session):
    from app.database import utcnow

    analysis = _sample_analysis()
    analysis.ai_consent_given = True
    analysis.consent_recorded_at = utcnow()
    analysis.provider_used = "example-hosted-provider"
    db.add(analysis)
    db.commit()

    stored = db.query(Analysis).one()
    assert stored.ai_consent_given is True
    assert stored.consent_recorded_at is not None
    assert stored.provider_used == "example-hosted-provider"
