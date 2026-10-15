"""Persistence for analyses and findings (PRD FR-09, FR-10, §8).

Privacy default (PRD §8, confirmed): raw source code and raw log text are NOT
stored. What is kept per analysis:
- type, a short target label (URL host/path or file name), status, summary
- the findings list, whose evidence fields are short, masked excerpts already
- AI consent metadata (that consent was given, which provider was used)
"""

from __future__ import annotations

import logging
from typing import Iterable

from sqlalchemy.orm import Session

from app.database import utcnow
from app.models import (
    Analysis,
    AnalysisStatus,
    AnalysisType,
    Finding,
    FindingSource,
)
from app.services.ai_assist import AIAssistOutcome
from app.services.ai_provider import AIFinding

logger = logging.getLogger(__name__)


def _model_findings(findings: Iterable) -> list[Finding]:
    model_findings: list[Finding] = []
    for f in findings:
        if isinstance(f, AIFinding):
            model_findings.append(
                Finding(
                    title=f.title,
                    category="ai-assisted",
                    severity=f.severity,
                    confidence=f.confidence,
                    evidence=f.evidence,
                    explanation=f.explanation,
                    recommendation=f.recommendation,
                    source_type=FindingSource.AI_ASSISTED,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    rule_id=None,
                )
            )
            continue
        model_findings.append(
            Finding(
                title=f.title,
                category=getattr(f, "category", "general") or "general",
                severity=f.severity,
                confidence=f.confidence,
                evidence=f.evidence,
                explanation=getattr(f, "explanation", None),
                recommendation=getattr(f, "recommendation", None),
                source_type=getattr(f, "source_type", FindingSource.RULE),
                line_start=getattr(f, "line_start", None),
                line_end=getattr(f, "line_end", None),
                rule_id=getattr(f, "rule_id", None) or None,
            )
        )
    return model_findings


def persist_analysis(
    db: Session,
    *,
    analysis_type: AnalysisType,
    target_label: str,
    summary: str,
    findings: Iterable,
    ai_outcome: AIAssistOutcome | None = None,
) -> Analysis | None:
    """Save one completed analysis. Returns the row, or None on DB failure
    (persistence must never break the user's check)."""
    ai_outcome = ai_outcome or AIAssistOutcome()
    model_findings = _model_findings(findings)
    if ai_outcome.ai_analysis is not None:
        model_findings += _model_findings(ai_outcome.ai_analysis.findings)
    analysis = Analysis(
        analysis_type=analysis_type,
        target_label=target_label[:512],
        status=AnalysisStatus.COMPLETED,
        completed_at=utcnow(),
        summary=summary[:2000] or None,
        ai_consent_given=bool(ai_outcome.consent_recorded),
        consent_recorded_at=utcnow() if ai_outcome.consent_recorded else None,
        provider_used=(
            ai_outcome.ai_analysis.provider_name if ai_outcome.ai_analysis else None
        ),
    )
    analysis.findings = model_findings
    try:
        db.add(analysis)
        db.commit()
        db.refresh(analysis)
        return analysis
    except Exception:
        logger.exception("Failed to persist analysis")
        db.rollback()
        return None


def get_analysis(db: Session, analysis_id: int) -> Analysis | None:
    return db.get(Analysis, analysis_id)


def list_analyses(db: Session, limit: int | None = None) -> list[Analysis]:
    query = db.query(Analysis).order_by(Analysis.created_at.desc())
    if limit:
        query = query.limit(limit)
    return list(query.all())


def delete_analysis(db: Session, analysis_id: int) -> bool:
    """Delete an analysis and (via cascade) its findings. True if it existed."""
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        return False
    try:
        db.delete(analysis)
        db.commit()
        return True
    except Exception:
        logger.exception("Failed to delete analysis %s", analysis_id)
        db.rollback()
        return False
