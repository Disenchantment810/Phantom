"""Persistence, history, detail, delete, and report export (PRD FR-09, FR-10)."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import create_engine
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
from app.services.persistence import (
    delete_analysis,
    get_analysis,
    list_analyses,
    persist_analysis,
)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'p5.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


class _FakeFinding:
    """Mimics the service-level finding objects."""

    def __init__(self, title="T", severity=Severity.LOW, rule_id=None, evidence="ev"):
        self.title = title
        self.category = "test"
        self.severity = severity
        self.confidence = Confidence.MEDIUM
        self.evidence = evidence
        self.explanation = "explanation"
        self.recommendation = "recommendation"
        self.source_type = FindingSource.RULE
        self.line_start = 1
        self.line_end = 2
        self.rule_id = rule_id


class TestPersistence:
    def test_persist_and_fetch_roundtrip(self, db: Session):
        analysis = persist_analysis(
            db,
            analysis_type=AnalysisType.LOG_ANALYSIS,
            target_label="pasted log",
            summary="6/6 lines parsed, 6 failed.",
            findings=[_FakeFinding(title="Burst", rule_id="LOG-BRUTE-001")],
        )
        assert analysis is not None
        fetched = get_analysis(db, analysis.id)
        assert fetched is not None
        assert fetched.analysis_type is AnalysisType.LOG_ANALYSIS
        assert fetched.status is AnalysisStatus.COMPLETED
        assert fetched.completed_at is not None
        finding = fetched.findings[0]
        assert finding.rule_id == "LOG-BRUTE-001"
        assert finding.evidence == "ev"

    def test_ai_metadata_persisted(self, db: Session):
        from app.services.ai_assist import AIAssistOutcome
        from app.services.ai_provider import AIAnalysis, AIFinding

        outcome = AIAssistOutcome(
            ai_analysis=AIAnalysis(
                findings=[
                    AIFinding(
                        title="AI note",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        evidence="e",
                        explanation="x",
                        recommendation="r",
                    )
                ],
                provider_name="prov",
                model="m",
                raw_response_chars=100,
            ),
            consent_recorded=True,
            disclosure="d",
        )
        analysis = persist_analysis(
            db,
            analysis_type=AnalysisType.CODE_REVIEW,
            target_label="snippet",
            summary="s",
            findings=[_FakeFinding()],
            ai_outcome=outcome,
        )
        assert analysis.ai_consent_given is True
        assert analysis.consent_recorded_at is not None
        assert analysis.provider_used == "prov"
        ai_finding = next(f for f in analysis.findings if f.source_type == FindingSource.AI_ASSISTED)
        assert ai_finding.title == "AI note"

    def test_no_consent_leaves_ai_fields_clear(self, db: Session):
        analysis = persist_analysis(
            db,
            analysis_type=AnalysisType.CODE_REVIEW,
            target_label="s",
            summary="s",
            findings=[],
        )
        assert analysis.ai_consent_given is False
        assert analysis.provider_used is None

    def test_db_failure_returns_none_not_crash(self, db: Session, monkeypatch):
        import sqlalchemy.orm

        def broken_commit(self):
            raise RuntimeError("db gone")

        monkeypatch.setattr(Session, "commit", broken_commit)
        result = persist_analysis(
            db,
            analysis_type=AnalysisType.CODE_REVIEW,
            target_label="s",
            summary="s",
            findings=[_FakeFinding()],
        )
        assert result is None

    def test_delete_removes_findings(self, db: Session):
        analysis = persist_analysis(
            db,
            analysis_type=AnalysisType.CODE_REVIEW,
            target_label="s",
            summary="s",
            findings=[_FakeFinding()],
        )
        assert analysis.findings
        assert delete_analysis(db, analysis.id) is True
        assert get_analysis(db, analysis.id) is None
        assert db.query(Finding).count() == 0

    def test_delete_missing_returns_false(self, db: Session):
        assert delete_analysis(db, 9999) is False

    def test_list_orders_newest_first(self, db: Session):
        persist_analysis(db, analysis_type=AnalysisType.CODE_REVIEW, target_label="first", summary="", findings=[])
        persist_analysis(db, analysis_type=AnalysisType.CODE_REVIEW, target_label="second", summary="", findings=[])
        labels = [a.target_label for a in list_analyses(db)]
        assert labels == ["second", "first"]


class TestWorkflowPersistence:
    def test_website_check_is_saved(self, app_client):
        from app.services.website_checker import WebsiteCheckResult, CheckFinding
        from datetime import datetime

        sample = WebsiteCheckResult(
            requested_url="https://example.com/",
            final_url="https://example.com/",
            status_code=200,
            redirect_chain=["https://example.com/"],
            https_used=True,
            checked_at=datetime(2026, 10, 15, 12, 0, 0),
            findings=[
                CheckFinding(
                    rule_id="WEB-TRANSPORT-003",
                    title="Checked over HTTPS",
                    category="transport",
                    severity=Severity.INFORMATIONAL,
                    evidence="reached over HTTPS",
                    explanation="encrypted",
                    recommendation="no change",
                )
            ],
        )

        def fake_check(raw_url):
            return sample

        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        response = app_client.post(
            "/website-check",
            data={"url": "example.com", "csrf_token": token},
        )
        assert response.status_code == 200

        history_page = app_client.get("/history")
        assert "https://example.com" in history_page.text
        assert "Website Check" in history_page.text

        detail_link = re.search(r'href="[^"]*?/analyses/(\d+)"', history_page.text)
        assert detail_link, "history should link to the detail page"

    def test_log_analysis_is_saved_via_upload(self, app_client):
        log = "\n".join(
            [f"Oct 15 12:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" for i in range(1, 7)]
        )
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        response = app_client.post(
            "/log-analysis/upload",
            data={"csrf_token": token},
            files={"file": ("sample.log", log.encode(), "text/plain")},
        )
        assert response.status_code == 200
        history_page = app_client.get("/history")
        assert "sample.log" in history_page.text
        assert "Log Analysis" in history_page.text

    def test_code_review_is_saved(self, app_client):
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        response = app_client.post(
            "/code-review",
            data={"code": "eval(1)\n", "language": "python", "csrf_token": token},
        )
        assert response.status_code == 200
        history_page = app_client.get("/history")
        assert "pasted snippet" in history_page.text


class TestDetailAndDelete:
    @pytest.fixture()
    def saved(self, app_client):
        """Persist one analysis through the log workflow and return its id."""
        log = "\n".join(
            [f"Oct 15 12:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" for i in range(1, 7)]
        )
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        app_client.post(
            "/log-analysis/upload",
            data={"csrf_token": token},
            files={"file": ("sample.log", log.encode(), "text/plain")},
        )
        history_page = app_client.get("/history")
        return int(re.search(r'href="[^"]*?/analyses/(\d+)"', history_page.text).group(1))

    def test_detail_renders_findings(self, app_client, saved):
        response = app_client.get(f"/analyses/{saved}")
        assert response.status_code == 200
        body = response.text
        assert "Repeated failed logins from one address" in body
        assert "LOG-BRUTE-001" in body
        assert "advisory" in body.lower()
        assert "Download report" in body

    def test_detail_404_for_missing(self, app_client):
        response = app_client.get("/analyses/9999")
        assert response.status_code == 404

    def test_delete_requires_csrf(self, app_client, saved):
        response = app_client.post(f"/analyses/{saved}/delete")
        assert response.status_code == 403
        assert app_client.get(f"/analyses/{saved}").status_code == 200  # still there

    def test_delete_redirects_and_removes(self, app_client, saved):
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        response = app_client.post(
            f"/analyses/{saved}/delete",
            data={"csrf_token": token},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/history"
        assert app_client.get(f"/analyses/{saved}").status_code == 404
        assert f"/analyses/{saved}" not in app_client.get("/history").text

    def test_delete_missing_404(self, app_client):
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        response = app_client.post("/analyses/9999/delete", data={"csrf_token": token})
        assert response.status_code == 404


class TestReportExport:
    @pytest.fixture()
    def saved(self, app_client):
        log = "\n".join(
            [f"Oct 15 12:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" for i in range(1, 7)]
        ) + "\nOct 15 12:00:30 srv nginx: Authorization: Bearer sk-live-abcdef123456 blocked\n"
        app_client.get("/")
        token = app_client.cookies.get("phantom_csrf")
        app_client.post(
            "/log-analysis/upload",
            data={"csrf_token": token},
            files={"file": ("sample.log", log.encode(), "text/plain")},
        )
        history_page = app_client.get("/history")
        return int(re.search(r'href="[^"]*?/analyses/(\d+)"', history_page.text).group(1))

    def test_report_downloads_as_attachment(self, app_client, saved):
        response = app_client.get(f"/analyses/{saved}/report")
        assert response.status_code == 200
        assert "attachment" in response.headers["content-disposition"]
        assert re.search(
            r'filename="phantom-report-[\d-]+\.html"',
            response.headers["content-disposition"],
        )

    def test_report_contains_required_sections(self, app_client, saved):
        report = app_client.get(f"/analyses/{saved}/report").text
        assert "Advisory notice" in report
        assert "human verification" in report.lower()
        assert "Scope" in report
        assert "Limitations" in report
        assert "Findings" in report
        assert "Repeated failed logins from one address" in report
        assert "LOG-BRUTE-001" in report
        assert "not proof of compromise" in report

    def test_report_masks_secrets(self, app_client, saved):
        report = app_client.get(f"/analyses/{saved}/report").text
        assert "sk-live-abcdef123456" not in report
        assert "[REDACTED]" in report

    def test_report_is_self_contained(self, app_client, saved):
        report = app_client.get(f"/analyses/{saved}/report").text
        assert "<style>" in report  # inline styles: standalone document
        assert "http://" not in report.replace("http://www.w3.org", "")
        assert "https://" not in report or "https://" not in re.sub(r'<[^>]*>', '', report)

    def test_report_404_for_missing(self, app_client):
        assert app_client.get("/analyses/9999/report").status_code == 404
