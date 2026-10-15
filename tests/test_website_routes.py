"""Website-check route: CSRF, safe error states, and rendered results."""

from __future__ import annotations

import httpx
import pytest

from app.services.input_safety import SafeInputError
from app.services.website_checker import CheckFinding, WebsiteCheckResult
from app.models import Confidence, FindingSource, Severity

TARGET = "https://example.com/"


def _csrf_post(client, url, data):
    client.get("/")  # obtain the CSRF cookie
    token = client.cookies.get("phantom_csrf")
    data = dict(data)
    data["csrf_token"] = token
    return client.post(url, data=data)


def _sample_result() -> WebsiteCheckResult:
    return WebsiteCheckResult(
        requested_url=TARGET,
        final_url=TARGET,
        status_code=200,
        redirect_chain=[TARGET],
        https_used=True,
        checked_at=__import__("datetime").datetime(2026, 10, 15, 12, 0, 0),
        findings=[
            CheckFinding(
                title="No Content-Security-Policy header",
                category="headers",
                severity=Severity.MEDIUM,
                evidence="No Content-Security-Policy header was observed in the response.",
                explanation="CSP is a strong defence against cross-site scripting.",
                recommendation="Serve a Content-Security-Policy starting with default-src 'self'.",
            ),
            CheckFinding(
                title="Checked over HTTPS",
                category="transport",
                severity=Severity.INFORMATIONAL,
                evidence=f"{TARGET} was reached directly over HTTPS (HTTP 200).",
                explanation="The connection was encrypted.",
                recommendation="No change needed for this control.",
            ),
        ],
        elapsed_ms=42,
    )


def test_form_renders_with_csrf_token(app_client):
    response = app_client.get("/website-check")
    assert response.status_code == 200
    assert 'name="csrf_token"' in response.text
    assert "Authorization notice" in response.text


def test_post_without_csrf_is_rejected(app_client):
    response = app_client.post("/website-check", data={"url": TARGET})
    assert response.status_code == 403


def test_successful_check_renders_findings(app_client, monkeypatch):
    monkeypatch.setattr("app.routes.website.check_website", lambda raw: _sample_result())

    response = _csrf_post(app_client, "/website-check", {"url": TARGET})
    assert response.status_code == 200
    body = response.text
    assert "Results for" in body
    assert "No Content-Security-Policy header" in body
    assert "Evidence:" in body
    assert "deterministic rule" in body
    assert "advisory and require human verification" in body


def test_invalid_target_shows_safe_error(app_client, monkeypatch):
    def explode(raw):
        raise SafeInputError("Refusing to check a private or reserved address.")

    monkeypatch.setattr("app.routes.website.check_website", explode)

    response = _csrf_post(app_client, "/website-check", {"url": "http://127.0.0.1/"})
    assert response.status_code == 400
    assert "private or reserved address" in response.text
    assert "Check not completed." in response.text


def test_unexpected_failure_shows_generic_error_without_details(app_client, monkeypatch):
    def explode(raw):
        raise RuntimeError("secret traceback details: password=hunter2")

    monkeypatch.setattr("app.routes.website.check_website", explode)

    response = _csrf_post(app_client, "/website-check", {"url": TARGET})
    assert response.status_code == 502
    assert "could not be completed" in response.text
    assert "hunter2" not in response.text
    assert "traceback" not in response.text.lower()


def test_private_target_is_rejected_end_to_end(app_client):
    """No service stubbing: input safety must reject before any request is made."""
    response = _csrf_post(app_client, "/website-check", {"url": "http://127.0.0.1/"})
    assert response.status_code == 400
    assert "Check not completed." in response.text
