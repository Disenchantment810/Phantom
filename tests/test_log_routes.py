"""Log-analysis routes: CSRF, paste and upload flows, safe errors."""

from __future__ import annotations

import re

import pytest

from app.services.log_analyzer import LogAnalysisError

SAMPLE = (
    "Oct 15 12:00:01 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    "Oct 15 12:00:03 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    "Oct 15 12:00:05 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    "Oct 15 12:00:07 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    "Oct 15 12:00:09 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
    "Oct 15 12:00:11 srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2\n"
)


def _csrf_post(client, url, data, files=None):
    client.get("/")
    token = client.cookies.get("phantom_csrf")
    data = dict(data)
    data["csrf_token"] = token
    return client.post(url, data=data, files=files)


def test_form_renders_with_notices(app_client):
    response = app_client.get("/log-analysis")
    assert response.status_code == 200
    assert "indicators for review" in response.text
    assert "not proof" in response.text
    assert 'name="csrf_token"' in response.text


def test_paste_review_renders_findings(app_client):
    response = _csrf_post(app_client, "/log-analysis", {"log": SAMPLE})
    assert response.status_code == 200
    body = response.text
    assert "Repeated failed logins from one address" in body
    assert "203.0.113.5" in body
    assert "Lines 1–6" in body
    assert "deterministic rule" in body
    assert "not proof of compromise" in body
    # Overview numbers
    assert "6 of 6 lines parsed" in body
    assert "6 failed" in body


def test_paste_requires_csrf(app_client):
    response = app_client.post("/log-analysis", data={"log": SAMPLE})
    assert response.status_code == 403


def test_log_content_is_escaped(app_client):
    evil = "Oct 15 12:00:00 srv sshd[1]: Failed password for <script>alert(1)</script> from 203.0.113.5 port 22 ssh2\n" * 6
    response = _csrf_post(app_client, "/log-analysis", {"log": evil})
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_secrets_masked_in_rendered_output(app_client):
    content = (
        "Oct 15 12:06:00 srv nginx: Authorization: Bearer sk-live-abcdef123456 blocked\n"
        + SAMPLE
    )
    response = _csrf_post(app_client, "/log-analysis", {"log": content})
    assert response.status_code == 200
    # The token must not appear anywhere in the rendered page.
    assert "sk-live-abcdef123456" not in response.text
    assert "[REDACTED]" in response.text


def test_empty_submission_shows_safe_error(app_client):
    response = _csrf_post(app_client, "/log-analysis", {"log": ""})
    assert response.status_code == 400
    assert "Analysis not completed." in response.text


def test_unexpected_failure_is_generic(app_client, monkeypatch):
    def explode(content):
        raise RuntimeError("internal detail xyz")

    monkeypatch.setattr("app.routes.log_analysis.analyze_log", explode)
    response = _csrf_post(app_client, "/log-analysis", {"log": SAMPLE})
    assert response.status_code == 502
    assert "xyz" not in response.text


def test_upload_review_from_file(app_client):
    response = _csrf_post(
        app_client,
        "/log-analysis/upload",
        {},
        files={"file": ("auth.log", SAMPLE.encode(), "text/plain")},
    )
    assert response.status_code == 200
    assert "auth.log" in response.text
    assert "Repeated failed logins from one address" in response.text


def test_upload_rejects_unknown_extension(app_client):
    response = _csrf_post(
        app_client,
        "/log-analysis/upload",
        {},
        files={"file": ("weird.bin", SAMPLE.encode(), "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "Unsupported file type" in response.text
    assert ".log" in response.text


def test_upload_rejects_oversized_file(app_client):
    big = SAMPLE.encode() * 1100  # ~540 KiB: over the 512 KiB upload cap, under the 1 MiB request cap
    response = _csrf_post(
        app_client,
        "/log-analysis/upload",
        {},
        files={"file": ("huge.log", big, "text/plain")},
    )
    assert response.status_code == 400
    assert "too large" in response.text


def test_upload_without_file_shows_error(app_client):
    response = _csrf_post(app_client, "/log-analysis/upload", {})
    assert response.status_code == 400
    assert "Choose a file" in response.text


def test_upload_requires_csrf(app_client):
    response = app_client.post(
        "/log-analysis/upload", files={"file": ("a.log", SAMPLE.encode(), "text/plain")}
    )
    assert response.status_code == 403


def test_upload_filename_is_sanitized(app_client):
    response = _csrf_post(
        app_client,
        "/log-analysis/upload",
        {},
        files={"file": ("../../etc/passwd.log", SAMPLE.encode(), "text/plain")},
    )
    assert response.status_code == 200
    assert "../../etc" not in response.text
    assert "passwd.log" in response.text


def test_no_findings_shows_explanatory_empty_state(app_client):
    content = (
        "Oct 15 12:00:00 srv sshd[1]: Accepted password for alice from 198.51.100.10 port 55012 ssh2\n"
    )
    response = _csrf_post(app_client, "/log-analysis", {"log": content})
    assert response.status_code == 200
    assert "No indicator patterns found" in response.text
    assert "not proof" in response.text
