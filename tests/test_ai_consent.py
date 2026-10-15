"""Consent gating and graceful fallback in the routes (PRD FR-11 to FR-13)."""

from __future__ import annotations

import json

import httpx
import pytest

from app.services.ai_provider import AIRequest

LOG_INPUT = "\n".join(
    [f"Oct 15 12:00:{i:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" for i in range(1, 7)]
) + "\n"

AI_PAYLOAD = json.dumps(
    {
        "findings": [
            {
                "title": "AI: credential stuffing pattern",
                "severity": "High",
                "confidence": "Low",
                "evidence": "6 failed attempts for root",
                "explanation": "The pattern resembles automated credential guessing.",
                "recommendation": "Verify ownership and review account activity.",
                "line_start": 1,
                "line_end": 6,
            }
        ]
    }
)


def _csrf_post(client, url, data, files=None):
    client.get("/")
    token = client.cookies.get("phantom_csrf")
    data = dict(data)
    data["csrf_token"] = token
    return client.post(url, data=data, files=files)


@pytest.fixture()
def ai_enabled(app_client, monkeypatch):
    """Configure AI against a mock provider that returns AI_PAYLOAD."""
    monkeypatch.setenv("AI_API_KEY", "sk-test-key")
    monkeypatch.setenv("AI_PROVIDER", "test-provider")
    monkeypatch.setenv("AI_MODEL", "test-model")
    from app.config import get_settings

    get_settings.cache_clear()

    def handler(request: httpx.Request) -> httpx.Response:
        assert "sk-test-key" in request.headers["Authorization"]
        return httpx.Response(200, json={"choices": [{"message": {"content": AI_PAYLOAD}}]})

    from app.services import ai_provider as ai_module

    # Refresh the settings snapshot the running app already captured.
    app_client.app.state.settings = get_settings()

    original = ai_module.httpx.Client

    def patched_client(*args, **kwargs):
        kwargs.pop("transport", None)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(ai_module.httpx, "Client", patched_client)
    yield
    get_settings.cache_clear()
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("AI_MODEL", raising=False)


def test_no_ai_checkbox_when_disabled(app_client):
    response = app_client.get("/log-analysis")
    assert response.status_code == 200
    assert 'name="ai_consent"' not in response.text
    assert "AI assistance is disabled" in response.text


def test_ai_checkbox_present_when_configured(app_client, ai_enabled):
    response = app_client.get("/log-analysis")
    assert response.status_code == 200
    assert 'name="ai_consent"' in response.text
    assert "hosted provider" in response.text


def test_no_ai_call_without_consent(app_client, ai_enabled, monkeypatch):
    called = False

    def boom(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("AI provider must not be called without consent")

    monkeypatch.setattr("app.services.ai_provider.AIProvider.complete", boom)
    response = _csrf_post(app_client, "/log-analysis", {"log": LOG_INPUT})
    assert response.status_code == 200
    assert called is False
    assert "test-provider" not in response.text
    assert "AI-assisted — verify" not in response.text


def test_consent_runs_ai_and_renders_labelled_section(app_client, ai_enabled):
    response = _csrf_post(
        app_client, "/log-analysis", {"log": LOG_INPUT, "ai_consent": "on"}
    )
    assert response.status_code == 200
    body = response.text
    assert "AI-assisted interpretation" in body
    assert "AI-assisted — verify" in body
    assert "test-provider" in body  # disclosure names the provider
    assert "credential stuffing pattern" in body
    # Deterministic findings still present alongside
    assert "Repeated failed logins from one address" in body
    # API key never rendered
    assert "sk-test-key" not in body


def test_ai_failure_falls_back_to_deterministic(app_client, ai_enabled, monkeypatch):
    def fail(*args, **kwargs):
        from app.services.ai_provider import AIProviderError

        raise AIProviderError("The AI provider could not be reached.")

    monkeypatch.setattr("app.services.ai_provider.AIProvider.complete", fail)
    response = _csrf_post(app_client, "/log-analysis", {"log": LOG_INPUT, "ai_consent": "on"})
    assert response.status_code == 200
    body = response.text
    assert "AI assistance:" in body
    assert "could not be reached" in body
    assert "Deterministic results are shown" in body
    # Deterministic findings still rendered
    assert "Repeated failed logins from one address" in body


def test_malformed_ai_answer_falls_back(app_client, ai_enabled, monkeypatch):
    def bad_answer(self, request: AIRequest):
        from app.services.ai_provider import AIResponseValidationError

        raise AIResponseValidationError("bad shape")

    monkeypatch.setattr("app.services.ai_provider.AIProvider.complete", bad_answer)
    response = _csrf_post(app_client, "/log-analysis", {"log": LOG_INPUT, "ai_consent": "on"})
    assert response.status_code == 200
    assert "could not be validated" in response.text
    assert "Repeated failed logins from one address" in response.text


def test_code_review_consent_flow(app_client, ai_enabled):
    code = "<?php\neval($_GET['x']);\n"
    response = _csrf_post(
        app_client,
        "/code-review",
        {"code": code, "language": "php", "ai_consent": "on"},
    )
    assert response.status_code == 200
    body = response.text
    assert "AI-assisted interpretation" in body
    assert "test-provider" in body
    assert "eval() on dynamic code" in body  # deterministic finding intact
    assert "sk-test-key" not in body


def test_consent_without_configuration_shows_explainer(app_client, monkeypatch):
    monkeypatch.delenv("AI_API_KEY", raising=False)
    from app.config import get_settings

    get_settings.cache_clear()
    response = _csrf_post(
        app_client,
        "/log-analysis",
        {"log": LOG_INPUT, "ai_consent": "on"},
    )
    assert response.status_code == 200
    assert "not configured on this instance" in response.text
    assert "Repeated failed logins from one address" in response.text
    get_settings.cache_clear()
