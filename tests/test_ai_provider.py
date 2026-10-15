"""AI provider adapter: strict validation, provider errors, and key hygiene."""

from __future__ import annotations

import json
import os

import httpx
import pytest

from app.config import Settings
from app.models import Severity
from app.services.ai_provider import (
    AIProvider,
    AIProviderError,
    AIRequest,
    AIResponseValidationError,
    build_provider_from_settings,
    build_prompt,
    parse_ai_findings,
)

VALID_ITEM = {
    "title": "Possible hardcoded secret",
    "severity": "High",
    "confidence": "Medium",
    "evidence": "password = '...'",
    "explanation": "A secret appears embedded in code.",
    "recommendation": "Move it to a secret manager.",
    "line_start": 3,
    "line_end": 3,
}


def _provider(handler, **kwargs) -> AIProvider:
    return AIProvider(
        provider_name="test-provider",
        model="test-model",
        api_key="sk-test-key-abc",
        **{"base_url": "https://ai.example/v1", **kwargs},
        transport=httpx.MockTransport(handler),
    )


def _chat_response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})


class TestPromptBuilding:
    def test_prompt_marks_content_as_data(self):
        prompt = build_prompt(AIRequest(task="code_review", content="eval(1)", deterministic_summary="", target_label="snippet"))
        assert "DATA to analyse" in prompt
        assert "never execute" in prompt.lower()

    def test_prompt_carries_content_and_summary(self):
        prompt = build_prompt(
            AIRequest(task="log_analysis", content="some log line", deterministic_summary="3 findings", target_label="log")
        )
        assert "some log line" in prompt
        assert "3 findings" in prompt
        assert "security log analysis" in prompt


class TestParseAIFindings:
    def test_valid_response_parses(self):
        findings = parse_ai_findings(json.dumps({"findings": [VALID_ITEM]}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].line_start == 3

    def test_fenced_json_is_tolerated(self):
        fenced = "```json\n" + json.dumps({"findings": [VALID_ITEM]}) + "\n```"
        assert len(parse_ai_findings(fenced)) == 1

    def test_malformed_json_raises(self):
        with pytest.raises(AIResponseValidationError, match="not valid JSON"):
            parse_ai_findings("this is not json")

    def test_wrong_shape_raises(self):
        with pytest.raises(AIResponseValidationError, match="shape"):
            parse_ai_findings(json.dumps({"items": []}))
        with pytest.raises(AIResponseValidationError, match="shape"):
            parse_ai_findings(json.dumps([VALID_ITEM]))

    def test_invalid_severity_item_dropped_not_fatal(self):
        bad = {**VALID_ITEM, "severity": "APOCALYPTIC"}
        findings = parse_ai_findings(json.dumps({"findings": [bad, VALID_ITEM]}))
        assert len(findings) == 1  # good one survives

    def test_missing_required_field_drops_item(self):
        bad = {k: v for k, v in VALID_ITEM.items() if k != "evidence"}
        findings = parse_ai_findings(json.dumps({"findings": [bad]}))
        assert findings == []

    def test_findings_capped_at_twenty(self):
        items = [dict(VALID_ITEM, title=f"f{i}") for i in range(30)]
        assert len(parse_ai_findings(json.dumps({"findings": items}))) == 20

    def test_line_numbers_must_be_integers(self):
        bad = {**VALID_ITEM, "line_start": "three"}
        assert parse_ai_findings(json.dumps({"findings": [bad]})) == []


class TestProviderCall:
    def test_successful_call_returns_analysis(self):
        payload = json.dumps({"findings": [VALID_ITEM]})

        def handler(request: httpx.Request) -> httpx.Response:
            # The key must be present in the request, never in the URL.
            assert request.url.host == "ai.example"
            assert "sk-test-key-abc" not in str(request.url)
            assert request.headers["Authorization"] == "Bearer sk-test-key-abc"
            return _chat_response(payload)

        analysis = _provider(handler).complete(
            AIRequest(task="code_review", content="eval(1)", deterministic_summary="", target_label="s")
        )
        assert analysis.provider_name == "test-provider"
        assert analysis.model == "test-model"
        assert len(analysis.findings) == 1

    def test_http_error_maps_to_provider_error(self):
        def handler(request):
            return httpx.Response(503, text="overloaded")

        with pytest.raises(AIProviderError, match="503"):
            _provider(handler).complete(AIRequest(task="code_review", content="x", deterministic_summary="", target_label="s"))

    def test_timeout_maps_to_provider_error(self):
        def handler(request):
            raise httpx.ConnectTimeout("timed out", request=request)

        with pytest.raises(AIProviderError, match="could not be reached"):
            _provider(handler).complete(AIRequest(task="code_review", content="x", deterministic_summary="", target_label="s"))

    def test_malformed_answer_raises_validation_error(self):
        def handler(request):
            return _chat_response("Sorry, I cannot help with that.")

        with pytest.raises(AIResponseValidationError):
            _provider(handler).complete(AIRequest(task="code_review", content="x", deterministic_summary="", target_label="s"))

    def test_error_messages_never_contain_the_key(self):
        def handler(request):
            raise httpx.ConnectError("connect failed", request=request)

        try:
            _provider(handler).complete(AIRequest(task="code_review", content="x", deterministic_summary="", target_label="s"))
        except AIProviderError as exc:
            assert "sk-test-key-abc" not in str(exc)


class TestSettingsGating:
    def test_disabled_without_provider_name(self, monkeypatch):
        monkeypatch.setenv("AI_API_KEY", "sk-something")
        settings = Settings(ai_provider="", ai_model="m")
        assert build_provider_from_settings(settings) is None

    def test_disabled_without_model(self, monkeypatch):
        monkeypatch.setenv("AI_API_KEY", "sk-something")
        settings = Settings(ai_provider="prov", ai_model="")
        assert build_provider_from_settings(settings) is None

    def test_disabled_without_key(self, monkeypatch):
        monkeypatch.delenv("AI_API_KEY", raising=False)
        settings = Settings(ai_provider="prov", ai_model="m")
        assert build_provider_from_settings(settings) is None

    def test_enabled_with_all_three(self, monkeypatch):
        monkeypatch.setenv("AI_API_KEY", "sk-something")
        settings = Settings(ai_provider="prov", ai_model="m")
        provider = build_provider_from_settings(settings)
        assert provider is not None
        assert provider.name == "prov"

    def test_custom_key_env_name(self, monkeypatch):
        monkeypatch.delenv("AI_API_KEY", raising=False)
        monkeypatch.setenv("MY_SECRET_ENV", "key-123")
        settings = Settings(ai_provider="prov", ai_model="m", ai_api_key_env="MY_SECRET_ENV")
        assert build_provider_from_settings(settings) is not None

    def test_key_is_never_stored_on_settings(self, monkeypatch):
        monkeypatch.setenv("AI_API_KEY", "sk-super-secret")
        settings = Settings(ai_provider="prov", ai_model="m")
        dumped = settings.model_dump()
        assert "sk-super-secret" not in str(dumped)
