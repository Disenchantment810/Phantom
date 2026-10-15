"""Header rules and bounded fetching with mocked transports (no network)."""

from __future__ import annotations

import httpx
import pytest

from app.models import Confidence, Severity
from app.services.input_safety import SafeInputError
from app.services.website_checker import (
    MAX_RESPONSE_BYTES,
    check_website,
    evaluate_headers,
)

PUBLIC_RESOLVER = {
    "example.com": ["93.184.216.34"],
    "www.example.com": ["93.184.216.34"],
    "cdn.example.com": ["93.184.216.34"],
    "rebind.example": ["10.9.9.9"],
}


def _resolver_for(mapping):
    def resolver(host):
        if host not in mapping:
            raise SafeInputError("The website host could not be resolved.")
        return mapping[host]

    return resolver


def _handler(response_for):
    def handler(request: httpx.Request) -> httpx.Response:
        return response_for(request)

    return handler


def _run(url, response_for, extra_resolved=None):
    mapping = dict(PUBLIC_RESOLVER)
    mapping.update(extra_resolved or {})
    transport = httpx.MockTransport(_handler(response_for))
    return check_website(
        url, transport=transport, resolver=_resolver_for(mapping), min_interval=0
    )


GOOD_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


class TestHeaderRules:
    def test_strong_headers_produce_informational_findings(self):
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(GOOD_HEADERS))
        by_title = {f.title: f for f in findings}
        assert all(f.severity == Severity.INFORMATIONAL for f in by_title.values())
        # Evidence always carries the observed value (FR-08).
        assert "default-src 'self'" in by_title[
            "Content-Security-Policy is configured"
        ].evidence

    def test_missing_csp_is_medium_on_https(self):
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "content-security-policy"}
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(headers))
        csp = next(f for f in findings if "Content-Security-Policy" in f.title)
        assert csp.severity == Severity.MEDIUM
        assert "No Content-Security-Policy header" in csp.title

    def test_missing_csp_is_low_without_https(self):
        findings = evaluate_headers(is_https=False, headers=httpx.Headers({}))
        csp = next(f for f in findings if "Content-Security-Policy" in f.title)
        assert csp.severity == Severity.LOW

    def test_weak_csp_is_flagged(self):
        findings = evaluate_headers(
            is_https=True,
            headers=httpx.Headers({**GOOD_HEADERS, "content-security-policy": "default-src 'self' 'unsafe-inline'"}),
        )
        csp = next(f for f in findings if "Content-Security-Policy" in f.title)
        assert csp.severity == Severity.LOW
        assert "weak" in csp.title.lower()

    def test_wildcard_script_source_is_weak(self):
        findings = evaluate_headers(
            is_https=True,
            headers=httpx.Headers({**GOOD_HEADERS, "content-security-policy": "script-src *"}),
        )
        csp = next(f for f in findings if "Content-Security-Policy" in f.title)
        assert csp.severity == Severity.LOW

    def test_missing_hsts_is_medium_over_https(self):
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "strict-transport-security"}
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(headers))
        hsts = next(f for f in findings if "Strict-Transport-Security" in f.title)
        assert hsts.severity == Severity.MEDIUM

    def test_short_hsts_max_age_is_low(self):
        findings = evaluate_headers(
            is_https=True,
            headers=httpx.Headers({**GOOD_HEADERS, "strict-transport-security": "max-age=3600"}),
        )
        hsts = next(f for f in findings if "Strict-Transport-Security" in f.title)
        assert hsts.severity == Severity.LOW

    def test_hsts_not_evaluated_without_https(self):
        findings = evaluate_headers(is_https=False, headers=httpx.Headers(GOOD_HEADERS))
        assert not any("Strict-Transport-Security" in f.title for f in findings)

    def test_missing_nosniff_is_low(self):
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "x-content-type-options"}
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(headers))
        nosniff = next(f for f in findings if "X-Content-Type-Options" in f.title)
        assert nosniff.severity == Severity.LOW

    def test_wrong_nosniff_value_is_flagged(self):
        findings = evaluate_headers(
            is_https=True,
            headers=httpx.Headers({**GOOD_HEADERS, "x-content-type-options": "something-else"}),
        )
        nosniff = next(f for f in findings if "X-Content-Type-Options" in f.title)
        assert nosniff.severity == Severity.LOW

    def test_unsafe_url_referrer_is_medium(self):
        findings = evaluate_headers(
            is_https=True,
            headers=httpx.Headers({**GOOD_HEADERS, "referrer-policy": "unsafe-url"}),
        )
        referrer = next(f for f in findings if "Referrer-Policy" in f.title)
        assert referrer.severity == Severity.MEDIUM

    def test_missing_frame_protection_is_low(self):
        headers = {k: v for k, v in GOOD_HEADERS.items() if k != "x-frame-options"}
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(headers))
        frame = next(f for f in findings if "frame protection" in f.title.lower())
        assert frame.severity == Severity.LOW
        assert frame.confidence == Confidence.MEDIUM

    def test_csp_frame_ancestors_satisfies_frame_protection(self):
        headers = {
            **GOOD_HEADERS,
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        }
        findings = evaluate_headers(is_https=True, headers=httpx.Headers(headers))
        frame = next(f for f in findings if "Frame protection" in f.title)
        assert frame.severity == Severity.INFORMATIONAL


class TestCheckWebsite:
    def test_happy_path_over_https(self):
        def response_for(request):
            return httpx.Response(200, headers=GOOD_HEADERS, text="ok")

        result = _run("https://example.com/", response_for)
        assert result.status_code == 200
        assert result.final_url == "https://example.com/"
        assert result.https_used is True
        assert result.redirect_chain == ["https://example.com/"]
        assert any("Checked over HTTPS" in f.title for f in result.findings)
        assert result.summary.startswith("Check completed:")

    def test_bare_domain_is_https(self):
        def response_for(request):
            assert request.url.scheme == "https"
            return httpx.Response(200, headers=GOOD_HEADERS, text="ok")

        result = _run("example.com", response_for)
        assert result.final_url == "https://example.com/"

    def test_http_to_https_redirect_is_reported(self):
        calls = {"n": 0}

        def response_for(request):
            if request.url.scheme == "http":
                return httpx.Response(
                    301, headers={**GOOD_HEADERS, "Location": "https://example.com/"}
                )
            return httpx.Response(200, headers=GOOD_HEADERS, text="ok")

        result = _run("http://example.com/", response_for)
        assert result.final_url == "https://example.com/"
        assert any("redirected" in f.title.lower() for f in result.findings)
        assert len(result.redirect_chain) == 2

    def test_relative_redirect_chain_is_followed(self):
        def response_for(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={**GOOD_HEADERS, "Location": "/login"})
            if request.url.path == "/login":
                return httpx.Response(302, headers={**GOOD_HEADERS, "Location": "https://cdn.example.com/home"})
            return httpx.Response(200, headers=GOOD_HEADERS, text="ok")

        result = _run("https://example.com/", response_for)
        assert result.final_url == "https://cdn.example.com/home"
        assert len(result.redirect_chain) == 3

    def test_redirect_to_private_ip_is_blocked(self):
        def response_for(request):
            return httpx.Response(
                302, headers={**GOOD_HEADERS, "Location": "http://169.254.169.254/latest/meta-data/"}
            )

        with pytest.raises(SafeInputError, match="private or reserved"):
            _run("https://example.com/", response_for)

    def test_redirect_to_internal_hostname_is_blocked(self):
        def response_for(request):
            return httpx.Response(302, headers={**GOOD_HEADERS, "Location": "http://localhost:8080/admin"})

        with pytest.raises(SafeInputError, match="internal"):
            _run("https://example.com/", response_for)

    def test_redirect_to_non_http_scheme_is_blocked(self):
        def response_for(request):
            return httpx.Response(302, headers={**GOOD_HEADERS, "Location": "file:///etc/passwd"})

        with pytest.raises(SafeInputError, match="unsupported scheme"):
            _run("https://example.com/", response_for)

    def test_redirect_loop_is_capped(self):
        def response_for(request):
            return httpx.Response(302, headers={**GOOD_HEADERS, "Location": "https://example.com/loop"})

        with pytest.raises(SafeInputError, match="Too many redirects"):
            _run("https://example.com/", response_for)

    def test_timeout_becomes_safe_error(self):
        def response_for(request):
            raise httpx.ConnectTimeout("timed out", request=request)

        with pytest.raises(SafeInputError, match="did not respond in time"):
            _run("https://example.com/", response_for)

    def test_tls_failure_becomes_safe_error(self):
        def response_for(request):
            raise httpx.ConnectError("certificate verify failed", request=request)

        # ConnectError is a generic transport error; checker reports it safely.
        with pytest.raises(SafeInputError):
            _run("https://example.com/", response_for)

    def test_large_response_body_is_truncated(self):
        def response_for(request):
            return httpx.Response(
                200,
                headers=GOOD_HEADERS,
                content=b"x" * (MAX_RESPONSE_BYTES + 1),
            )

        result = _run("https://example.com/", response_for)
        assert result.response_truncated is True
        assert result.status_code == 200

    def test_finding_sources_are_deterministic(self):
        def response_for(request):
            return httpx.Response(200, headers=GOOD_HEADERS, text="ok")

        result = _run("https://example.com/", response_for)
        assert result.findings
        assert all(f.source_type.value == "rule" for f in result.findings)
