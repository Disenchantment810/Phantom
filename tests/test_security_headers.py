"""Security headers on every response, including errors (PRD §9)."""

from __future__ import annotations


def test_security_headers_present(app_client):
    response = app_client.get("/")
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    csp = headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


def test_security_headers_on_404(app_client):
    response = app_client.get("/missing")
    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_templates_carry_no_inline_script_or_style(app_client):
    """CSP forbids inline code, so rendered pages must not use any."""
    for path in ("/", "/website-check", "/code-review", "/log-analysis", "/history", "/settings"):
        body = app_client.get(path).text.lower()
        assert "style=" not in body, f"inline style found on {path}"
        assert "onclick=" not in body, f"inline handler found on {path}"
        assert "<script>" not in body, f"inline script found on {path}"


def test_oversized_body_rejected(app_client):
    response = app_client.post(
        "/",
        content=b"x" * (2 * 1024 * 1024),
        headers={"Content-Length": str(2 * 1024 * 1024)},
    )
    assert response.status_code == 413
