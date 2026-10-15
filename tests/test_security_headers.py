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


def _post_chunked(app, chunks: list[bytes], method: str = "POST", path: str = "/"):
    """Invoke the ASGI app directly with a body that has no Content-Length."""
    import asyncio

    async def scenario():
        messages: list[dict] = []
        received = {"i": 0}

        async def receive() -> dict:
            i = received["i"]
            received["i"] += 1
            if i < len(chunks):
                return {
                    "type": "http.request",
                    "body": chunks[i],
                    "more_body": i + 1 < len(chunks),
                }
            return {"type": "http.disconnect"}

        async def send(message: dict) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],  # no content-length: forces the streaming path
        }
        await app(scope, receive, send)
        return messages

    return asyncio.run(scenario())


def test_chunked_body_over_cap_rejected(app_client):
    chunks = [b"x" * 65536] * 20  # 1.25 MiB streamed with no declared length
    messages = _post_chunked(app_client.app, chunks)
    status = next(m for m in messages if m["type"] == "http.response.start")
    assert status["status"] == 413


def test_chunked_body_under_cap_reaches_app_intact():
    """A chunked body inside the cap is buffered and replayed unmodified."""
    import asyncio

    from app.security.middleware import BodySizeLimitMiddleware

    async def scenario():
        captured: dict = {}

        async def stub_app(scope, receive, send):  # noqa: ANN001
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    break
                body.extend(message.get("body", b""))
                if not message.get("more_body", False):
                    break
            captured["body"] = bytes(body)

        parts = [b"hello ", b"world"]
        received = {"i": 0}

        async def receive() -> dict:
            i = received["i"]
            received["i"] += 1
            if i < len(parts):
                return {
                    "type": "http.request",
                    "body": parts[i],
                    "more_body": i + 1 < len(parts),
                }
            return {"type": "http.disconnect"}

        async def send(message: dict) -> None:  # app under test sends nothing
            pass

        middleware = BodySizeLimitMiddleware(stub_app, max_body_bytes=1024)
        await middleware(
            {"type": "http", "method": "POST", "headers": []}, receive, send
        )
        return captured

    result = asyncio.run(scenario())
    assert result["body"] == b"hello world"
