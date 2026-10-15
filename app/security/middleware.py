"""Response security headers and request-body size guard."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defence-in-depth headers on every response.

    Templates never rely on inline styles or scripts, so the CSP below stays
    strict ('self' only). Escaped output comes from Jinja2 autoescaping.
    """

    async def dispatch(self, request, call_next):  # noqa: ANN001
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies early (413) instead of buffering them."""

    def __init__(self, app, max_body_bytes: int):  # noqa: ANN001
        super().__init__(app)
        self.max_body_bytes = max_body_bytes

    async def dispatch(self, request, call_next):  # noqa: ANN001
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > self.max_body_bytes:
            return PlainTextResponse("Request body too large.", status_code=413)
        return await call_next(request)
