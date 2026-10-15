"""Response security headers and request-body size guard."""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

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


class BodySizeLimitMiddleware:
    """Reject oversized request bodies early (413) instead of buffering them.

    Handles both declared and undeclared body lengths:
    - A Content-Length header over the cap is rejected before the body is read.
    - A body with no Content-Length (chunked transfer) declares no size, so it
      is streamed through a bounded buffer and rejected mid-stream once the cap
      is exceeded; under the cap, the buffered body is replayed to the app.
    """

    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in BODY_METHODS:
            await self.app(scope, receive, send)
            return

        content_length = Headers(scope=scope).get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                declared = None
            if declared is not None and declared > self.max_body_bytes:
                await self._reject(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        body, too_large = await self._buffer_body(receive)
        if too_large:
            await self._reject(scope, receive, send)
            return

        replayed = {"done": False}

        async def replay() -> Message:
            if not replayed["done"]:
                replayed["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    async def _buffer_body(self, receive: Receive) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return b"", False
            total += len(message.get("body", b""))
            if total > self.max_body_bytes:
                return b"", True
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                return b"".join(chunks), False

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = PlainTextResponse("Request body too large.", status_code=413)
        await response(scope, receive, send)
