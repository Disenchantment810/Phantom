"""CSRF protection: signed double-submit tokens.

- GET requests get a signed token in a SameSite=Lax cookie; the same value is
  exposed to templates as `csrf_token` (via request.state) for hidden inputs.
- State-changing routes MUST apply the `csrf_protect` dependency. It accepts the
  token from either the X-CSRF-Token header or a csrf_token form field and
  requires it to match the signed cookie.

The token is signed with the application SECRET_KEY (itsdangerous), so values
forged by an attacker fail validation even if a cookie is planted.
"""

from __future__ import annotations

import hmac
import secrets

from fastapi import HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

CSRF_COOKIE_NAME = "phantom_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
TOKEN_MAX_AGE_SECONDS = 24 * 60 * 60


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="phantom.csrf")


def new_signed_token(secret_key: str) -> str:
    """Create a fresh signed token."""
    return _serializer(secret_key).dumps(secrets.token_urlsafe(32))


def validate_token(secret_key: str, token: str, max_age: int = TOKEN_MAX_AGE_SECONDS) -> bool:
    """Return True only for a well-formed, unexpired, untampered token."""
    if not token:
        return False
    try:
        _serializer(secret_key).loads(token, max_age=max_age)
    except (BadSignature, Exception):  # itsdangerous raises BadData subclasses
        return False
    return True


def tokens_match(token_a: str, token_b: str) -> bool:
    return bool(token_a) and bool(token_b) and hmac.compare_digest(token_a, token_b)


async def csrf_protect(request: Request) -> None:
    """FastAPI dependency enforcing CSRF on state-changing requests.

    Usage: app.include_router(..., dependencies=[Depends(csrf_protect)]) or
    per-endpoint dependencies=[Depends(csrf_protect)].
    """
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return

    from app.config import get_settings

    settings = get_settings()
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not validate_token(settings.secret_key, cookie_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token. Reload the page and try again.",
        )

    token = request.headers.get(CSRF_HEADER_NAME, "")
    if not token and request.method == "POST":
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            try:
                form = await request.form()
            except Exception:  # malformed body; fall through to failure below
                form = None
            if form is not None:
                value = form.get(CSRF_FORM_FIELD)
                token = value if isinstance(value, str) else ""

    if not tokens_match(token, cookie_token) or not validate_token(settings.secret_key, token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token. Reload the page and try again.",
        )


class CsrfMiddleware(BaseHTTPMiddleware):
    """Issues the CSRF cookie and exposes the token to templates on safe requests."""

    def __init__(self, app, secret_key: str, secure: bool = False):  # noqa: ANN001
        super().__init__(app)
        self.secret_key = secret_key
        self.secure = secure

    async def dispatch(self, request, call_next):  # noqa: ANN001
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            # Validation for state-changing requests happens in csrf_protect.
            return await call_next(request)

        token = request.cookies.get(CSRF_COOKIE_NAME, "")
        issue_cookie = False
        if not validate_token(self.secret_key, token):
            token = new_signed_token(self.secret_key)
            issue_cookie = True

        request.state.csrf_token = token
        response = await call_next(request)
        if issue_cookie:
            response.set_cookie(
                CSRF_COOKIE_NAME,
                token,
                max_age=TOKEN_MAX_AGE_SECONDS,
                samesite="lax",
                secure=self.secure,
                httponly=True,
                path="/",
            )
        return response
