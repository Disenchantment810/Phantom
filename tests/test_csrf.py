"""CSRF token signing, dependency enforcement, and route coverage."""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.security.csrf import (
    CSRF_COOKIE_NAME,
    CsrfMiddleware,
    csrf_protect,
    new_signed_token,
    tokens_match,
    validate_token,
)

SECRET = "unit-test-secret"


def test_signed_token_roundtrip():
    token = new_signed_token(SECRET)
    assert validate_token(SECRET, token)
    assert not validate_token("another-secret", token)
    assert not validate_token(SECRET, token + "tampered")
    assert not validate_token(SECRET, "")
    assert not validate_token(SECRET, None)  # type: ignore[arg-type]


def test_tokens_match_uses_constant_time_comparison():
    assert tokens_match("abc", "abc")
    assert not tokens_match("abc", "abd")
    assert not tokens_match("", "abc")
    assert not tokens_match("abc", "")


def _mini_app() -> FastAPI:
    from app.config import get_settings

    app = FastAPI()
    # Use the real app secret so the dependency and middleware agree, as they
    # do in the actual application.
    app.add_middleware(CsrfMiddleware, secret_key=get_settings().secret_key, secure=False)

    @app.post("/submit", dependencies=[Depends(csrf_protect)])
    def submit():
        return {"ok": True}

    @app.get("/")
    def index():
        return {"ok": True}

    return app


def test_post_without_token_is_rejected():
    client = TestClient(_mini_app())
    response = client.post("/submit")
    assert response.status_code == 403


def test_post_with_header_token_is_accepted():
    client = TestClient(_mini_app())
    client.get("/")  # issues the CSRF cookie
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    response = client.post("/submit", headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_post_with_form_field_token_is_accepted():
    client = TestClient(_mini_app())
    client.get("/")
    token = client.cookies.get(CSRF_COOKIE_NAME)
    response = client.post("/submit", data={"csrf_token": token})
    assert response.status_code == 200


def test_post_with_forged_token_is_rejected():
    client = TestClient(_mini_app())
    client.get("/")
    forged = new_signed_token("attacker-key")
    response = client.post("/submit", headers={"X-CSRF-Token": forged})
    assert response.status_code == 403


def test_get_requests_receive_a_csrf_cookie():
    from app.config import get_settings

    client = TestClient(_mini_app())
    response = client.get("/")
    assert response.status_code == 200
    cookie = client.cookies.get(CSRF_COOKIE_NAME)
    assert cookie and validate_token(get_settings().secret_key, cookie)


def test_every_unsafe_route_uses_the_csrf_dependency():
    """Guardrail: any state-changing route must include csrf_protect."""
    from app.main import create_app

    app = create_app()
    unsafe = [
        route
        for route in app.router.routes
        if getattr(route, "methods", None)
        and route.methods - {"GET", "HEAD", "OPTIONS"}
    ]
    for route in unsafe:
        dependencies = [dep.dependency for dep in route.dependencies]
        assert csrf_protect in dependencies, (
            f"Route {route.path} accepts unsafe methods without CSRF protection"
        )
