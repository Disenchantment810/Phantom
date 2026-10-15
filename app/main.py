"""PHANTOM application factory and ASGI entry point.

Run locally with:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import database
from app.config import APP_NAME, APP_VERSION, get_settings
from app.routes import code_review, dashboard, history, log_analysis, reports, website
from app.security.csrf import CsrfMiddleware
from app.security.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.templating import PhantomTemplates

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    logger.info("PHANTOM started (version %s)", APP_VERSION)
    yield
    database.dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description=(
            "AI-assisted cybersecurity analysis workbench. Findings are advisory "
            "and require human verification."
        ),
        lifespan=lifespan,
        # Interactive API docs are a dev convenience; not exposed in production.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
    )

    app.state.settings = settings
    app.state.templates = PhantomTemplates(settings)

    # Middleware order: last-added runs first for requests.
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=settings.max_body_bytes)
    app.add_middleware(
        CsrfMiddleware, secret_key=settings.secret_key, secure=settings.is_production
    )
    app.add_middleware(SecurityHeadersMiddleware)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(dashboard.router)
    app.include_router(history.router)
    app.include_router(website.router)
    app.include_router(code_review.router)
    app.include_router(log_analysis.router)
    app.include_router(reports.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        # Render friendly error pages; never echo the offending URL or details.
        if exc.status_code == 404:
            return app.state.templates.render(request, "404.html", status_code=404)
        if exc.status_code >= 500:
            logger.error("Server error on %s: %s", request.url.path, exc.detail)
            return app.state.templates.render(request, "500.html", status_code=500)
        templates: PhantomTemplates = app.state.templates
        return templates.render(
            request,
            "error.html",
            {"status_code": exc.status_code, "message": str(exc.detail)},
            status_code=exc.status_code,
        )

    return app


app = create_app()
