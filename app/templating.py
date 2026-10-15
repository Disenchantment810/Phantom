"""Jinja2 templating with safe defaults and shared template context.

Autoescaping is on (default for HTML in FastAPI's Jinja2Templates), so untrusted
content (URLs, code excerpts, log lines) is escaped in every template.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import APP_NAME, APP_VERSION, Settings, get_settings

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class PhantomTemplates:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
        self._templates.env.globals["app_name"] = APP_NAME
        self._templates.env.globals["app_version"] = APP_VERSION

    def render(
        self,
        request: Request,
        name: str,
        context: dict[str, Any] | None = None,
        status_code: int = 200,
    ):
        ctx: dict[str, Any] = {
            "request": request,
            "csrf_token": getattr(request.state, "csrf_token", ""),
            "environment": self.settings.environment,
            "ai_provider": self.settings.ai_provider,
        }
        if context:
            ctx.update(context)
        return self._templates.TemplateResponse(
            request=request, name=name, context=ctx, status_code=status_code
        )


def get_templates(request: Request) -> PhantomTemplates:
    """FastAPI dependency: the app-level template renderer."""
    return request.app.state.templates
