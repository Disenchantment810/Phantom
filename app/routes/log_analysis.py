"""Security log analysis (placeholder until Phase 3)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.templating import PhantomTemplates, get_templates

router = APIRouter()


@router.api_route("/log-analysis", methods=["GET", "HEAD"], name="log_analysis")
def log_analysis(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return templates.render(request, "log_analysis.html")
