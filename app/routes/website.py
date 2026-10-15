"""Website security configuration check (placeholder until Phase 1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.templating import PhantomTemplates, get_templates

router = APIRouter()


@router.api_route("/website-check", methods=["GET", "HEAD"], name="website_check")
def website_check(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return templates.render(request, "website_check.html")
