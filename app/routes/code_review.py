"""Source code security review (placeholder until Phase 2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.templating import PhantomTemplates, get_templates

router = APIRouter()


@router.api_route("/code-review", methods=["GET", "HEAD"], name="code_review")
def code_review(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return templates.render(request, "code_review.html")
