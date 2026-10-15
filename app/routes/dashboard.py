"""Dashboard, history, and settings routes (Phase 0 foundation)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Analysis
from app.templating import PhantomTemplates, get_templates

router = APIRouter()


@router.api_route("/", methods=["GET", "HEAD"], name="dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    recent = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(10).all()
    total = db.query(func.count(Analysis.id)).scalar() or 0
    return templates.render(
        request, "index.html", {"recent": recent, "total_analyses": total}
    )


@router.api_route("/history", methods=["GET", "HEAD"], name="history")
def history(
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    analyses = db.query(Analysis).order_by(Analysis.created_at.desc()).all()
    return templates.render(request, "history.html", {"analyses": analyses})


@router.api_route("/settings", methods=["GET", "HEAD"], name="settings")
def settings_view(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    settings = templates.settings
    return templates.render(
        request,
        "settings.html",
        {
            "environment": settings.environment,
            "max_body_bytes": settings.max_body_bytes,
            "upload_max_bytes": settings.upload_max_bytes,
            "ai_provider_configured": bool(settings.ai_provider),
        },
    )
