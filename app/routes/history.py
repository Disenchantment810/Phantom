"""History: list, detail, delete, and HTML report export (PRD FR-09, FR-10)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AnalysisType
from app.security.csrf import csrf_protect
from app.services.persistence import delete_analysis, get_analysis
from app.templating import PhantomTemplates, get_templates

logger = logging.getLogger(__name__)

router = APIRouter()

TYPE_LABELS = {
    AnalysisType.WEBSITE_CHECK: "Website Check",
    AnalysisType.CODE_REVIEW: "Code Review",
    AnalysisType.LOG_ANALYSIS: "Log Analysis",
}


@router.api_route("/history", methods=["GET", "HEAD"], name="history")
def history(
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    from app.services.persistence import list_analyses

    analyses = list_analyses(db)
    return templates.render(
        request,
        "history.html",
        {"analyses": analyses, "type_labels": TYPE_LABELS},
    )


@router.api_route("/analyses/{analysis_id}", methods=["GET", "HEAD"], name="analysis_detail")
def analysis_detail(
    analysis_id: int,
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    analysis = get_analysis(db, analysis_id)
    if analysis is None:
        return templates.render(request, "404.html", status_code=404)
    return templates.render(
        request,
        "analysis_detail.html",
        {"analysis": analysis, "type_labels": TYPE_LABELS},
    )


@router.api_route(
    "/analyses/{analysis_id}/delete",
    methods=["POST"],
    name="analysis_delete",
    dependencies=[Depends(csrf_protect)],
)
def analysis_delete(
    analysis_id: int,
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    deleted = delete_analysis(db, analysis_id)
    if not deleted:
        return templates.render(request, "404.html", status_code=404)
    return RedirectResponse(url="/history", status_code=303)


@router.api_route(
    "/analyses/{analysis_id}/report",
    methods=["GET", "HEAD"],
    name="analysis_report",
)
def analysis_report(
    analysis_id: int,
    request: Request,
    db: Session = Depends(get_db),
    templates: PhantomTemplates = Depends(get_templates),
):
    analysis = get_analysis(db, analysis_id)
    if analysis is None:
        return templates.render(request, "404.html", status_code=404)

    from app.services.report_generator import generate_report

    html = generate_report(analysis)
    safe_stamp = analysis.created_at.strftime("%Y%m%d-%H%M%S")
    filename = f"phantom-report-{analysis_id}-{safe_stamp}.html"
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
