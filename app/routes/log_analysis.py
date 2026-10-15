"""Security log analysis (Phase 3).

Paste and upload flows, both CSRF-protected. Log text is analysed as data
only; findings are indicators for review, not proof of compromise, and every
result repeats that. Persistence and history arrive in Phase 5.
"""

from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from starlette.responses import Response

from app.security.csrf import csrf_protect
from app.database import get_db
from app.models import AnalysisType
from app.services.ai_assist import AIAssistOutcome, run_ai_assist
from app.services.persistence import persist_analysis
from app.services.log_analyzer import LogAnalysisError, analyze_log
from app.templating import PhantomTemplates, get_templates

logger = logging.getLogger(__name__)

router = APIRouter()


def ai_available(request: Request) -> bool:
    from app.services.ai_provider import build_provider_from_settings

    return build_provider_from_settings(request.app.state.settings) is not None

LOG_EXTENSIONS = (".log", ".txt")


def _form_page(
    templates: PhantomTemplates,
    request: Request,
    *,
    log_value: str = "",
    error: str | None = None,
    result=None,
    result_label: str = "",
    ai_outcome: AIAssistOutcome | None = None,
    status_code: int = 200,
) -> Response:
    return templates.render(
        request,
        "log_analysis.html",
        {
            "error": error,
            "result": result,
            "result_label": result_label,
            "log_value": log_value,
            "ai_outcome": ai_outcome,
            "ai_available": ai_available(request),
        },
        status_code=status_code,
    )


@router.api_route("/log-analysis", methods=["GET", "HEAD"], name="log_analysis")
def log_analysis(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return _form_page(templates, request)


def _sanitize_label(filename: str) -> str:
    name = os.path.basename(filename.replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]", "", name).strip(". ")
    return name[:80] if name else "uploaded log"


async def _analyze(
    templates: PhantomTemplates,
    request: Request,
    *,
    content: str,
    label: str,
    log_value: str = "",
    ai_consented: bool = False,
    db: Session | None = None,
) -> Response:
    try:
        result = await run_in_threadpool(analyze_log, content)
    except LogAnalysisError as exc:
        logger.info("Log analysis rejected (%s): %s", label[:40] or "<paste>", exc)
        return _form_page(
            templates,
            request,
            log_value=log_value,
            error=str(exc),
            status_code=400,
        )
    except Exception:
        logger.exception("Log analysis failed unexpectedly")
        return _form_page(
            templates,
            request,
            log_value=log_value,
            error=(
                "The analysis could not be completed. Deterministic features are "
                "unaffected — please try again."
            ),
            status_code=502,
        )
    # Echo the MASKED text back into the textarea so copy-pasting the page or
    # re-sharing the input never re-exposes a secret (PRD privacy stance).
    from app.services.log_analyzer import mask_secrets

    ai_outcome = await run_in_threadpool(
        run_ai_assist,
        settings=request.app.state.settings,
        task="log_analysis",
        consented=ai_consented,
        content=log_value,
        deterministic_summary=(
            f"{len(result.findings)} deterministic findings: "
            + "; ".join(f"{f.title} ({f.severity.value})" for f in result.findings[:10])
            if result.findings
            else ""
        ),
        target_label=label,
    )
    if db is not None:
        persist_analysis(
            db,
            analysis_type=AnalysisType.LOG_ANALYSIS,
            target_label=label,
            summary=(
                f"{result.stats.parsed_lines}/{result.stats.total_lines} lines parsed, "
                f"{result.stats.failed_events} failed, {result.stats.success_events} successful, "
                f"{len(result.findings)} indicator(s)."
                + (f" AI-assisted interpretation by {ai_outcome.ai_analysis.provider_name}." if ai_outcome.ai_analysis else "")
            ),
            findings=result.findings,
            ai_outcome=ai_outcome,
        )
    return _form_page(
        templates,
        request,
        log_value=mask_secrets(content),
        result=result,
        result_label=label,
        ai_outcome=ai_outcome,
    )
@router.api_route(
    "/log-analysis",
    methods=["POST"],
    name="log_analysis_submit",
    dependencies=[Depends(csrf_protect)],
)
async def log_analysis_submit(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
    db: Session = Depends(get_db),
):
    form = await request.form()
    log_text = form.get("log", "")
    if not isinstance(log_text, str):
        log_text = ""
    consent = form.get("ai_consent") == "on"
    return await _analyze(
        templates,
        request,
        content=log_text,
        label="pasted log",
        log_value=log_text,
        ai_consented=consent,
        db=db,
    )


@router.api_route(
    "/log-analysis/upload",
    methods=["POST"],
    name="log_analysis_upload",
    dependencies=[Depends(csrf_protect)],
)
async def log_analysis_upload(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
    db: Session = Depends(get_db),
):
    settings = request.app.state.settings
    form = await request.form()
    upload = form.get("file")

    if upload is None or not getattr(upload, "filename", None):
        return _form_page(
            templates,
            request,
            error="Choose a file to upload, or paste the log text instead.",
            status_code=400,
        )

    label = _sanitize_label(upload.filename)
    if not label.lower().endswith(LOG_EXTENSIONS):
        return _form_page(
            templates,
            request,
            error=(
                f"Unsupported file type for {label}. Use a .log or .txt file, "
                "or paste the text instead."
            ),
            status_code=400,
        )

    content_bytes = await upload.read(settings.upload_max_bytes + 1)
    if len(content_bytes) > settings.upload_max_bytes:
        limit_kib = settings.upload_max_bytes // 1024
        return _form_page(
            templates,
            request,
            error=f"The file is too large (limit {limit_kib} KiB). Paste a smaller excerpt instead.",
            status_code=400,
        )

    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _form_page(
            templates,
            request,
            error="The file could not be read as UTF-8 text. PHANTOM reviews text logs only.",
            status_code=400,
        )

    consent = form.get("ai_consent") == "on"
    return await _analyze(
        templates, request, content=content, label=label, ai_consented=consent, db=db
    )
