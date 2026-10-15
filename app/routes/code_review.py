"""Source code security review (Phase 2).

Two submission flows, both CSRF-protected:
- POST /code-review        — pasted code in a text field
- POST /code-review/upload — one small text file (multipart)

Submissions are analysed as data only (never executed); results are rendered
in the response. Persistence and history arrive in Phase 5.
"""

from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from starlette.responses import Response

from app.security.csrf import csrf_protect
from app.services.code_analyzer import (
    EXTENSION_LANGUAGES,
    LANGUAGE_LABELS,
    SUPPORTED_LANGUAGES,
    CodeReviewError,
    analyze_code,
)
from app.templating import PhantomTemplates, get_templates

logger = logging.getLogger(__name__)

router = APIRouter()

SUPPORTED_EXTENSIONS = sorted(EXTENSION_LANGUAGES)


def _form_page(
    templates: PhantomTemplates,
    request: Request,
    *,
    code_value: str = "",
    language_choice: str = "auto",
    error: str | None = None,
    result=None,
    result_label: str = "",
    status_code: int = 200,
) -> Response:
    return templates.render(
        request,
        "code_review.html",
        {
            "error": error,
            "result": result,
            "result_label": result_label,
            "code_value": code_value,
            "language_choice": language_choice,
            "language_labels": LANGUAGE_LABELS,
            "supported_languages": SUPPORTED_LANGUAGES,
            "supported_extensions": ", ".join(SUPPORTED_EXTENSIONS),
        },
        status_code=status_code,
    )


@router.api_route("/code-review", methods=["GET", "HEAD"], name="code_review")
def code_review(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return _form_page(templates, request)


def _sanitize_label(filename: str) -> str:
    """A short display label from an upload's name — never a path, never raw."""
    name = os.path.basename(filename.replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]", "", name).strip(". ")
    if not name:
        return "uploaded file"
    return name[:80]


def _language_from_filename(filename: str) -> str | None:
    name = os.path.basename(filename.replace("\\", "/")).lower()
    return next(
        (lang for ext, lang in EXTENSION_LANGUAGES.items() if name.endswith(ext)),
        None,
    )


async def _analyze(templates: PhantomTemplates, request: Request, *, content: str, language_choice: str, label: str, code_value: str = "") -> Response:
    try:
        language, findings = await run_in_threadpool(analyze_code, content, language_choice)
    except CodeReviewError as exc:
        logger.info("Code review rejected (%s): %s", label[:40] or "<paste>", exc)
        return _form_page(
            templates,
            request,
            code_value=code_value,
            language_choice=language_choice,
            error=str(exc),
            status_code=400,
        )
    except Exception:
        logger.exception("Code review failed unexpectedly")
        return _form_page(
            templates,
            request,
            code_value=code_value,
            language_choice=language_choice,
            error=(
                "The review could not be completed. Deterministic features are "
                "unaffected — please try again."
            ),
            status_code=502,
        )
    return _form_page(
        templates,
        request,
        code_value=code_value,
        language_choice=language_choice,
        result=(language, findings),
        result_label=label,
    )


@router.api_route(
    "/code-review",
    methods=["POST"],
    name="code_review_submit",
    dependencies=[Depends(csrf_protect)],
)
async def code_review_submit(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    form = await request.form()
    code = form.get("code", "")
    language = form.get("language", "auto")
    if not isinstance(code, str):
        code = ""
    if not isinstance(language, str):
        language = "auto"
    return await _analyze(
        templates,
        request,
        content=code,
        language_choice=language,
        label="pasted snippet",
        code_value=code,
    )


@router.api_route(
    "/code-review/upload",
    methods=["POST"],
    name="code_review_upload",
    dependencies=[Depends(csrf_protect)],
)
async def code_review_upload(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    settings = request.app.state.settings
    form = await request.form()
    upload = form.get("file")
    language = form.get("language", "auto")
    if not isinstance(language, str):
        language = "auto"

    if upload is None or not getattr(upload, "filename", None):
        return _form_page(
            templates,
            request,
            language_choice=language,
            error="Choose a file to upload, or paste the code instead.",
            status_code=400,
        )

    label = _sanitize_label(upload.filename)

    detected = _language_from_filename(upload.filename)
    if detected is None:
        return _form_page(
            templates,
            request,
            language_choice=language,
            error=(
                f"Unsupported file type for {label}. Supported extensions: "
                f"{', '.join(SUPPORTED_EXTENSIONS)}."
            ),
            status_code=400,
        )

    content_bytes = await upload.read(settings.upload_max_bytes + 1)
    if len(content_bytes) > settings.upload_max_bytes:
        limit_kib = settings.upload_max_bytes // 1024
        return _form_page(
            templates,
            request,
            language_choice=language,
            error=f"The file is too large (limit {limit_kib} KiB). Paste the relevant section instead.",
            status_code=400,
        )

    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return _form_page(
            templates,
            request,
            language_choice=language,
            error="The file could not be read as UTF-8 text. PHANTOM reviews text source files only.",
            status_code=400,
        )

    return await _analyze(
        templates,
        request,
        content=content,
        language_choice=language if language in SUPPORTED_LANGUAGES else detected,
        label=label,
    )
