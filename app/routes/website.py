"""Website security configuration check (Phase 1).

Passive, bounded, single-target checks with SSRF validation on every hop.
Results are rendered in the response; persistence and history arrive in
Phase 5 (per the delivery plan), so nothing is stored yet.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from starlette.responses import Response

from app.security.csrf import csrf_protect
from app.services.input_safety import SafeInputError
from app.services.website_checker import WebsiteCheckResult, check_website
from app.templating import PhantomTemplates, get_templates

logger = logging.getLogger(__name__)

router = APIRouter()


def _form_page(
    templates: PhantomTemplates,
    request: Request,
    *,
    url_value: str = "",
    error: str | None = None,
    result: WebsiteCheckResult | None = None,
    status_code: int = 200,
) -> Response:
    return templates.render(
        request,
        "website_check.html",
        {"url_value": url_value, "error": error, "result": result},
        status_code=status_code,
    )


@router.api_route("/website-check", methods=["GET", "HEAD"], name="website_check")
def website_check(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    return _form_page(templates, request)


@router.api_route(
    "/website-check",
    methods=["POST"],
    name="website_check_submit",
    dependencies=[Depends(csrf_protect)],
)
async def website_check_submit(
    request: Request,
    templates: PhantomTemplates = Depends(get_templates),
):
    form = await request.form()
    raw_url = form.get("url", "")
    if not isinstance(raw_url, str):
        raw_url = ""

    try:
        result = await run_in_threadpool(check_website, raw_url)
    except SafeInputError as exc:
        # Invalid, unreachable, or unsupported target: a safe, explainable error.
        logger.info("Website check rejected for %s: %s", _log_label(raw_url), exc)
        return _form_page(
            templates,
            request,
            url_value=raw_url[:200],
            error=str(exc),
            status_code=400,
        )
    except Exception:
        # Never leak stack traces or raw targets into the page (FR-15).
        logger.exception("Website check failed unexpectedly")
        return _form_page(
            templates,
            request,
            url_value=raw_url[:200],
            error=(
                "The check could not be completed. Deterministic features are "
                "unaffected — please try again."
            ),
            status_code=502,
        )

    return _form_page(templates, request, url_value=raw_url[:200], result=result)


def _log_label(raw_url: str) -> str:
    """Log only the host, never a full URL with possible query strings."""
    from app.services.input_safety import normalize_url
    from urllib.parse import urlparse

    try:
        return urlparse(normalize_url(raw_url)).hostname or "<unparsed>"
    except SafeInputError:
        return "<invalid>"
