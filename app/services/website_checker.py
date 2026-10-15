"""Passive website security-configuration checker (PRD §3.2, FR-03).

What it does:
- Sends at most one bounded GET per hop, following redirects manually with
  fresh SSRF validation of every destination (input_safety).
- Evaluates a documented set of security headers and HTTPS behaviour.
- Produces findings that separate observed evidence from interpretation.

What it never does: port scanning, crawling, exploit payloads, or repeated
requests (a small process-wide rate limit keeps checks spaced out).

Severity policy (documented, deliberately conservative — a missing header is
hardening advice, not proof of exploitability):
- Medium: no CSP on an HTTPS response; no HSTS on an HTTPS response;
  Referrer-Policy explicitly leaking full URLs.
- Low: weak CSP directives, short HSTS max-age, missing nosniff, no frame
  protection, missing Referrer-Policy, no HTTPS redirect from http.
- Informational: a well-configured control was observed (evidence attached).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import httpx

from app.database import utcnow
from app.models import Confidence, FindingSource, Severity
from app.services.input_safety import (
    DEFAULT_RESOLVER,
    MAX_REDIRECTS,
    SafeInputError,
    resolve_and_validate_hop,
    resolve_redirect,
)

USER_AGENT = "PHANTOM/0.1 (+local security-configuration checker)"
MAX_RESPONSE_BYTES = 65_536  # we analyse headers; the body is not needed
HSTS_RECOMMENDED_MAX_AGE = 15_552_000  # 180 days
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MIN_CHECK_INTERVAL_SECONDS = 1.0

_rate_lock = threading.Lock()
_last_check_at = 0.0


def _respect_rate_limit(min_interval: float) -> None:
    """Space checks out process-wide; single-user tool, so this stays simple."""
    global _last_check_at
    if min_interval <= 0:
        return
    with _rate_lock:
        elapsed = time.monotonic() - _last_check_at
        if elapsed < min_interval:
            time.sleep(min(min_interval - elapsed, 5.0))
        _last_check_at = time.monotonic()


@dataclass
class CheckFinding:
    """One rule result. Mirrors the Finding model (PRD §8) without the DB."""

    title: str
    category: str
    severity: Severity
    evidence: str
    explanation: str
    recommendation: str
    confidence: Confidence = Confidence.HIGH
    source_type: FindingSource = FindingSource.RULE


@dataclass
class WebsiteCheckResult:
    requested_url: str
    final_url: str
    status_code: int
    redirect_chain: list[str]
    https_used: bool
    checked_at: datetime
    findings: list[CheckFinding] = field(default_factory=list)
    response_truncated: bool = False
    elapsed_ms: int = 0

    @property
    def summary(self) -> str:
        counts = {level.name: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        parts = [f"{count} {name.lower()}" for name, count in counts.items() if count]
        detail = ", ".join(parts) if parts else "no findings"
        return f"Check completed: {detail}."


def _evidence(value: str) -> str:
    value = " ".join(value.split())
    if len(value) > 200:
        value = value[:197] + "..."
    return value


def _header_finding(
    *,
    header_name: str,
    observed: str | None,
    title_missing: str,
    title_present: str,
    severity_missing: Severity,
    severity_weak: Severity | None,
    is_weak: bool,
    explanation_missing: str,
    explanation_present: str,
    recommendation: str,
) -> CheckFinding:
    if observed is None:
        return CheckFinding(
            title=title_missing,
            category="headers",
            severity=severity_missing,
            evidence=f"No {header_name} header was observed in the response.",
            explanation=explanation_missing,
            recommendation=recommendation,
            confidence=Confidence.HIGH,
        )
    if severity_weak is not None and is_weak:
        return CheckFinding(
            title=f"{header_name} configuration is weak",
            category="headers",
            severity=severity_weak,
            evidence=f"Observed header: {header_name}: {_evidence(observed)}",
            explanation=explanation_present,
            recommendation=recommendation,
            confidence=Confidence.HIGH,
        )
    return CheckFinding(
        title=title_present,
        category="headers",
        severity=Severity.INFORMATIONAL,
        evidence=f"Observed header: {header_name}: {_evidence(observed)}",
        explanation=explanation_present,
        recommendation="No change needed for this control.",
        confidence=Confidence.HIGH,
    )


def evaluate_headers(
    *,
    is_https: bool,
    headers: httpx.Headers,
) -> list[CheckFinding]:
    """Deterministic header rules. Every rule documents its severity choice."""
    findings: list[CheckFinding] = []

    # --- Content-Security-Policy -------------------------------------------
    csp = headers.get("content-security-policy")
    csp_weak = False
    if csp:
        lowered = csp.lower()
        script_sources = []
        for directive in lowered.split(";"):
            parts = directive.split()
            if parts and parts[0] in {"default-src", "script-src"}:
                script_sources = parts[1:]
                break
        csp_weak = any(token in script_sources for token in ("'unsafe-inline'", "'unsafe-eval'", "*"))
    findings.append(
        _header_finding(
            header_name="Content-Security-Policy",
            observed=csp,
            title_missing="No Content-Security-Policy header",
            title_present="Content-Security-Policy is configured",
            severity_missing=Severity.MEDIUM if is_https else Severity.LOW,
            severity_weak=Severity.LOW,
            is_weak=csp_weak,
            explanation_missing=(
                "A Content-Security-Policy header lets a site control which resources "
                "browsers may load, and is a strong defence against cross-site scripting."
            ),
            explanation_present=(
                "The policy was observed"
                + (", but it allows inline or wildcard script sources, which weakens it." if csp_weak else ".")
            ),
            recommendation=(
                "Serve a Content-Security-Policy, starting with default-src 'self' and "
                "adding sources only as needed; avoid 'unsafe-inline' and 'unsafe-eval'."
            ),
        )
    )

    # --- Strict-Transport-Security (HTTPS responses only) -------------------
    hsts = headers.get("strict-transport-security")
    hsts_max_age = 0
    if hsts:
        for part in hsts.split(";"):
            key, _, value = part.strip().partition("=")
            if key.strip().lower() == "max-age":
                try:
                    hsts_max_age = int(value.strip().strip('"'))
                except ValueError:
                    hsts_max_age = 0
    if is_https:
        findings.append(
            _header_finding(
                header_name="Strict-Transport-Security",
                observed=hsts,
                title_missing="No Strict-Transport-Security header",
                title_present="Strict-Transport-Security is configured",
                severity_missing=Severity.MEDIUM,
                severity_weak=Severity.LOW if hsts_max_age < HSTS_RECOMMENDED_MAX_AGE else None,
                is_weak=True,
                explanation_missing=(
                    "Strict-Transport-Security tells browsers to use HTTPS for this site, "
                    "blocking downgrade attacks and cookie theft on open networks."
                ),
                explanation_present=(
                    "The header was observed"
                    + (
                        f", but the max-age of {hsts_max_age} seconds is shorter than the "
                        f"recommended {HSTS_RECOMMENDED_MAX_AGE} seconds (180 days)."
                        if hsts_max_age < HSTS_RECOMMENDED_MAX_AGE
                        else "."
                    )
                ),
                recommendation=(
                    "Serve Strict-Transport-Security with max-age of at least 180 days; "
                    "add the includeSubDomains directive once subdomains support HTTPS."
                ),
            )
        )

    # --- X-Content-Type-Options ---------------------------------------------
    nosniff = headers.get("x-content-type-options")
    findings.append(
        _header_finding(
            header_name="X-Content-Type-Options",
            observed=nosniff,
            title_missing="No X-Content-Type-Options header",
            title_present="X-Content-Type-Options is configured",
            severity_missing=Severity.LOW,
            severity_weak=Severity.LOW,
            is_weak=nosniff is not None and nosniff.strip().lower() != "nosniff",
            explanation_missing=(
                "Without this header, browsers may guess (\"sniff\") a file's type and "
                "interpret an uploaded file as script or styles."
            ),
            explanation_present=(
                "The header was observed"
                + ("" if nosniff and nosniff.strip().lower() == "nosniff" else ", but its value is not 'nosniff'.")
            ),
            recommendation="Serve the header with the exact value: X-Content-Type-Options: nosniff.",
        )
    )

    # --- Referrer-Policy ------------------------------------------------------
    referrer = headers.get("referrer-policy")
    referrer_weak = referrer is not None and referrer.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}
    findings.append(
        _header_finding(
            header_name="Referrer-Policy",
            observed=referrer,
            title_missing="No Referrer-Policy header",
            title_present="Referrer-Policy is configured",
            severity_missing=Severity.LOW,
            severity_weak=Severity.MEDIUM if referrer is not None and referrer.strip().lower() == "unsafe-url" else Severity.LOW,
            is_weak=referrer_weak,
            explanation_missing=(
                "A Referrer-Policy controls how much of the page address is shared when "
                "visitors follow links away from the site; unrestricted values can leak "
                "paths and tokens."
            ),
            explanation_present=(
                "The policy was observed"
                + (", but its value shares more referrer data than needed." if referrer_weak else ".")
            ),
            recommendation="Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin.",
        )
    )

    # --- Frame protection (X-Frame-Options and CSP frame-ancestors) ----------
    xfo = headers.get("x-frame-options")
    frame_ancestors = None
    if csp:
        for directive in csp.lower().split(";"):
            parts = directive.split()
            if parts and parts[0] == "frame-ancestors":
                frame_ancestors = " ".join(parts[1:])
    framed_protected = (
        (xfo is not None and xfo.strip().lower() in {"deny", "sameorigin"})
        or (frame_ancestors is not None and frame_ancestors not in {"", "*"})
    )
    if framed_protected:
        observed_value = f"X-Frame-Options: {xfo}" if xfo else f"CSP frame-ancestors: {frame_ancestors}"
        findings.append(
            CheckFinding(
                title="Frame protection is configured",
                category="headers",
                severity=Severity.INFORMATIONAL,
                evidence=f"Observed header: {_evidence(observed_value)}",
                explanation=(
                    "The response restricts who may embed it in a frame, which reduces "
                    "clickjacking risk."
                ),
                recommendation="No change needed for this control.",
            )
        )
    else:
        detail = "an unrecognised value" if xfo else "no X-Frame-Options header and no frame-ancestors directive"
        findings.append(
            CheckFinding(
                title="No frame protection observed",
                category="headers",
                severity=Severity.LOW,
                evidence=(
                    f"Observed header: X-Frame-Options: {_evidence(xfo)}"
                    if xfo
                    else "No X-Frame-Options header was observed in the response and the "
                    "Content-Security-Policy has no frame-ancestors directive."
                ),
                explanation=(
                    f"The response was checked and {detail} was found. Without frame "
                    "protection another site can embed this page, enabling clickjacking "
                    "layouts against signed-in users."
                ),
                recommendation=(
                    "Serve X-Frame-Options: DENY (or SAMEORIGIN), or add "
                    "frame-ancestors 'none' to the Content-Security-Policy."
                ),
                confidence=Confidence.MEDIUM,
            )
        )

    return findings


def _https_finding(requested_url: str, final_url: str, status_code: int) -> CheckFinding:
    requested_is_http = requested_url.startswith("http://")
    final_is_https = final_url.startswith("https://")
    if requested_is_http and final_is_https:
        return CheckFinding(
            title="HTTP requests are redirected to HTTPS",
            category="transport",
            severity=Severity.INFORMATIONAL,
            evidence=f"{requested_url} returned {status_code} and redirected to {final_url}.",
            explanation="Plain-HTTP requests are moved to HTTPS, which protects the connection.",
            recommendation="No change needed for this control.",
        )
    if requested_is_http and not final_is_https:
        return CheckFinding(
            title="Site is served without HTTPS",
            category="transport",
            severity=Severity.LOW,
            evidence=f"The check ended on {final_url} (HTTP {status_code}) without an HTTPS redirect.",
            explanation=(
                "Traffic to the site is not upgraded to HTTPS, so data in transit can be "
                "read or modified on the network path."
            ),
            recommendation="Serve the site over HTTPS and redirect HTTP requests to it.",
        )
    return CheckFinding(
        title="Checked over HTTPS",
        category="transport",
        severity=Severity.INFORMATIONAL,
        evidence=f"{final_url} was reached directly over HTTPS (HTTP {status_code}).",
        explanation="The connection was encrypted, protecting data in transit.",
        recommendation="No change needed for this control.",
    )


def _network_error(exc: Exception) -> SafeInputError:
    if isinstance(exc, httpx.TimeoutException):
        return SafeInputError("The website did not respond in time. Try again later.")
    if isinstance(exc, httpx.ConnectError) and "certificate" in str(exc).lower():
        return SafeInputError("The website's TLS certificate could not be validated.")
    if isinstance(exc, httpx.ProtocolError):
        return SafeInputError("The website returned a malformed response.")
    return SafeInputError("The website could not be reached.")


def fetch_with_limits(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
    timeout: httpx.Timeout | None = None,
) -> tuple[str, int, httpx.Headers, list[str], bool]:
    """Bounded GET(s) with per-hop validation. Returns final response details.

    Returns (final_url, status_code, headers, redirect_chain, body_truncated).
    """
    timeout = timeout or httpx.Timeout(10.0, connect=5.0)
    resolve = resolver or DEFAULT_RESOLVER
    chain: list[str] = [url]
    current = url

    with httpx.Client(
        transport=transport,
        follow_redirects=False,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    ) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            current = resolve_and_validate_hop(current, resolver=resolve)
            try:
                with client.stream("GET", current) as response:
                    body_bytes = 0
                    truncated = False
                    for chunk in response.iter_bytes(chunk_size=4096):
                        body_bytes += len(chunk)
                        if body_bytes > MAX_RESPONSE_BYTES:
                            truncated = True
                            break
                    if response.is_redirect:
                        if len(chain) > MAX_REDIRECTS:
                            raise SafeInputError(
                                f"Too many redirects (more than {MAX_REDIRECTS})."
                            )
                        current = resolve_redirect(
                            response.headers.get("location", ""), current
                        )
                        chain.append(current)
                        continue
                    return (
                        current,
                        response.status_code,
                        response.headers,
                        chain,
                        truncated,
                    )
            except SafeInputError:
                raise
            except httpx.HTTPError as exc:
                raise _network_error(exc) from exc
    raise SafeInputError(f"Too many redirects (more than {MAX_REDIRECTS}).")


def check_website(
    raw_url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
    timeout: httpx.Timeout | None = None,
    min_interval: float = MIN_CHECK_INTERVAL_SECONDS,
) -> WebsiteCheckResult:
    """Run the full passive check for one URL. Raises SafeInputError on any
    unsafe, unreachable, or unsupported target — never performs a scan."""
    from app.services.input_safety import normalize_url

    requested = normalize_url(raw_url)
    _respect_rate_limit(min_interval)

    started = time.monotonic()
    final_url, status_code, headers, chain, truncated = fetch_with_limits(
        requested, transport=transport, resolver=resolver, timeout=timeout
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)

    https_used = final_url.startswith("https://")
    findings = [_https_finding(requested, final_url, status_code)]
    findings.extend(evaluate_headers(is_https=https_used, headers=headers))

    return WebsiteCheckResult(
        requested_url=requested,
        final_url=final_url,
        status_code=status_code,
        redirect_chain=chain,
        https_used=https_used,
        checked_at=utcnow(),
        findings=findings,
        response_truncated=truncated,
        elapsed_ms=elapsed_ms,
    )
