"""Standalone HTML report generation (PRD FR-10).

The report is a self-contained document (inline <style>, no external
resources) delivered as a download. It states scope, what was checked,
findings with evidence, the advisory disclaimer, and limitations — so it can
be shared as coursework evidence without PHANTOM running.

Served with Content-Disposition: attachment, so the app's strict CSP (which
forbids inline styles in *rendered app pages*) does not affect the downloaded
file opened from disk.
"""

from __future__ import annotations

import html
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import Analysis, Finding, FindingSource

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

TYPE_LABELS = {
    "website_check": "Website security configuration check",
    "code_review": "Source code security review",
    "log_analysis": "Security log analysis",
}

_SCOPE_NOTES = {
    "website_check": (
        "One bounded request per hop to the recorded target: response headers and HTTPS "
        "behaviour only. No port scanning, crawling, exploit execution, or repeated requests."
    ),
    "code_review": (
        "Deterministic pattern review of the submitted code as text. The code was never "
        "executed. Rules are starter-grade and do not track data flow across files."
    ),
    "log_analysis": (
        "Deterministic pattern review of the submitted log text as data. Logs were never "
        "sent anywhere by PHANTOM itself."
    ),
}

_LIMITATIONS = (
    "PHANTOM is an educational tool, not a professional audit. Findings may include false "
    "positives and miss real issues (false negatives). A result with no findings is not "
    "proof that the analysed target is secure. Severity labels are advisory defaults; assess "
    "them in the context of your system before acting.",
)

_PRIVACY_NOTE = (
    "By default PHANTOM stores no raw source code or raw log text. This report contains only "
    "short evidence excerpts shown in the app at analysis time, with secret-looking values masked."
)


def _severities(analysis: Analysis) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in analysis.findings:
        counts[finding.severity.value] += 1
    return counts


def generate_report(analysis: Analysis) -> str:
    """Render the standalone HTML report for one persisted analysis."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(
        analysis=analysis,
        type_label=TYPE_LABELS.get(analysis.analysis_type.value, "Analysis"),
        scope_note=_SCOPE_NOTES.get(analysis.analysis_type.value, ""),
        limitations=_LIMITATIONS,
        privacy_note=_PRIVACY_NOTE,
        severity_counts=_severities(analysis),
        ai_findings=[f for f in analysis.findings if f.source_type == FindingSource.AI_ASSISTED],
        rule_findings=[f for f in analysis.findings if f.source_type == FindingSource.RULE],
    )
