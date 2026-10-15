"""Consent-gated AI assist shared by the code-review and log-analysis routes.

Contract with the routes:
1. Deterministic analysis always runs first and is always rendered.
2. AI is only attempted when configured (provider + model + key present) AND
   the user ticked the consent checkbox for THIS submission.
3. The content handed to the provider is the masked/redacted text from the
   analysis services — the same bytes the user sees on screen.
4. Any provider or validation failure downgrades gracefully: deterministic
   results render with a warning banner. AI output, when valid, renders in a
   clearly-labelled separate section — never merged into the deterministic
   findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.services.ai_provider import (
    AIAnalysis,
    AIProviderError,
    AIRequest,
    AIResponseValidationError,
    build_provider_from_settings,
)

logger = logging.getLogger(__name__)


@dataclass
class AIAssistOutcome:
    ai_analysis: AIAnalysis | None = None
    error: str | None = None  # safe, user-facing reason when AI failed
    consent_recorded: bool = False
    disclosure: str = ""  # what was sent, shown with results


def _disclosure(provider_name: str, model: str, chars: int) -> str:
    return (
        f"With your consent, the masked text ({chars:,} characters) and a summary of the "
        f"deterministic findings were sent to the hosted AI provider '{provider_name}' "
        f"(model {model}) for interpretation. No API keys were sent. Results below are "
        "AI-assisted and require human verification."
    )


def run_ai_assist(
    *,
    settings,
    task: str,
    consented: bool,
    content: str,
    deterministic_summary: str,
    target_label: str,
) -> AIAssistOutcome:
    """Attempt the AI-assisted interpretation, honouring the consent gate."""
    outcome = AIAssistOutcome()

    if not consented:
        return outcome
    outcome.consent_recorded = True

    provider = build_provider_from_settings(settings)
    if provider is None:
        outcome.error = (
            "AI assistance was requested but is not configured on this instance "
            "(missing provider or API key). Deterministic results are shown."
        )
        return outcome

    chars = len(content)
    request = AIRequest(
        task=task,
        content=content,
        deterministic_summary=deterministic_summary,
        target_label=target_label,
    )
    try:
        analysis = provider.complete(request)
    except AIResponseValidationError:
        logger.info("AI assist for %s returned a malformed response; falling back.", task)
        outcome.error = (
            "The AI response could not be validated, so it was discarded. "
            "Deterministic results are shown."
        )
        return outcome
    except AIProviderError as exc:
        logger.info("AI assist for %s failed: %s", task, exc)
        outcome.error = f"{exc} Deterministic results are shown."
        return outcome
    except Exception:
        logger.exception("AI assist failed unexpectedly")
        outcome.error = (
            "AI assistance failed unexpectedly. Deterministic results are shown."
        )
        return outcome

    outcome.ai_analysis = analysis
    outcome.disclosure = _disclosure(analysis.provider_name, analysis.model, chars)
    return outcome
