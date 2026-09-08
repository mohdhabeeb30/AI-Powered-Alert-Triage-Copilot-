"""
Async Classification & Triage Engine.

Orchestrates alert triage by invoking the ADK agent (live or mock)
for individual or batch classification, with feedback-enhanced
prompt construction.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .agent import invoke_live_agent, mock_classify
from .db import SessionLocal
from .feedback_loop import FeedbackStore
from .models import DBTriageDecision
from .schemas import RawAlert, TriageDecision


# ──────────────────────────────────────────────────────────────────────
#  Single Alert Triage
# ──────────────────────────────────────────────────────────────────────

async def triage_single_alert(
    alert: RawAlert,
    feedback_store: Optional[FeedbackStore] = None,
    live_mode: bool = False,
) -> TriageDecision:
    """
    Classify a single security alert as TP or FP.

    Args:
        alert: The raw security alert to triage.
        feedback_store: Optional feedback store for few-shot learning.
        live_mode: If True, uses live Gemini API. If False, uses mock.

    Returns:
        A structured TriageDecision with classification, confidence,
        reasoning, recommended action, and MITRE ATT&CK tactics.
    """
    if live_mode:
        decision = await invoke_live_agent(alert, feedback_store)
    else:
        # Mock classifier runs synchronously, wrap for async interface
        decision = mock_classify(alert, feedback_store)

    # Persist the decision to the database
    with SessionLocal() as session:
        db_decision = DBTriageDecision(
            alert_id=decision.alert_id,
            classification=decision.classification,
            confidence=decision.confidence,
            reasoning=decision.reasoning,
            recommended_action=decision.recommended_action,
            mitre_tactics=decision.mitre_tactics,
            mitre_technique_id=decision.mitre_technique_id,
            severity_justification=decision.severity_justification,
            remediation_steps=decision.remediation_steps,
            analyst_notes=decision.analyst_notes,
        )
        session.add(db_decision)
        session.commit()

    return decision


# ──────────────────────────────────────────────────────────────────────
#  Batch Triage with Concurrency Control
# ──────────────────────────────────────────────────────────────────────

async def triage_batch(
    alerts: list[RawAlert],
    feedback_store: Optional[FeedbackStore] = None,
    live_mode: bool = False,
    max_concurrency: int = 5,
) -> list[TriageDecision]:
    """
    Triage a batch of alerts with controlled concurrency.

    Uses asyncio.Semaphore to limit parallel LLM calls and prevent
    rate-limit errors in live mode.

    Args:
        alerts: List of raw alerts to classify.
        feedback_store: Optional feedback store for few-shot learning.
        live_mode: If True, uses live Gemini API.
        max_concurrency: Max parallel classifications (default 5).

    Returns:
        List of TriageDecisions, one per input alert (order preserved).
    """
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _guarded_triage(alert: RawAlert) -> TriageDecision:
        async with semaphore:
            return await triage_single_alert(
                alert,
                feedback_store=feedback_store,
                live_mode=live_mode,
            )

    # Launch all tasks concurrently (bounded by semaphore)
    tasks = [_guarded_triage(alert) for alert in alerts]
    results = await asyncio.gather(*tasks)

    return list(results)


# ──────────────────────────────────────────────────────────────────────
#  Triage with Feedback Enhancement
# ──────────────────────────────────────────────────────────────────────

async def triage_with_feedback(
    alerts: list[RawAlert],
    feedback_store: FeedbackStore,
    live_mode: bool = False,
) -> list[TriageDecision]:
    """
    Triage alerts with feedback-enhanced classification.

    This is the primary entry point for re-triage passes. It:
    1. Queries the feedback store for relevant analyst corrections
    2. Injects few-shot examples into the classification context
    3. Returns improved classifications

    Args:
        alerts: Alerts to re-classify.
        feedback_store: Store containing analyst corrections.
        live_mode: If True, uses live Gemini API.

    Returns:
        List of improved TriageDecisions.
    """
    return await triage_batch(
        alerts,
        feedback_store=feedback_store,
        live_mode=live_mode,
    )
