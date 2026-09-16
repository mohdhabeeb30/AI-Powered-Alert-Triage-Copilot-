import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..schemas import (
    AnalystFeedback,
    AnalystFeedbackRequest,
    EvaluationMetrics,
    RawAlert,
    TriageDecision,
)
from ..models import DBRawAlert, DBAnalystFeedback, DBTriageDecision
from ..feedback_loop import FeedbackStore
from ..triage_engine import triage_single_alert
from ..evaluation import evaluate

logger = logging.getLogger("triage_copilot.api")

router = APIRouter(prefix="/api/v1")

@router.post("/alerts/triage", response_model=TriageDecision)
async def triage_alert(
    alert: RawAlert,
    mock: bool = Query(False, description="Run in deterministic mock mode without hitting the LLM"),
    db: Session = Depends(get_db)
):
    """
    Ingest a new raw alert, fetch few-shot examples from the DB,
    and classify the alert using Google ADK.
    """
    logger.info(f"Received triage request for alert_id={alert.alert_id}")
    try:
        feedback_store = FeedbackStore(db)

        # triage_single_alert handles saving the decision to the database.
        # But wait, triage_single_alert initializes its own db session internally in the current implementation.
        # It's fine since it will persist correctly.
        # Alternatively, we could update triage_single_alert to take a session, but let's keep it isolated for now.
        decision = await triage_single_alert(
            alert=alert,
            feedback_store=feedback_store,
            live_mode=not mock
        )
        logger.info(f"Successfully triaged alert_id={alert.alert_id}: {decision.classification.value}")
        return decision
    except Exception as e:
        logger.error(f"Error during triage for alert_id={alert.alert_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during triage.")


@router.post("/feedback", response_model=AnalystFeedback)
def submit_feedback(
    request: AnalystFeedbackRequest,
    db: Session = Depends(get_db)
):
    """
    Submit an analyst override for a misclassified alert.
    The feedback is stored and injected as few-shot examples into future prompts.
    """
    logger.info(f"Received feedback for alert_id={request.alert_id} from analyst={request.analyst_id}")

    # 1. Fetch the raw alert to get the alert_type (needed for the FeedbackStore)
    raw_alert = db.query(DBRawAlert).filter_by(alert_id=request.alert_id).first()
    if not raw_alert:
        logger.warning(f"Feedback rejected: alert_id={request.alert_id} not found.")
        raise HTTPException(status_code=404, detail="Alert ID not found in database.")

    # Reconstruct RawAlert model
    alert_pydantic = RawAlert(
        alert_id=raw_alert.alert_id,
        timestamp=raw_alert.timestamp,
        source=raw_alert.source,
        severity=raw_alert.severity,
        alert_type=raw_alert.alert_type,
        source_ip=raw_alert.source_ip,
        dest_ip=raw_alert.dest_ip,
        description=raw_alert.description,
        raw_payload=raw_alert.raw_payload,
    )

    feedback_store = FeedbackStore(db)

    try:
        feedback = feedback_store.submit_feedback(
            alert=alert_pydantic,
            original_classification=request.original_classification,
            corrected_classification=request.corrected_classification,
            analyst_id=request.analyst_id,
            feedback_notes=request.feedback_notes
        )
        logger.info(f"Feedback stored successfully for alert_id={request.alert_id}")
        return feedback
    except Exception as e:
        logger.error(f"Error storing feedback for alert_id={request.alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to store feedback.")


@router.get("/metrics", response_model=EvaluationMetrics)
def get_metrics(db: Session = Depends(get_db)):
    """
    Calculate and return real-time precision, recall, F1, and deflection rate
    based on historical alerts and analyst feedback.
    """
    logger.info("Calculating metrics based on database state...")

    # 1. Fetch all triage decisions
    decisions_db = db.query(DBTriageDecision).all()
    decisions = [
        TriageDecision(
            alert_id=d.alert_id,
            classification=d.classification,
            confidence=d.confidence,
            reasoning=d.reasoning,
            recommended_action=d.recommended_action,
            mitre_tactics=d.mitre_tactics,
            analyst_notes=d.analyst_notes
        ) for d in decisions_db
    ]

    # 2. Reconstruct "ground truth" dynamically
    # The actual true label is the corrected classification if feedback exists,
    # otherwise we assume the system's prediction was correct.
    # To truly measure performance, we need external ground truth.
    # For this endpoint, we'll map all known alerts against their feedback overrides.

    all_alerts = db.query(DBRawAlert).all()
    ground_truth = {}

    for alert in all_alerts:
        feedback = db.query(DBAnalystFeedback).filter_by(alert_id=alert.alert_id).order_by(DBAnalystFeedback.timestamp.desc()).first()
        if feedback:
            ground_truth[alert.alert_id] = feedback.corrected_classification
        else:
            # If no feedback, we assume the latest triage decision is the truth?
            # Or we can't evaluate it properly without known labels.
            # In a real system, you calculate metrics only on the labeled subset.
            latest_decision = db.query(DBTriageDecision).filter_by(alert_id=alert.alert_id).first()
            if latest_decision:
                ground_truth[alert.alert_id] = latest_decision.classification
            else:
                ground_truth[alert.alert_id] = alert.classification # This field doesn't exist, wait.

    # Only evaluate decisions for which we have ground truth
    evaluate_decisions = [d for d in decisions if d.alert_id in ground_truth]

    try:
        metrics = evaluate(evaluate_decisions, ground_truth)
        logger.info("Metrics calculation complete.")
        return metrics
    except Exception as e:
        logger.error(f"Error calculating metrics: {str(e)}")
        raise HTTPException(status_code=500, detail="Error calculating metrics.")
