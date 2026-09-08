"""FastAPI application for the AI-powered alert triage copilot."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from .agent import get_triage_decision
from .db import get_db, init_db
from .evaluation import evaluate
from .feedback_loop import FeedbackStore
from .models import DBAnalystFeedback, DBRawAlert, DBTriageDecision
from .schemas import AnalystFeedback, EvaluationMetrics, RawAlert, TriageDecision

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("triage_copilot.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize persistent storage before serving requests."""
    logger.info("Initializing triage database")
    init_db()
    yield
    logger.info("Shutting down alert triage API")


app = FastAPI(
    title="AI-Powered Alert Triage Copilot",
    description="REST API for Google ADK 2.0 security alert classification.",
    version="1.0.0",
    lifespan=lifespan,
)

configured_origins = [
    origin.strip()
    for origin in os.getenv("TRIAGE_CORS_ORIGINS", "*").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins,
    allow_credentials="*" not in configured_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return a stable 422 response for invalid API payloads."""
    logger.warning("Validation failed for %s: %s", request.url.path, exc.errors())
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed", "errors": exc.errors()},
    )


def _save_raw_alert(db: Session, alert: RawAlert) -> None:
    """Persist an alert once, preserving the original ingestion record."""
    if db.query(DBRawAlert).filter_by(alert_id=alert.alert_id).first():
        return
    db.add(
        DBRawAlert(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp,
            source=alert.source,
            severity=alert.severity,
            alert_type=alert.alert_type,
            source_ip=alert.source_ip,
            dest_ip=alert.dest_ip,
            description=alert.description,
            raw_payload=alert.raw_payload,
        )
    )


def _save_decision(db: Session, decision: TriageDecision) -> None:
    """Append a triage result to the historical decision log."""
    db.add(
        DBTriageDecision(
            alert_id=decision.alert_id,
            classification=decision.classification,
            confidence=decision.confidence,
            reasoning=decision.reasoning,
            recommended_action=decision.recommended_action,
            mitre_tactics=decision.mitre_tactics,
            mitre_technique_id=decision.mitre_technique_id,
            severity_justification=decision.severity_justification,
            remediation_steps=decision.remediation_steps or [],
            analyst_notes=decision.analyst_notes,
        )
    )


def _to_raw_alert(db_alert: DBRawAlert) -> RawAlert:
    """Convert the persisted ORM record back to the validated API schema."""
    return RawAlert(
        alert_id=db_alert.alert_id,
        timestamp=db_alert.timestamp,
        source=db_alert.source,
        severity=db_alert.severity,
        alert_type=db_alert.alert_type,
        source_ip=db_alert.source_ip,
        dest_ip=db_alert.dest_ip,
        description=db_alert.description,
        raw_payload=db_alert.raw_payload or {},
    )


@app.post("/api/v1/alerts/triage", response_model=TriageDecision)
async def triage_alert(
    alert: RawAlert,
    live: bool = Query(False, description="Use Gemini through Google ADK when available."),
    db: Session = Depends(get_db),
) -> TriageDecision:
    """Ingest, classify, and persist one security alert."""
    logger.info("Triage requested for alert_id=%s live=%s", alert.alert_id, live)
    try:
        _save_raw_alert(db, alert)
        feedbacks = FeedbackStore(db).get_relevant_examples(alert.alert_type)
        decision = await get_triage_decision(alert, feedbacks, use_live_llm=live)
        _save_decision(db, decision)
        db.commit()
        logger.info(
            "Triage completed for alert_id=%s classification=%s",
            alert.alert_id,
            decision.classification.value,
        )
        return decision
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("Triage failed for alert_id=%s: %s", alert.alert_id, exc)
        raise HTTPException(status_code=500, detail="Alert triage failed.") from exc


@app.post("/api/v1/feedback", response_model=AnalystFeedback)
async def submit_feedback(
    feedback: AnalystFeedback,
    db: Session = Depends(get_db),
) -> AnalystFeedback:
    """Persist an analyst correction for a previously triaged alert."""
    logger.info("Feedback received for alert_id=%s", feedback.alert_id)
    stored_alert = db.query(DBRawAlert).filter_by(alert_id=feedback.alert_id).first()
    if stored_alert is None:
        raise HTTPException(status_code=404, detail="Alert ID not found.")

    latest_decision = (
        db.query(DBTriageDecision)
        .filter_by(alert_id=feedback.alert_id)
        .order_by(DBTriageDecision.id.desc())
        .first()
    )
    if latest_decision is None:
        raise HTTPException(status_code=422, detail="Alert has no triage decision to correct.")
    if feedback.original_classification != latest_decision.classification:
        raise HTTPException(
            status_code=422,
            detail="original_classification does not match the latest triage decision.",
        )

    try:
        persisted_feedback = FeedbackStore(db).submit_feedback(
            alert=_to_raw_alert(stored_alert),
            original_classification=feedback.original_classification,
            corrected_classification=feedback.corrected_classification,
            analyst_id=feedback.analyst_id,
            feedback_notes=feedback.feedback_notes,
        )
        logger.info("Feedback stored for alert_id=%s", feedback.alert_id)
        return persisted_feedback
    except Exception as exc:
        db.rollback()
        logger.exception("Feedback persistence failed for alert_id=%s", feedback.alert_id)
        raise HTTPException(status_code=500, detail="Failed to store feedback.") from exc


@app.get("/api/v1/metrics", response_model=EvaluationMetrics)
async def get_metrics(db: Session = Depends(get_db)) -> EvaluationMetrics:
    """Compute live metrics for historical decisions with analyst labels."""
    latest_feedback = (
        db.query(
            DBAnalystFeedback.alert_id,
            func.max(DBAnalystFeedback.timestamp).label("latest_timestamp"),
        )
        .group_by(DBAnalystFeedback.alert_id)
        .subquery()
    )
    labeled_rows = (
        db.query(DBTriageDecision, DBAnalystFeedback)
        .join(
            latest_feedback,
            DBTriageDecision.alert_id == latest_feedback.c.alert_id,
        )
        .join(
            DBAnalystFeedback,
            and_(
                DBAnalystFeedback.alert_id == latest_feedback.c.alert_id,
                DBAnalystFeedback.timestamp == latest_feedback.c.latest_timestamp,
            ),
        )
        .all()
    )

    decisions = [
        TriageDecision(
            alert_id=decision.alert_id,
            classification=decision.classification,
            confidence=decision.confidence,
            reasoning=decision.reasoning,
            recommended_action=decision.recommended_action,
            mitre_tactics=decision.mitre_tactics or [],
            mitre_technique_id=(
                decision.mitre_technique_id
                or ("T1595" if decision.classification.value == "TP" else None)
            ),
            severity_justification=(
                decision.severity_justification
                or (
                    "Legacy TP record retained for historical metrics; review "
                    "the original alert evidence for current CTI enrichment."
                    if decision.classification.value == "TP" else ""
                )
            ),
            remediation_steps=(
                decision.remediation_steps
                or (
                    [
                        "Review the original alert and confirm the CTI mapping.",
                        "Preserve the associated logs and decision evidence.",
                        "Update the record with current analyst remediation actions.",
                    ]
                    if decision.classification.value == "TP" else []
                )
            ),
            analyst_notes=decision.analyst_notes,
        )
        for decision, _ in labeled_rows
    ]
    ground_truth = {
        feedback.alert_id: feedback.corrected_classification
        for _, feedback in labeled_rows
    }
    metrics = evaluate(decisions, ground_truth)
    logger.info("Metrics calculated for %d labeled decisions", len(decisions))
    return metrics


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "service": "alert-triage-copilot"}
