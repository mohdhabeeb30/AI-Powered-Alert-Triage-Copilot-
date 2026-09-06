"""
Human-in-the-Loop Feedback Store (Persistent).

Manages analyst overrides of LLM triage decisions and serves them
back as few-shot examples so the model self-corrects on similar
alerts in subsequent passes.

Now backed by a persistent SQLite database via SQLAlchemy.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import DBAnalystFeedback, DBRawAlert, DBTriageDecision
from .schemas import AnalystFeedback, Classification, RawAlert


class FeedbackStore:
    """
    Persistent feedback store that records analyst corrections and
    provides relevant few-shot examples for prompt augmentation.
    """

    def __init__(self, session: Session) -> None:
        """
        Initialize with a SQLAlchemy session.
        """
        self.session = session

    # ── Write Path ───────────────────────────────────────────────────

    def submit_feedback(
        self,
        alert: RawAlert,
        original_classification: Classification,
        corrected_classification: Classification,
        analyst_id: str,
        feedback_notes: str,
    ) -> AnalystFeedback:
        """
        Record an analyst's override of a triage decision.
        Also persists the raw alert if it isn't already in the DB.

        Args:
            alert: The original raw alert being corrected.
            original_classification: What the LLM originally decided.
            corrected_classification: What the analyst says is correct.
            analyst_id: Who is making the correction.
            feedback_notes: Rationale for the override.

        Returns:
            The created AnalystFeedback record.
        """
        # Save RawAlert if it doesn't exist
        existing_alert = self.session.query(DBRawAlert).filter_by(alert_id=alert.alert_id).first()
        if not existing_alert:
            db_alert = DBRawAlert(
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
            self.session.add(db_alert)

        db_feedback = DBAnalystFeedback(
            alert_id=alert.alert_id,
            original_classification=original_classification,
            corrected_classification=corrected_classification,
            analyst_id=analyst_id,
            feedback_notes=feedback_notes,
            alert_type=alert.alert_type,
            timestamp=datetime.now(timezone.utc),
        )

        self.session.add(db_feedback)
        self.session.commit()

        # We need to refresh to ensure the id is set
        self.session.refresh(db_feedback)

        return AnalystFeedback(
            alert_id=db_feedback.alert_id,
            original_classification=db_feedback.original_classification,
            corrected_classification=db_feedback.corrected_classification,
            analyst_id=db_feedback.analyst_id,
            feedback_notes=db_feedback.feedback_notes,
            alert_type=db_feedback.alert_type,
            timestamp=db_feedback.timestamp,
        )

    # ── Read Path ────────────────────────────────────────────────────

    def get_feedback(self, alert_id: str) -> Optional[AnalystFeedback]:
        """Retrieve the latest feedback for a specific alert, if it exists."""
        db_fb = (
            self.session.query(DBAnalystFeedback)
            .filter_by(alert_id=alert_id)
            .order_by(DBAnalystFeedback.timestamp.desc())
            .first()
        )
        if db_fb:
            return AnalystFeedback(
                alert_id=db_fb.alert_id,
                original_classification=db_fb.original_classification,
                corrected_classification=db_fb.corrected_classification,
                analyst_id=db_fb.analyst_id,
                feedback_notes=db_fb.feedback_notes,
                alert_type=db_fb.alert_type,
                timestamp=db_fb.timestamp,
            )
        return None

    def has_feedback(self, alert_id: str) -> bool:
        """Check whether an alert has been reviewed by an analyst."""
        count = self.session.query(DBAnalystFeedback).filter_by(alert_id=alert_id).count()
        return count > 0

    def get_relevant_examples(
        self,
        alert_type: str,
        n: int = 3,
    ) -> list[AnalystFeedback]:
        """
        Retrieve the N most recent analyst corrections for a given
        alert type. These serve as few-shot examples in the LLM prompt.

        Args:
            alert_type: Type of the incoming alert to match against.
            n: Maximum number of examples to return.

        Returns:
            List of relevant AnalystFeedback records, newest first.
        """
        records = (
            self.session.query(DBAnalystFeedback)
            .filter_by(alert_type=alert_type)
            .order_by(DBAnalystFeedback.timestamp.desc())
            .limit(n)
            .all()
        )
        return [
            AnalystFeedback(
                alert_id=r.alert_id,
                original_classification=r.original_classification,
                corrected_classification=r.corrected_classification,
                analyst_id=r.analyst_id,
                feedback_notes=r.feedback_notes,
                alert_type=r.alert_type,
                timestamp=r.timestamp,
            ) for r in records
        ]

    def get_all_feedback(self) -> list[AnalystFeedback]:
        """Return all feedback records."""
        records = self.session.query(DBAnalystFeedback).all()
        return [
            AnalystFeedback(
                alert_id=r.alert_id,
                original_classification=r.original_classification,
                corrected_classification=r.corrected_classification,
                analyst_id=r.analyst_id,
                feedback_notes=r.feedback_notes,
                alert_type=r.alert_type,
                timestamp=r.timestamp,
            ) for r in records
        ]

    # ── Stats ────────────────────────────────────────────────────────

    def get_correction_stats(self) -> dict:
        """
        Summary statistics about analyst corrections.

        Returns:
            Dict with total corrections, breakdown by original/corrected
            classification, and per-type counts.
        """
        total = self.session.query(DBAnalystFeedback).count()

        tp_to_fp = self.session.query(DBAnalystFeedback).filter(
            DBAnalystFeedback.original_classification == Classification.TRUE_POSITIVE,
            DBAnalystFeedback.corrected_classification == Classification.FALSE_POSITIVE
        ).count()

        fp_to_tp = self.session.query(DBAnalystFeedback).filter(
            DBAnalystFeedback.original_classification == Classification.FALSE_POSITIVE,
            DBAnalystFeedback.corrected_classification == Classification.TRUE_POSITIVE
        ).count()

        # Group by alert type
        type_counts_query = self.session.query(
            DBAnalystFeedback.alert_type,
            func.count(DBAnalystFeedback.id)
        ).group_by(DBAnalystFeedback.alert_type).all()

        type_counts = {item[0]: item[1] for item in type_counts_query}

        return {
            "total_corrections": total,
            "tp_to_fp_corrections": tp_to_fp,
            "fp_to_tp_corrections": fp_to_tp,
            "corrections_by_alert_type": type_counts,
        }

    def build_few_shot_prompt(self, alert_type: str) -> str:
        """
        Build a few-shot prompt section from analyst corrections.

        This is injected into the LLM system prompt so the model
        learns from past analyst overrides for this alert type.

        Returns:
            A formatted string of few-shot examples, or empty string
            if no relevant feedback exists.
        """
        examples = self.get_relevant_examples(alert_type)
        if not examples:
            return ""

        lines = [
            "\n── ANALYST CORRECTION HISTORY (Learn from these) ──"
        ]
        for i, ex in enumerate(examples, 1):
            lines.append(
                f"\n  Example {i}:\n"
                f"    Alert Type : {ex.alert_type}\n"
                f"    LLM Said   : {ex.original_classification.value}\n"
                f"    Analyst    : {ex.corrected_classification.value}\n"
                f"    Reason     : {ex.feedback_notes}\n"
                f"    ➤ CORRECT ANSWER: {ex.corrected_classification.value}"
            )
        lines.append(
            "\n── Apply these lessons to the current alert. ──\n"
        )
        return "\n".join(lines)

    def __len__(self) -> int:
        return self.session.query(DBAnalystFeedback).count()

    def __repr__(self) -> str:
        return f"FeedbackStore(records={len(self)}, corrections={len(self)})"
