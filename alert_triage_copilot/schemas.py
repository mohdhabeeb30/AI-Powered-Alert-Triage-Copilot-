"""
Pydantic Data Models for the Alert Triage Copilot.

Defines the canonical schemas for raw security alerts, triage decisions,
analyst feedback records, and evaluation metrics. All inter-module
communication flows through these typed contracts.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


# ──────────────────────────────────────────────────────────────────────
#  Enumerations
# ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Alert severity levels aligned with CVSS qualitative ratings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Classification(str, Enum):
    """Binary triage classification for a security alert."""
    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"


# ──────────────────────────────────────────────────────────────────────
#  Core Data Models
# ──────────────────────────────────────────────────────────────────────

class RawAlert(BaseModel):
    """
    A raw security alert as ingested from a SIEM, IDS/IPS, EDR, or
    cloud-native detection pipeline.

    This is the *immutable* input to the triage pipeline.
    """
    alert_id: str = Field(
        default_factory=lambda: f"ALERT-{uuid.uuid4().hex[:8].upper()}",
        description="Unique alert identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the alert was generated",
    )
    source: str = Field(
        ...,
        description="Detection source (e.g., 'Suricata IDS', 'CrowdStrike EDR', 'AWS GuardDuty')",
    )
    severity: Severity = Field(
        ...,
        description="Alert severity level",
    )
    alert_type: str = Field(
        ...,
        description="Category of the alert (e.g., 'Brute Force', 'Phishing', 'Port Scan')",
    )
    source_ip: str = Field(
        ...,
        description="Source IP address that triggered the alert",
    )
    dest_ip: str = Field(
        default="10.0.1.100",
        description="Destination IP address targeted by the activity",
    )
    description: str = Field(
        ...,
        description="Human-readable description of the detected activity",
    )
    raw_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw detection metadata (signatures, packet info, log lines)",
    )

    def to_prompt_context(self) -> str:
        """Serialize the alert into a structured text block for LLM consumption."""
        return (
            f"━━━ SECURITY ALERT ━━━\n"
            f"  Alert ID   : {self.alert_id}\n"
            f"  Timestamp  : {self.timestamp.isoformat()}\n"
            f"  Source      : {self.source}\n"
            f"  Severity   : {self.severity.value.upper()}\n"
            f"  Type        : {self.alert_type}\n"
            f"  Source IP   : {self.source_ip}\n"
            f"  Dest IP     : {self.dest_ip}\n"
            f"  Description : {self.description}\n"
            f"  Payload     : {self.raw_payload}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━"
        )


class TriageDecision(BaseModel):
    """
    The structured output of the LLM triage agent for a single alert.

    Contains the classification, confidence score, reasoning chain,
    and recommended SOC response action.
    """
    alert_id: str = Field(
        ...,
        description="References the RawAlert.alert_id being triaged",
    )
    classification: Classification = Field(
        ...,
        description="Binary classification: TP (True Positive) or FP (False Positive)",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model confidence in the classification (0.0 to 1.0)",
    )
    reasoning: str = Field(
        ...,
        description="Step-by-step reasoning chain justifying the classification",
    )
    recommended_action: str = Field(
        ...,
        description="Recommended SOC action (e.g., 'Escalate to IR', 'Suppress', 'Monitor')",
    )
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK tactics (e.g., ['TA0006 - Credential Access'])",
    )
    mitre_technique_id: Optional[str] = Field(
        default=None,
        description="Primary MITRE ATT&CK technique ID, required for true positives",
    )
    severity_justification: str = Field(
        default="",
        description="Evidence-based explanation for the alert severity",
    )
    remediation_steps: list[str] = Field(
        default_factory=list,
        description="Exactly three immediate SOC remediation steps for true positives",
    )
    analyst_notes: Optional[str] = Field(
        default=None,
        description="Optional notes from human analyst review",
    )

    @model_validator(mode="after")
    def validate_threat_intelligence_mapping(self) -> "TriageDecision":
        """Require complete CTI enrichment whenever an alert is a threat."""
        if self.classification == Classification.TRUE_POSITIVE:
            if not self.mitre_technique_id or not self.mitre_technique_id.strip():
                raise ValueError("True positives require a MITRE ATT&CK technique ID")
            if not self.severity_justification.strip():
                raise ValueError("True positives require a severity justification")
            if len(self.remediation_steps) != 3 or any(
                not step.strip() for step in self.remediation_steps
            ):
                raise ValueError("True positives require exactly three remediation steps")
        return self


class AnalystFeedback(BaseModel):
    """
    A human analyst's override of an LLM triage decision.

    Feeds back into the few-shot store so the model self-corrects
    on similar alerts in subsequent passes.
    """
    alert_id: str = Field(
        ...,
        description="The alert whose classification is being corrected",
    )
    original_classification: Classification = Field(
        ...,
        description="The LLM's original classification",
    )
    corrected_classification: Classification = Field(
        ...,
        description="The analyst's corrected classification",
    )
    analyst_id: str = Field(
        ...,
        description="Identifier of the reviewing analyst (e.g., 'soc-analyst-42')",
    )
    feedback_notes: str = Field(
        ...,
        description="Analyst rationale for the correction",
    )
    alert_type: str = Field(
        default="",
        description="Alert type for few-shot matching",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the feedback was submitted",
    )


class AnalystFeedbackRequest(BaseModel):
    """Input payload for submitting analyst feedback via API."""
    alert_id: str = Field(..., description="The ID of the alert being corrected")
    original_classification: Classification = Field(..., description="What the system originally decided")
    corrected_classification: Classification = Field(..., description="The analyst's corrected decision")
    analyst_id: str = Field(..., description="ID of the analyst making the correction")
    feedback_notes: str = Field(..., description="Reasoning for the override")


class EvaluationMetrics(BaseModel):
    """
    Aggregate performance metrics for a triage evaluation run.

    Treats TRUE_POSITIVE as the positive class for Precision/Recall.
    """
    total_alerts: int = Field(..., description="Total alerts evaluated")
    true_positives: int = Field(..., description="Correctly identified real threats (TP→TP)")
    false_positives: int = Field(..., description="Benign alerts misclassified as threats (FP→TP)")
    true_negatives: int = Field(..., description="Correctly identified benign alerts (FP→FP)")
    false_negatives: int = Field(..., description="Real threats missed (TP→FP)")
    precision: float = Field(..., description="TP / (TP + FP) — threat classification accuracy")
    recall: float = Field(..., description="TP / (TP + FN) — threat detection completeness")
    f1_score: float = Field(..., description="Harmonic mean of Precision and Recall")
    deflection_rate: float = Field(
        ...,
        description="% of actual false-positive alerts correctly deflected (TN / (TN + FP))",
    )
