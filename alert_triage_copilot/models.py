"""
SQLAlchemy ORM Models for the Alert Triage Copilot.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Float, String, TypeDecorator
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import registry

from .schemas import Classification, Severity

mapper_registry = registry()
Base = mapper_registry.generate_base()


class ClassificationType(TypeDecorator):
    """Custom SQLAlchemy type for Classification enum."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return value.value if isinstance(value, Classification) else value
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return Classification(value)
        return None


class SeverityType(TypeDecorator):
    """Custom SQLAlchemy type for Severity enum."""
    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return value.value if isinstance(value, Severity) else value
        return None

    def process_result_value(self, value, dialect):
        if value is not None:
            return Severity(value)
        return None


class DBRawAlert(Base):
    """SQLAlchemy model for RawAlert."""
    __tablename__ = "raw_alerts"

    alert_id = Column(String, primary_key=True, default=lambda: f"ALERT-{uuid.uuid4().hex[:8].upper()}")
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    source = Column(String, nullable=False)
    severity = Column(SeverityType, nullable=False)
    alert_type = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)
    dest_ip = Column(String, default="10.0.1.100")
    description = Column(String, nullable=False)
    raw_payload = Column(JSON, default=dict)


class DBTriageDecision(Base):
    """SQLAlchemy model for TriageDecision."""
    __tablename__ = "triage_decisions"

    # We use a surrogate primary key here to allow multiple decisions for the same alert (e.g. Pass 1, Pass 2)
    id = Column(String, primary_key=True, default=lambda: uuid.uuid4().hex)
    alert_id = Column(String, nullable=False, index=True)
    classification = Column(ClassificationType, nullable=False)
    confidence = Column(Float, nullable=False)
    reasoning = Column(String, nullable=False)
    recommended_action = Column(String, nullable=False)
    mitre_tactics = Column(JSON, default=list)
    mitre_technique_id = Column(String, nullable=True)
    severity_justification = Column(String, nullable=False, default="")
    remediation_steps = Column(JSON, default=list)
    analyst_notes = Column(String, nullable=True)


class DBAnalystFeedback(Base):
    """SQLAlchemy model for AnalystFeedback."""
    __tablename__ = "analyst_feedback"

    id = Column(String, primary_key=True, default=lambda: uuid.uuid4().hex)
    alert_id = Column(String, nullable=False, index=True)
    original_classification = Column(ClassificationType, nullable=False)
    corrected_classification = Column(ClassificationType, nullable=False)
    analyst_id = Column(String, nullable=False)
    feedback_notes = Column(String, nullable=False)
    alert_type = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
