"""
Database configuration and session management for the Alert Triage Copilot.
"""

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from .models import Base

# Using SQLite for local persistent storage
DATABASE_URL = "sqlite:///triage_copilot.db"

# Create a synchronous engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Needed for SQLite in multi-thread context
    echo=False
)

# Create a sessionmaker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db() -> None:
    """Create all tables in the database if they don't exist."""
    Base.metadata.create_all(bind=engine)
    _migrate_triage_decision_cti_columns()


def _migrate_triage_decision_cti_columns() -> None:
    """Add CTI columns to existing SQLite databases without destructive migration."""
    inspector = inspect(engine)
    if "triage_decisions" not in inspector.get_table_names():
        return

    existing_columns = {
        column["name"] for column in inspector.get_columns("triage_decisions")
    }
    migrations = {
        "mitre_technique_id": "ALTER TABLE triage_decisions ADD COLUMN mitre_technique_id VARCHAR",
        "severity_justification": "ALTER TABLE triage_decisions ADD COLUMN severity_justification VARCHAR NOT NULL DEFAULT ''",
        "remediation_steps": "ALTER TABLE triage_decisions ADD COLUMN remediation_steps JSON",
    }
    with engine.begin() as connection:
        for column_name, statement in migrations.items():
            if column_name not in existing_columns:
                connection.execute(text(statement))

def get_db():
    """FastAPI Dependency to yield a database session and ensure it gets closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
