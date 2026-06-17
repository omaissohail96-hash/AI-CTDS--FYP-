from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from src.core.config import settings
from src.models.models import Base

# For SQLite, we need connect_args={"check_same_thread": False}
if settings.DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        settings.DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(settings.DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def initialize_database():
    Base.metadata.create_all(bind=engine)
    _ensure_scan_history_schema()
    _ensure_uba_schema()


def _ensure_scan_history_schema():
    inspector = inspect(engine)
    if "scan_history" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("scan_history")}
    column_ddl = {
        "entities": "ALTER TABLE scan_history ADD COLUMN entities JSON",
        "attack_type": "ALTER TABLE scan_history ADD COLUMN attack_type VARCHAR",
        "severity": "ALTER TABLE scan_history ADD COLUMN severity VARCHAR",
        "ml_confidence": "ALTER TABLE scan_history ADD COLUMN ml_confidence INTEGER DEFAULT 0",
        "intelligence_hit": "ALTER TABLE scan_history ADD COLUMN intelligence_hit BOOLEAN DEFAULT 0",
        "correlation_hit": "ALTER TABLE scan_history ADD COLUMN correlation_hit BOOLEAN DEFAULT 0",
        "prevention_triggered": "ALTER TABLE scan_history ADD COLUMN prevention_triggered BOOLEAN DEFAULT 0",
        "explanation": "ALTER TABLE scan_history ADD COLUMN explanation JSON",
        "mitre_mappings": "ALTER TABLE scan_history ADD COLUMN mitre_mappings JSON",
    }

    with engine.begin() as connection:
        for column_name, ddl in column_ddl.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))

        existing_indexes = {index["name"] for index in inspector.get_indexes("scan_history")}
        index_ddl = {
            "ix_scan_history_workspace_created": "CREATE INDEX ix_scan_history_workspace_created ON scan_history (workspace_id, created_at)",
            "ix_scan_history_workspace_verdict": "CREATE INDEX ix_scan_history_workspace_verdict ON scan_history (workspace_id, verdict)",
            "ix_scan_history_workspace_attack_type": "CREATE INDEX ix_scan_history_workspace_attack_type ON scan_history (workspace_id, attack_type)",
            "ix_scan_history_workspace_entity": "CREATE INDEX ix_scan_history_workspace_entity ON scan_history (workspace_id, entity)",
            "ix_scan_history_workspace_severity": "CREATE INDEX ix_scan_history_workspace_severity ON scan_history (workspace_id, severity)",
        }
        for index_name, ddl in index_ddl.items():
            if index_name not in existing_indexes:
                connection.execute(text(ddl))


def _ensure_uba_schema():
    inspector = inspect(engine)
    if "user_behavior_events" not in inspector.get_table_names():
        return

    existing_event_columns = {
        column["name"] for column in inspector.get_columns("user_behavior_events")
    }
    event_column_ddl = {
        "explanation": "ALTER TABLE user_behavior_events ADD COLUMN explanation JSON",
    }

    with engine.begin() as connection:
        for column_name, ddl in event_column_ddl.items():
            if column_name not in existing_event_columns:
                connection.execute(text(ddl))

        existing_event_indexes = {
            index["name"] for index in inspector.get_indexes("user_behavior_events")
        }
        event_index_ddl = {
            "ix_uba_event_workspace_timestamp": "CREATE INDEX ix_uba_event_workspace_timestamp ON user_behavior_events (workspace_id, timestamp)",
            "ix_uba_event_workspace_user": "CREATE INDEX ix_uba_event_workspace_user ON user_behavior_events (workspace_id, user_id)",
            "ix_uba_event_workspace_type": "CREATE INDEX ix_uba_event_workspace_type ON user_behavior_events (workspace_id, event_type)",
            "ix_uba_event_workspace_risk": "CREATE INDEX ix_uba_event_workspace_risk ON user_behavior_events (workspace_id, risk_level)",
        }
        for index_name, ddl in event_index_ddl.items():
            if index_name not in existing_event_indexes:
                connection.execute(text(ddl))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
