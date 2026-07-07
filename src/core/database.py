from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from src.core.config import settings
from src.models.models import Base

# ── Engine setup ──────────────────────────────────────────────────────────────
_pool_kwargs = {}
if not settings.DATABASE_URL.startswith("sqlite"):
    _pool_kwargs = {
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_pre_ping": settings.DB_POOL_PRE_PING,
    }

if settings.DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(settings.DATABASE_URL, **_pool_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def initialize_database():
    """Create all tables and apply incremental schema migrations."""
    Base.metadata.create_all(bind=engine)
    _ensure_scan_history_schema()
    _ensure_uba_schema()
    _ensure_enterprise_schema()


def _ensure_scan_history_schema():
    inspector = inspect(engine)
    if "scan_history" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("scan_history")}
    column_ddl = {
        "entities":             "ALTER TABLE scan_history ADD COLUMN entities JSON",
        "attack_type":          "ALTER TABLE scan_history ADD COLUMN attack_type VARCHAR",
        "severity":             "ALTER TABLE scan_history ADD COLUMN severity VARCHAR",
        "ml_confidence":        "ALTER TABLE scan_history ADD COLUMN ml_confidence INTEGER DEFAULT 0",
        "intelligence_hit":     "ALTER TABLE scan_history ADD COLUMN intelligence_hit BOOLEAN DEFAULT 0",
        "correlation_hit":      "ALTER TABLE scan_history ADD COLUMN correlation_hit BOOLEAN DEFAULT 0",
        "prevention_triggered": "ALTER TABLE scan_history ADD COLUMN prevention_triggered BOOLEAN DEFAULT 0",
        "explanation":          "ALTER TABLE scan_history ADD COLUMN explanation JSON",
        "mitre_mappings":       "ALTER TABLE scan_history ADD COLUMN mitre_mappings JSON",
        "risk_contributions":   "ALTER TABLE scan_history ADD COLUMN risk_contributions JSON",
    }

    with engine.begin() as connection:
        for column_name, ddl in column_ddl.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))

        existing_indexes = {index["name"] for index in inspector.get_indexes("scan_history")}
        index_ddl = {
            "ix_scan_history_workspace_created":     "CREATE INDEX ix_scan_history_workspace_created ON scan_history (workspace_id, created_at)",
            "ix_scan_history_workspace_verdict":     "CREATE INDEX ix_scan_history_workspace_verdict ON scan_history (workspace_id, verdict)",
            "ix_scan_history_workspace_attack_type": "CREATE INDEX ix_scan_history_workspace_attack_type ON scan_history (workspace_id, attack_type)",
            "ix_scan_history_workspace_entity":      "CREATE INDEX ix_scan_history_workspace_entity ON scan_history (workspace_id, entity)",
            "ix_scan_history_workspace_severity":    "CREATE INDEX ix_scan_history_workspace_severity ON scan_history (workspace_id, severity)",
        }
        for index_name, ddl in index_ddl.items():
            if index_name not in existing_indexes:
                try:
                    connection.execute(text(ddl))
                except Exception:
                    pass  # Index may already exist under a different name


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
            "ix_uba_event_workspace_user":      "CREATE INDEX ix_uba_event_workspace_user ON user_behavior_events (workspace_id, user_id)",
            "ix_uba_event_workspace_type":      "CREATE INDEX ix_uba_event_workspace_type ON user_behavior_events (workspace_id, event_type)",
            "ix_uba_event_workspace_risk":      "CREATE INDEX ix_uba_event_workspace_risk ON user_behavior_events (workspace_id, risk_level)",
        }
        for index_name, ddl in event_index_ddl.items():
            if index_name not in existing_event_indexes:
                try:
                    connection.execute(text(ddl))
                except Exception:
                    pass


def _ensure_enterprise_schema():
    """Apply v2.2.0 enterprise upgrade columns (idempotent)."""
    inspector = inspect(engine)

    with engine.begin() as connection:
        # users.refresh_token_version
        if "users" in inspector.get_table_names():
            existing = {c["name"] for c in inspector.get_columns("users")}
            if "refresh_token_version" not in existing:
                connection.execute(text(
                    "ALTER TABLE users ADD COLUMN refresh_token_version INTEGER DEFAULT 0"
                ))

        # alerts: new columns
        if "alerts" in inspector.get_table_names():
            existing = {c["name"] for c in inspector.get_columns("alerts")}
            for col, ddl in [
                ("risk_contributions",      "ALTER TABLE alerts ADD COLUMN risk_contributions JSON"),
                ("false_positive_reported", "ALTER TABLE alerts ADD COLUMN false_positive_reported BOOLEAN DEFAULT 0"),
                ("in_review_queue",         "ALTER TABLE alerts ADD COLUMN in_review_queue BOOLEAN DEFAULT 0"),
            ]:
                if col not in existing:
                    connection.execute(text(ddl))

        # AuditLog indexes
        if "audit_logs" in inspector.get_table_names():
            existing_idx = {i["name"] for i in inspector.get_indexes("audit_logs")}
            for idx_name, ddl in [
                ("ix_audit_workspace_created", "CREATE INDEX ix_audit_workspace_created ON audit_logs (workspace_id, created_at)"),
                ("ix_audit_action_created",    "CREATE INDEX ix_audit_action_created ON audit_logs (action, created_at)"),
            ]:
                if idx_name not in existing_idx:
                    try:
                        connection.execute(text(ddl))
                    except Exception:
                        pass

        # ThreatIntel covering index
        if "threat_intel" in inspector.get_table_names():
            existing_idx = {i["name"] for i in inspector.get_indexes("threat_intel")}
            if "ix_threat_intel_active" not in existing_idx:
                try:
                    connection.execute(text(
                        "CREATE INDEX ix_threat_intel_active ON threat_intel (entity_value, is_active)"
                    ))
                except Exception:
                    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
