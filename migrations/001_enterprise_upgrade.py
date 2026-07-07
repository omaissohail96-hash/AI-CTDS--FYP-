"""
Database migration 001: Enterprise Upgrade for CyberGuard AI.

Adds new tables and columns introduced in v2.2.0 without destroying
any existing data. Safe to run multiple times (idempotent).

Usage:
    python migrations/001_enterprise_upgrade.py upgrade
    python migrations/001_enterprise_upgrade.py downgrade
"""

import sys
import os

# Allow running from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, inspect, text
from src.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    **({"connect_args": {"check_same_thread": False}} if settings.DATABASE_URL.startswith("sqlite") else {})
)

IS_SQLITE = settings.DATABASE_URL.startswith("sqlite")
IS_POSTGRES = settings.DATABASE_URL.startswith("postgresql") or settings.DATABASE_URL.startswith("postgres")


def _column_exists(inspector, table: str, column: str) -> bool:
    try:
        cols = {c["name"] for c in inspector.get_columns(table)}
        return column in cols
    except Exception:
        return False


def _index_exists(inspector, table: str, index_name: str) -> bool:
    try:
        idxs = {i["name"] for i in inspector.get_indexes(table)}
        return index_name in idxs
    except Exception:
        return False


def _table_exists(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def _safe_add_column(conn, inspector, table: str, column: str, ddl: str):
    if _table_exists(inspector, table) and not _column_exists(inspector, table, column):
        print(f"  + Adding column {table}.{column}")
        conn.execute(text(ddl))
    else:
        print(f"  . Skipping {table}.{column} (already exists)")


def _safe_add_index(conn, inspector, table: str, index_name: str, ddl: str):
    if _table_exists(inspector, table) and not _index_exists(inspector, table, index_name):
        print(f"  + Creating index {index_name}")
        try:
            conn.execute(text(ddl))
        except Exception as exc:
            print(f"  ! Index creation failed (non-fatal): {exc}")
    else:
        print(f"  . Skipping index {index_name} (already exists)")


def upgrade():
    """Apply all 001 enterprise upgrade changes."""
    print("=== CyberGuard AI Migration 001: Enterprise Upgrade ===")
    inspector = inspect(engine)

    with engine.begin() as conn:
        # ── users table ──────────────────────────────────────────────────────
        print("\n[users]")
        _safe_add_column(
            conn, inspector, "users", "refresh_token_version",
            "ALTER TABLE users ADD COLUMN refresh_token_version INTEGER DEFAULT 0 NOT NULL"
            if IS_POSTGRES else
            "ALTER TABLE users ADD COLUMN refresh_token_version INTEGER DEFAULT 0"
        )

        # ── scan_history table ───────────────────────────────────────────────
        print("\n[scan_history]")
        # These were added in earlier migrations — check first
        for col, ddl_pg, ddl_sqlite in [
            ("entities",            "ALTER TABLE scan_history ADD COLUMN entities JSON",                         "ALTER TABLE scan_history ADD COLUMN entities JSON"),
            ("attack_type",         "ALTER TABLE scan_history ADD COLUMN attack_type VARCHAR",                   "ALTER TABLE scan_history ADD COLUMN attack_type VARCHAR"),
            ("severity",            "ALTER TABLE scan_history ADD COLUMN severity VARCHAR",                      "ALTER TABLE scan_history ADD COLUMN severity VARCHAR"),
            ("ml_confidence",       "ALTER TABLE scan_history ADD COLUMN ml_confidence INTEGER DEFAULT 0",       "ALTER TABLE scan_history ADD COLUMN ml_confidence INTEGER DEFAULT 0"),
            ("intelligence_hit",    "ALTER TABLE scan_history ADD COLUMN intelligence_hit BOOLEAN DEFAULT false","ALTER TABLE scan_history ADD COLUMN intelligence_hit BOOLEAN DEFAULT 0"),
            ("correlation_hit",     "ALTER TABLE scan_history ADD COLUMN correlation_hit BOOLEAN DEFAULT false", "ALTER TABLE scan_history ADD COLUMN correlation_hit BOOLEAN DEFAULT 0"),
            ("prevention_triggered","ALTER TABLE scan_history ADD COLUMN prevention_triggered BOOLEAN DEFAULT false","ALTER TABLE scan_history ADD COLUMN prevention_triggered BOOLEAN DEFAULT 0"),
            ("explanation",         "ALTER TABLE scan_history ADD COLUMN explanation JSON",                      "ALTER TABLE scan_history ADD COLUMN explanation JSON"),
            ("mitre_mappings",      "ALTER TABLE scan_history ADD COLUMN mitre_mappings JSON",                   "ALTER TABLE scan_history ADD COLUMN mitre_mappings JSON"),
            ("risk_contributions",  "ALTER TABLE scan_history ADD COLUMN risk_contributions JSON",               "ALTER TABLE scan_history ADD COLUMN risk_contributions JSON"),
        ]:
            _safe_add_column(conn, inspector, "scan_history", col, ddl_pg if IS_POSTGRES else ddl_sqlite)

        # ── alerts table ─────────────────────────────────────────────────────
        print("\n[alerts]")
        for col, ddl_pg, ddl_sqlite in [
            ("risk_contributions",      "ALTER TABLE alerts ADD COLUMN risk_contributions JSON",                          "ALTER TABLE alerts ADD COLUMN risk_contributions JSON"),
            ("false_positive_reported", "ALTER TABLE alerts ADD COLUMN false_positive_reported BOOLEAN DEFAULT false",    "ALTER TABLE alerts ADD COLUMN false_positive_reported BOOLEAN DEFAULT 0"),
            ("in_review_queue",         "ALTER TABLE alerts ADD COLUMN in_review_queue BOOLEAN DEFAULT false",            "ALTER TABLE alerts ADD COLUMN in_review_queue BOOLEAN DEFAULT 0"),
        ]:
            _safe_add_column(conn, inspector, "alerts", col, ddl_pg if IS_POSTGRES else ddl_sqlite)

        # ── user_behavior_events table ────────────────────────────────────────
        print("\n[user_behavior_events]")
        _safe_add_column(
            conn, inspector, "user_behavior_events", "explanation",
            "ALTER TABLE user_behavior_events ADD COLUMN explanation JSON"
        )

        # ── New tables ────────────────────────────────────────────────────────
        print("\n[New Tables]")

        if not _table_exists(inspector, "refresh_tokens"):
            print("  + Creating table refresh_tokens")
            conn.execute(text("""
                CREATE TABLE refresh_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) NOT NULL REFERENCES users(id),
                    token_hash VARCHAR(64) UNIQUE NOT NULL,
                    jti VARCHAR(64),
                    expires_at TIMESTAMP NOT NULL,
                    revoked BOOLEAN DEFAULT 0,
                    revoked_at TIMESTAMP,
                    user_agent VARCHAR(512),
                    client_ip VARCHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            print("  . Skipping refresh_tokens (already exists)")

        if not _table_exists(inspector, "false_positive_reports"):
            print("  + Creating table false_positive_reports")
            conn.execute(text("""
                CREATE TABLE false_positive_reports (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id),
                    scan_history_id VARCHAR(36) REFERENCES scan_history(id),
                    alert_id VARCHAR(36) REFERENCES alerts(id),
                    entity VARCHAR(512) NOT NULL,
                    reported_by VARCHAR(36) NOT NULL REFERENCES users(id),
                    reason TEXT NOT NULL,
                    status VARCHAR(32) DEFAULT 'pending',
                    reviewed_by VARCHAR(36) REFERENCES users(id),
                    reviewer_notes TEXT,
                    override_applied BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP
                )
            """))
        else:
            print("  . Skipping false_positive_reports (already exists)")

        if not _table_exists(inspector, "human_review_queue"):
            print("  + Creating table human_review_queue")
            conn.execute(text("""
                CREATE TABLE human_review_queue (
                    id VARCHAR(36) PRIMARY KEY,
                    workspace_id VARCHAR(36) NOT NULL REFERENCES workspaces(id),
                    entity VARCHAR(512) NOT NULL,
                    entity_type VARCHAR(64) NOT NULL,
                    risk_score INTEGER NOT NULL,
                    signals JSON,
                    risk_contributions JSON,
                    scan_history_id VARCHAR(36) REFERENCES scan_history(id),
                    alert_id VARCHAR(36) REFERENCES alerts(id),
                    status VARCHAR(32) DEFAULT 'pending',
                    reviewed_by VARCHAR(36) REFERENCES users(id),
                    reviewer_notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TIMESTAMP
                )
            """))
        else:
            print("  . Skipping human_review_queue (already exists)")

        if not _table_exists(inspector, "system_health_logs"):
            print("  + Creating table system_health_logs")
            conn.execute(text("""
                CREATE TABLE system_health_logs (
                    id VARCHAR(36) PRIMARY KEY,
                    service VARCHAR(64) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    latency_ms REAL,
                    detail JSON,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
        else:
            print("  . Skipping system_health_logs (already exists)")

        # ── Indexes ───────────────────────────────────────────────────────────
        # Re-inspect after table creation
        inspector2 = inspect(engine)
        print("\n[Indexes]")
        indexes = [
            ("scan_history",         "ix_scan_history_workspace_entity",   "CREATE INDEX ix_scan_history_workspace_entity ON scan_history (workspace_id, entity)"),
            ("scan_history",         "ix_scan_history_workspace_severity",  "CREATE INDEX ix_scan_history_workspace_severity ON scan_history (workspace_id, severity)"),
            ("audit_logs",           "ix_audit_workspace_created",          "CREATE INDEX ix_audit_workspace_created ON audit_logs (workspace_id, created_at)"),
            ("audit_logs",           "ix_audit_action_created",             "CREATE INDEX ix_audit_action_created ON audit_logs (action, created_at)"),
            ("threat_intel",         "ix_threat_intel_active",              "CREATE INDEX ix_threat_intel_active ON threat_intel (entity_value, is_active)"),
            ("refresh_tokens",       "ix_refresh_token_user",               "CREATE INDEX ix_refresh_token_user ON refresh_tokens (user_id)"),
            ("refresh_tokens",       "ix_refresh_token_hash",               "CREATE INDEX ix_refresh_token_hash ON refresh_tokens (token_hash)"),
            ("false_positive_reports","ix_fp_report_workspace_status",      "CREATE INDEX ix_fp_report_workspace_status ON false_positive_reports (workspace_id, status)"),
            ("false_positive_reports","ix_fp_report_scan",                  "CREATE INDEX ix_fp_report_scan ON false_positive_reports (scan_history_id)"),
            ("human_review_queue",   "ix_review_queue_workspace_status",    "CREATE INDEX ix_review_queue_workspace_status ON human_review_queue (workspace_id, status)"),
            ("human_review_queue",   "ix_review_queue_entity",              "CREATE INDEX ix_review_queue_entity ON human_review_queue (workspace_id, entity)"),
            ("system_health_logs",   "ix_health_log_service_time",          "CREATE INDEX ix_health_log_service_time ON system_health_logs (service, checked_at)"),
        ]
        for table, idx_name, ddl in indexes:
            _safe_add_index(conn, inspector2, table, idx_name, ddl)

    print("\n✓ Migration 001 complete.")


def downgrade():
    """Remove changes introduced in migration 001 (destructive — use with caution)."""
    print("=== CyberGuard AI Migration 001: DOWNGRADE ===")
    print("WARNING: This will drop new tables and columns added by migration 001.")
    confirm = input("Type 'yes' to proceed: ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        return

    with engine.begin() as conn:
        for table in ["system_health_logs", "human_review_queue", "false_positive_reports", "refresh_tokens"]:
            print(f"  - Dropping table {table}")
            conn.execute(text(f"DROP TABLE IF EXISTS {table}"))

    print("✓ Downgrade complete. Note: column-level changes (risk_contributions etc.) were NOT reversed.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "upgrade"
    if cmd == "upgrade":
        upgrade()
    elif cmd == "downgrade":
        downgrade()
    else:
        print(f"Unknown command: {cmd}. Use 'upgrade' or 'downgrade'.")
        sys.exit(1)
