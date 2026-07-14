import sys
from pathlib import Path
import logging

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from src.core.database import SessionLocal, engine
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NEW_API_KEY_COLUMNS = [
    ("usage_count",        "INTEGER DEFAULT 0"),
    ("successful_requests","INTEGER DEFAULT 0"),
    ("failed_requests",    "INTEGER DEFAULT 0"),
    ("expires_at",         "TIMESTAMP"),
    ("last_used_ip",       "TEXT"),
    ("rotated_at",         "TIMESTAMP"),
]

def migrate():
    db = SessionLocal()
    try:
        # --- api_keys extra columns ---
        for col, coltype in NEW_API_KEY_COLUMNS:
            try:
                db.execute(text(f"ALTER TABLE api_keys ADD COLUMN {col} {coltype}"))
                logger.info(f"Added api_keys.{col}")
            except Exception:
                logger.warning(f"api_keys.{col} already exists – skipping")

        # --- api_key_audit_logs table ---
        db.execute(text("""
            CREATE TABLE IF NOT EXISTS api_key_audit_logs (
                id          TEXT PRIMARY KEY,
                api_key_id  TEXT NOT NULL REFERENCES api_keys(id),
                workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                endpoint    TEXT,
                method      TEXT,
                status_code INTEGER,
                client_ip   TEXT,
                response_ms REAL,
                event       TEXT,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))
        logger.info("api_key_audit_logs table ensured")

        db.commit()
        logger.info("Migration completed successfully")
    except Exception as e:
        db.rollback()
        logger.error(f"Migration failed: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate()
