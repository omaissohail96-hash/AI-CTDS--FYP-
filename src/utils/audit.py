import uuid
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from src.models import models

class AuditLogger:
    @staticmethod
    def log(
        db: Session,
        action: str,
        module: str,
        status: str = "success",
        workspace_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Records an enterprise security event in the audit log.
        """
        audit_entry = models.AuditLog(
            workspace_id=workspace_id,
            user_id=user_id,
            action=action,
            module=module,
            status=status,
            event_metadata=metadata or {}
        )
        db.add(audit_entry)
        db.commit()

def log_security_event(db: Session, **kwargs):
    AuditLogger.log(db, **kwargs)
