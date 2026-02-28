from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from src.models.models import Workspace, ScanHistory
from fastapi import HTTPException, status

class SaaSGuard:
    """
    Ensures multi-tenant fairness and subscription compliance.
    Handles rate limiting and monthly quota enforcement.
    """

    @staticmethod
    def check_quota(db: Session, workspace: Workspace):
        """
        Verifies if the workspace has exceeded its monthly scan quota.
        """
        # Calculate start of current month
        now = datetime.utcnow()
        first_day = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        # Count scans this month
        usage_count = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace.id,
            ScanHistory.created_at >= first_day
        ).count()
        
        if usage_count >= workspace.monthly_quota:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Monthly scan quota exceeded ({workspace.monthly_quota}). Please upgrade your plan."
            )
        
        return usage_count

    @staticmethod
    def check_rate_limit(db: Session, workspace: Workspace):
        """
        Basic rate limiting (Requests Per Minute).
        """
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        
        recent_requests = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace.id,
            ScanHistory.created_at >= one_minute_ago
        ).count()
        
        if recent_requests >= workspace.rate_limit_rpm:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({workspace.rate_limit_rpm} requests per minute). Slow down."
            )
        
        return recent_requests
