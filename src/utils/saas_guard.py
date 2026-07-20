from datetime import datetime, timedelta, timezone
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
            reset_at = SaaSGuard._next_month_start(now)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "monthly_quota_exhausted",
                    "message": "Your workspace has used all available scans for this month.",
                    "usage": usage_count,
                    "limit": workspace.monthly_quota,
                    "remaining": 0,
                    "reset_at": SaaSGuard._format_utc(reset_at),
                },
                headers={
                    "X-RateLimit-Limit": str(workspace.monthly_quota),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": SaaSGuard._format_utc(reset_at),
                },
            )
        
        return usage_count

    @staticmethod
    def check_rate_limit(db: Session, workspace: Workspace):
        """
        Basic rate limiting (Requests Per Minute).
        """
        one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
        
        recent_scans = db.query(ScanHistory).filter(
            ScanHistory.workspace_id == workspace.id,
            ScanHistory.created_at >= one_minute_ago
        ).order_by(ScanHistory.created_at.asc()).all()
        recent_requests = len(recent_scans)
        
        if recent_requests >= workspace.rate_limit_rpm:
            reset_at = recent_scans[0].created_at + timedelta(minutes=1)
            current_time = datetime.now(reset_at.tzinfo) if reset_at.tzinfo else datetime.utcnow()
            retry_after = max(1, int((reset_at - current_time).total_seconds() + 0.999))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "code": "rate_limit_exceeded",
                    "message": "Your workspace has reached its scan rate limit. Please try again shortly.",
                    "usage": recent_requests,
                    "limit": workspace.rate_limit_rpm,
                    "remaining": 0,
                    "reset_at": SaaSGuard._format_utc(reset_at),
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(workspace.rate_limit_rpm),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": SaaSGuard._format_utc(reset_at),
                },
            )
        
        return recent_requests

    @staticmethod
    def _next_month_start(now: datetime) -> datetime:
        if now.month == 12:
            return now.replace(year=now.year + 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        return now.replace(month=now.month + 1, day=1, hour=0, minute=0, second=0, microsecond=0)

    @staticmethod
    def _format_utc(value: datetime) -> str:
        if value.tzinfo:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        return value.isoformat() + "Z"
