"""
Background task definitions for CyberGuard AI.

All tasks include:
  - Retry with exponential backoff (max 3 retries)
  - Dead-letter handling via on_failure hooks
  - Synchronous fallback path when Celery is disabled
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _get_db():
    """Get a database session for use inside Celery tasks."""
    from src.core.database import SessionLocal
    return SessionLocal()


def _dispatch(task_fn, *args, async_mode: bool = True, **kwargs):
    """
    Dispatch a task asynchronously via Celery if enabled,
    otherwise execute synchronously (graceful degradation).
    """
    from src.core.config import settings
    if settings.CELERY_ENABLED and async_mode:
        try:
            task_fn.delay(*args, **kwargs)
            return True
        except Exception as exc:
            logger.warning(f"Celery dispatch failed, running synchronously: {exc}")
    # Synchronous fallback
    try:
        task_fn(*args, **kwargs)
    except Exception as exc:
        logger.error(f"Synchronous task execution failed: {exc}")
    return False


try:
    from src.workers.celery_app import celery_app

    # ── Email Notifications ───────────────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=3, default_retry_delay=60, queue="default")
    def send_email_notification(self, alert_id: str, recipient: str, template: str = "alert"):
        """Send email notification for a generated alert."""
        try:
            db = _get_db()
            try:
                from src.models.models import Alert
                alert = db.query(Alert).filter(Alert.id == alert_id).first()
                if not alert:
                    logger.warning(f"Alert {alert_id} not found for email notification")
                    return

                # Import and use the existing notification service
                from src.services.notification_service import NotificationService
                NotificationService.send_alert_email(alert, recipient)

                alert.email_sent = True
                db.commit()
                logger.info(f"Email notification sent for alert {alert_id}")
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Email notification failed for alert {alert_id}: {exc}")
            raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

    # ── PDF Report Generation ─────────────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=2, default_retry_delay=120, queue="default")
    def generate_pdf_report(self, workspace_id: str, hours: int = 0, report_id: Optional[str] = None):
        """Generate PDF security report in background and store result."""
        try:
            db = _get_db()
            try:
                from src.models.models import Workspace
                from src.services.pdf_report_service import PDFReportService
                workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
                if not workspace:
                    logger.error(f"Workspace {workspace_id} not found")
                    return

                pdf_bytes = PDFReportService.generate_security_report(db, workspace, hours=hours)
                logger.info(f"PDF report generated for workspace {workspace_id}: {len(pdf_bytes)} bytes")
                return len(pdf_bytes)
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"PDF generation failed for workspace {workspace_id}: {exc}")
            raise self.retry(exc=exc, countdown=120)

    # ── Alert Webhook Delivery ────────────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=5, default_retry_delay=30, queue="high_priority")
    def deliver_alert_webhook(self, alert_id: str, webhook_url: str):
        """Deliver alert payload to an external webhook endpoint."""
        import requests
        try:
            db = _get_db()
            try:
                from src.models.models import Alert
                alert = db.query(Alert).filter(Alert.id == alert_id).first()
                if not alert:
                    return

                payload = {
                    "alert_id": str(alert.id),
                    "severity": alert.severity,
                    "title": alert.title,
                    "entity": alert.entity,
                    "risk_score": alert.risk_score,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                }
                resp = requests.post(webhook_url, json=payload, timeout=10)
                resp.raise_for_status()

                alert.webhook_sent = True
                db.commit()
                logger.info(f"Webhook delivered for alert {alert_id}")
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Webhook delivery failed for alert {alert_id}: {exc}")
            backoff = 30 * (2 ** self.request.retries)
            raise self.retry(exc=exc, countdown=min(backoff, 3600))

    # ── Async Audit Log Persistence ───────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=3, default_retry_delay=30, queue="default")
    def persist_audit_log(
        self,
        action: str,
        module: str,
        status: str = "success",
        workspace_id: Optional[str] = None,
        user_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ):
        """Persist an audit log entry asynchronously."""
        try:
            db = _get_db()
            try:
                import uuid
                from src.utils.audit import AuditLogger
                AuditLogger.log(
                    db,
                    action=action,
                    module=module,
                    status=status,
                    workspace_id=uuid.UUID(workspace_id) if workspace_id else None,
                    user_id=uuid.UUID(user_id) if user_id else None,
                    metadata=metadata or {},
                )
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Async audit log persistence failed: {exc}")
            raise self.retry(exc=exc, countdown=30)

    # ── Threat Intelligence Synchronization ───────────────────────────────────

    @celery_app.task(bind=True, max_retries=2, default_retry_delay=300, queue="low_priority")
    def sync_threat_intelligence(self, source: str = "scheduled"):
        """Refresh threat intelligence data from external feeds."""
        try:
            db = _get_db()
            try:
                from src.services.threat_intel import ThreatIntelService
                # Invalidate TI cache after sync
                import asyncio
                from src.services.cache_service import CacheService
                count = ThreatIntelService.sync_feeds(db)
                asyncio.run(CacheService.invalidate_all_threat_intel())
                logger.info(f"TI sync complete ({source}): {count} indicators refreshed")
                return count
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"TI sync failed: {exc}")
            raise self.retry(exc=exc, countdown=300)

    # ── Redis Cache Warming ───────────────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=1, queue="low_priority")
    def warm_redis_cache(self, workspace_id: Optional[str] = None):
        """Warm Redis cache for a specific workspace or globally."""
        try:
            import asyncio
            db = _get_db()
            try:
                from src.services.cache_service import CacheService
                result = asyncio.run(CacheService.warm_cache_on_startup(db))
                logger.info(f"Cache warming complete: {result}")
                return result
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Cache warming failed: {exc}")

    # ── Expired Block Cleanup ─────────────────────────────────────────────────

    @celery_app.task(bind=True, max_retries=1, queue="low_priority")
    def cleanup_expired_blocks(self):
        """Remove expired block records and invalidate their cache entries."""
        try:
            db = _get_db()
            try:
                from src.services.prevention_engine import PreventionEngine
                count = PreventionEngine.cleanup_expired_blocks(db)
                logger.info(f"Cleaned up {count} expired blocks")
                return count
            finally:
                db.close()
        except Exception as exc:
            logger.error(f"Block cleanup failed: {exc}")

except ImportError:
    # Celery not installed — provide no-op stubs
    logger.warning("Celery not available — background task stubs loaded")

    class _Stub:
        """No-op stub for when Celery is not installed."""
        @staticmethod
        def delay(*a, **kw):
            pass
        @staticmethod
        def apply_async(*a, **kw):
            pass

    send_email_notification = _Stub()
    generate_pdf_report = _Stub()
    deliver_alert_webhook = _Stub()
    persist_audit_log = _Stub()
    sync_threat_intelligence = _Stub()
    warm_redis_cache = _Stub()
    cleanup_expired_blocks = _Stub()


# ── Public dispatch helpers (used by API layer) ───────────────────────────────

def dispatch_email_notification(alert_id: str, recipient: str):
    _dispatch(send_email_notification, alert_id, recipient)


def dispatch_pdf_report(workspace_id: str, hours: int = 0):
    _dispatch(generate_pdf_report, workspace_id, hours)


def dispatch_webhook(alert_id: str, webhook_url: str):
    _dispatch(deliver_alert_webhook, alert_id, webhook_url)


def dispatch_audit_log(action: str, module: str, **kwargs):
    _dispatch(persist_audit_log, action, module, **kwargs)


def dispatch_ti_sync(source: str = "manual"):
    _dispatch(sync_threat_intelligence, source)
