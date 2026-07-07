"""
Celery application configuration for CyberGuard AI.

Queues:
  - high_priority  : Alert delivery, critical notifications
  - default        : Email notifications, PDF reports, audit logs
  - low_priority   : TI synchronization, cache warming, cleanup

When CELERY_ENABLED=False, tasks fall back to synchronous execution
so the app works without any external dependencies.
"""

import logging
from src.core.config import settings

logger = logging.getLogger(__name__)

try:
    from celery import Celery

    celery_app = Celery(
        "cyberguard",
        broker=settings.CELERY_BROKER_URL,
        backend=settings.CELERY_RESULT_BACKEND,
        include=["src.workers.tasks"],
    )

    celery_app.conf.update(
        # Serialization
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,

        # Task routing
        task_routes={
            "src.workers.tasks.deliver_alert_webhook": {"queue": "high_priority"},
            "src.workers.tasks.send_email_notification": {"queue": "default"},
            "src.workers.tasks.generate_pdf_report": {"queue": "default"},
            "src.workers.tasks.persist_audit_log": {"queue": "default"},
            "src.workers.tasks.sync_threat_intelligence": {"queue": "low_priority"},
            "src.workers.tasks.warm_redis_cache": {"queue": "low_priority"},
            "src.workers.tasks.cleanup_expired_blocks": {"queue": "low_priority"},
        },

        # Reliability
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_default_retry_delay=60,
        task_max_retries=3,

        # Dead-letter: failed tasks are stored in result backend for 48h
        task_store_errors_even_if_ignored=True,
        result_expires=172800,  # 48 hours

        # Worker concurrency
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=1000,

        # Beat schedule (background periodic tasks)
        beat_schedule={
            "cleanup-expired-blocks-every-hour": {
                "task": "src.workers.tasks.cleanup_expired_blocks",
                "schedule": 3600.0,
            },
            "sync-threat-intel-every-6h": {
                "task": "src.workers.tasks.sync_threat_intelligence",
                "schedule": 21600.0,
                "kwargs": {"source": "scheduled"},
            },
        },
    )

    logger.info("Celery application configured")

except ImportError:
    logger.warning("Celery not installed — background tasks will run synchronously")

    class _FakeCelery:
        """Stub Celery app for environments without celery installed."""
        def task(self, *args, **kwargs):
            def decorator(fn):
                fn.delay = fn
                fn.apply_async = lambda *a, **kw: fn(*a)
                return fn
            return decorator

    celery_app = _FakeCelery()
