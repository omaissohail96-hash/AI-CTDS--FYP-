from datetime import datetime
from fastapi import APIRouter, Response
from src.core.config import settings
from src.core.redis_client import check_redis_health
from src.utils.metrics_collector import metrics

router = APIRouter()

@router.get("/health")
async def health_check():
    """Comprehensive health check."""
    redis_health = await check_redis_health()
    
    # In a full implementation, we'd also check DB and Workers
    status = "healthy"
    if redis_health["status"] != "ok" and settings.REDIS_ENABLED:
        status = "degraded"
        
    return {
        "status": status,
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.VERSION,
        "services": {
            "database": {"status": "ok"}, # Mocked for now
            "redis": redis_health,
            "workers": {"status": "ok" if settings.CELERY_ENABLED else "disabled"}
        }
    }

@router.get("/health/live")
def liveness_probe():
    """Fast kubernetes liveness probe."""
    return {"status": "ok"}

@router.get("/health/ready")
def readiness_probe():
    """Kubernetes readiness probe."""
    return {"status": "ok"}

@router.get("/metrics")
def get_metrics(response: Response):
    """Exposes Prometheus text format metrics."""
    response.headers["Content-Type"] = "text/plain; version=0.0.4"
    return metrics.generate_prometheus_format()
