import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.v1 import auth, agent, workspace, stats, alerts, prevention, explanations, hunting, reports, mitre, uba, health, session, false_positives, mfa, monitoring, threats, api_keys, feedback, rbac
from src.api.v1.versions import v1, v2
from src.core.config import settings
from src.core.database import initialize_database
from src.core.logging_config import configure_logging
from src.utils.prevention_scheduler import PreventionScheduler
from detectors.web_detector_ml import validate_web_attack_model

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

initialize_database()

from src.api.middleware import (
    AuditMiddleware,
    PreventionMiddleware,
    TrustedProxyMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    CSRFMiddleware
)

# Order of middleware is important (Outer to Inner)
# 1. TrustedProxy (resolves IP)
app.add_middleware(TrustedProxyMiddleware)
# 2. Security Headers
app.add_middleware(SecurityHeadersMiddleware)
# 3. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 4. Rate Limiting
app.add_middleware(RateLimitMiddleware)
# 5. CSRF (double-submit cookie)
app.add_middleware(CSRFMiddleware)
# 6. Prevention (IP block list)
app.add_middleware(PreventionMiddleware)
# 7. Audit Logging (Logs final request/response)
app.add_middleware(AuditMiddleware)

# Include Routers
# Root-level health endpoints
app.include_router(health.router, tags=["health"])

app.include_router(auth.router, prefix=settings.API_V1_STR, tags=["auth"])
app.include_router(monitoring.router, prefix=settings.API_V1_STR, tags=["monitoring"])
app.include_router(threats.router, prefix=settings.API_V1_STR, tags=["threats"])
app.include_router(feedback.router, prefix=f"{settings.API_V1_STR}/feedback", tags=["feedback"])
app.include_router(workspace.router, prefix=f"{settings.API_V1_STR}/workspace", tags=["workspace"])
app.include_router(agent.router, prefix=f"{settings.API_V1_STR}/agent", tags=["agent"])
app.include_router(stats.router, prefix=f"{settings.API_V1_STR}/stats", tags=["stats"])
app.include_router(alerts.router, prefix=settings.API_V1_STR, tags=["alerts"])
app.include_router(prevention.router, prefix=f"{settings.API_V1_STR}/prevention", tags=["prevention"])
app.include_router(explanations.router, prefix=f"{settings.API_V1_STR}/explanations", tags=["explanations"])
app.include_router(hunting.router, prefix=f"{settings.API_V1_STR}/hunting", tags=["hunting"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
app.include_router(mitre.router, prefix=f"{settings.API_V1_STR}/mitre", tags=["mitre"])
app.include_router(uba.router, prefix=f"{settings.API_V1_STR}/uba", tags=["uba"])
app.include_router(session.router, prefix=f"{settings.API_V1_STR}/sessions", tags=["sessions"])
app.include_router(false_positives.router, prefix=f"{settings.API_V1_STR}/fp", tags=["false_positives"])
app.include_router(mfa.router, prefix=f"{settings.API_V1_STR}/mfa", tags=["mfa"])
app.include_router(v1.router)
app.include_router(v2.router)
app.include_router(api_keys.router, prefix="/api-keys", tags=["api-keys"])
app.include_router(rbac.router, prefix=f"{settings.API_V1_STR}/rbac", tags=["rbac"])

@app.on_event("startup")
async def startup_event():
    """Initialize background tasks on application startup"""
    # Fail startup rather than serving web scans with an untrained/fallback model.
    validate_web_attack_model()
    await PreventionScheduler.start_scheduler()
    logger.info("CyberGuard startup completed")
    
    # Warm up Redis cache if enabled
    import asyncio
    from src.workers.tasks import warm_redis_cache
    if settings.CELERY_ENABLED:
        warm_redis_cache.delay()
    else:
        # Fallback to sync warming if no Celery
        try:
            from src.core.database import SessionLocal
            from src.services.cache_service import CacheService
            db = SessionLocal()
            await CacheService.warm_cache_on_startup(db)
            db.close()
        except Exception as exc:
            print(f"Startup cache warming failed: {exc}")

@app.get("/")
async def root():
    return {
        "message": "CyberGuard AI SaaS Gateway",
        "version": settings.VERSION,
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
