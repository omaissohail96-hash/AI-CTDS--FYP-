from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.v1 import auth, agent, workspace, stats, alerts, prevention, explanations, hunting, reports, mitre, uba
from src.core.config import settings
from src.core.database import initialize_database
from src.utils.prevention_scheduler import PreventionScheduler

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

initialize_database()

from src.api.middleware import AuditMiddleware

# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Audit Trail Middleware
app.add_middleware(AuditMiddleware)

# Include Routers
app.include_router(auth.router, prefix=settings.API_V1_STR, tags=["auth"])
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


@app.on_event("startup")
async def startup_event():
    """Initialize background tasks on application startup"""
    await PreventionScheduler.start_scheduler()

@app.get("/")
async def root():
    return {
        "message": "CyberGuard AI SaaS Gateway",
        "version": "2.1.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
