from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.v1 import auth, agent, workspace
from src.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

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
