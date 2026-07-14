from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["versioning"])


@router.get("/version")
async def version_info():
    return {
        "version": "v1",
        "status": "stable",
        "deprecated": False,
        "docs": "/docs",
    }
