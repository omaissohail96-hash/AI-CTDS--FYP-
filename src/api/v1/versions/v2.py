from fastapi import APIRouter

router = APIRouter(prefix="/api/v2", tags=["versioning"])


@router.get("/version")
async def version_info():
    return {
        "version": "v2",
        "status": "preview",
        "deprecated": False,
        "docs": "/docs",
    }
