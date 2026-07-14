"""
Workspace configuration endpoints.
API key management has been moved to /api-keys/* (src/api/v1/api_keys.py).
"""
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.api import deps
from src.models.models import Workspace

router = APIRouter()


@router.get("/info")
def get_workspace_info(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: Any = Depends(deps.get_current_user),
) -> Any:
    """Return workspace configuration (tier, quota, rate limit)."""
    return {
        "id": str(workspace.id),
        "name": workspace.name,
        "tier": workspace.tier,
        "monthly_quota": workspace.monthly_quota,
        "rate_limit_rpm": workspace.rate_limit_rpm,
        "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
    }
