from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api import deps
from src.services.monitoring_service import MonitoringService

router = APIRouter()


@router.get("/monitoring")
async def get_monitoring_snapshot(
    db: Session = Depends(deps.get_db),
    _: deps.AuthContext = Depends(deps.require_permissions("alerts:read")),
):
    return MonitoringService.get_system_snapshot()
