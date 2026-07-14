from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.api import deps
from src.models.models import ScanHistory, Workspace

router = APIRouter()


@router.get("/threats/{scan_id}/explanation")
async def get_threat_explanation(
    scan_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: deps.AuthContext = Depends(deps.require_permissions("scans:read")),
):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.workspace_id == workspace.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": str(scan.id),
        "explanation": scan.explanation or {},
        "risk_score": scan.risk_score,
        "verdict": scan.verdict,
    }
