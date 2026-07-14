import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.api import deps
from src.models.models import ScanHistory, Workspace

router = APIRouter()


@router.get("/{scan_id}")
async def get_explanation(
    scan_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: deps.AuthContext = Depends(deps.require_permissions("scans:read")),
) -> Dict[str, Any]:
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan id")

    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_uuid,
        ScanHistory.workspace_id == workspace.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.id),
        "entity": scan.entity,
        "input_type": scan.input_type,
        "attack_type": scan.attack_type,
        "risk_score": scan.risk_score,
        "verdict": scan.verdict,
        "explanation": scan.explanation or {},
        "mitre_mappings": scan.mitre_mappings or [],
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }
