import uuid
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.api import deps
from src.models.models import User, Workspace, FalsePositiveReport, HumanReviewQueue
from src.services.false_positive_service import FalsePositiveFramework

router = APIRouter()

class FPSubmission(BaseModel):
    entity: str
    reason: str
    scan_history_id: str | None = None
    alert_id: str | None = None

class FPAction(BaseModel):
    notes: str = ""

@router.post("/submit")
def submit_false_positive(
    submission: FPSubmission,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """Submit a false positive report for analyst review."""
    scan_uuid = uuid.UUID(submission.scan_history_id) if submission.scan_history_id else None
    alert_uuid = uuid.UUID(submission.alert_id) if submission.alert_id else None
    
    report = FalsePositiveFramework.submit_false_positive(
        db=db,
        workspace_id=workspace.id,
        reported_by=current_user.id,
        entity=submission.entity,
        reason=submission.reason,
        scan_history_id=scan_uuid,
        alert_id=alert_uuid
    )
    
    return {"message": "False positive report submitted successfully", "report_id": str(report.id)}

@router.get("/metrics")
def get_fp_metrics(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """Get false positive and review queue metrics for the workspace."""
    return FalsePositiveFramework.get_fp_metrics(db, workspace.id)

@router.get("/review-queue")
def get_review_queue(
    status: str = "pending",
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """Get the human review queue."""
    items, total = FalsePositiveFramework.get_review_queue(
        db, workspace.id, status=status, skip=skip, limit=limit
    )
    
    return {
        "total": total,
        "items": [
            {
                "id": str(item.id),
                "entity": item.entity,
                "entity_type": item.entity_type,
                "risk_score": item.risk_score,
                "signals": item.signals,
                "risk_contributions": item.risk_contributions,
                "status": item.status,
                "created_at": item.created_at,
            }
            for item in items
        ]
    }

@router.post("/reports/{report_id}/approve")
def approve_fp_report(
    report_id: uuid.UUID,
    action: FPAction,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """Approve a FP report, marking it confirmed and removing any active blocks."""
    # Ensure user is admin (in real app)
    if current_user.role != "admin":
         raise HTTPException(status_code=403, detail="Not authorized")
         
    try:
        report = FalsePositiveFramework.apply_override(
            db=db,
            report_id=report_id,
            reviewer_id=current_user.id,
            notes=action.notes
        )
        return {"message": "Report approved and override applied"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/reports/{report_id}/reject")
def reject_fp_report(
    report_id: uuid.UUID,
    action: FPAction,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """Reject a FP report (entity remains blocked)."""
    if current_user.role != "admin":
         raise HTTPException(status_code=403, detail="Not authorized")
         
    try:
        report = FalsePositiveFramework.reject_report(
            db=db,
            report_id=report_id,
            reviewer_id=current_user.id,
            notes=action.notes
        )
        return {"message": "Report rejected"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
