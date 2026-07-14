"""
False Positive Framework Endpoints

RBAC:
  POST /fp/submit               → false_positives:submit
  GET  /fp/metrics              → false_positives:submit (any analyst)
  GET  /fp/review-queue         → review_queue:read
  POST /fp/reports/{id}/approve → false_positives:review
  POST /fp/reports/{id}/reject  → false_positives:review
  (replaces hardcoded role == "admin" checks)
"""
import uuid
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from src.api import deps
from src.api.deps import RequirePermissions
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
    current_user: User = Depends(RequirePermissions("false_positives:submit")),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """
    Submit a false positive report for analyst review.
    Requires false_positives:submit (security_analyst, workspace_admin, super_admin).
    """
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
    _: User = Depends(RequirePermissions("false_positives:submit")),
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
    _: User = Depends(RequirePermissions("review_queue:read")),
) -> Any:
    """Get the human review queue. Requires review_queue:read."""
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
    current_user: User = Depends(RequirePermissions("false_positives:review")),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """
    Approve a FP report. Requires false_positives:review.
    (security_analyst, workspace_admin, super_admin)
    """
    try:
        FalsePositiveFramework.apply_override(
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
    current_user: User = Depends(RequirePermissions("false_positives:review")),
    workspace: Workspace = Depends(deps.get_current_workspace),
) -> Any:
    """
    Reject a FP report. Requires false_positives:review.
    (security_analyst, workspace_admin, super_admin)
    """
    try:
        FalsePositiveFramework.reject_report(
            db=db,
            report_id=report_id,
            reviewer_id=current_user.id,
            notes=action.notes
        )
        return {"message": "Report rejected"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
