from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
import uuid
from pydantic import BaseModel

from src.api.deps import get_db, get_current_user, get_current_workspace, RequirePermissions
from src.models.models import User, Workspace, AIFeedback
from src.services.feedback_service import FeedbackService

router = APIRouter()

class FeedbackSubmitRequest(BaseModel):
    scan_id: uuid.UUID
    feedback_type: str
    comments: Optional[str] = None

class FeedbackResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    entity: str
    entity_type: str
    predicted_label: str
    actual_label: str
    confidence: float
    risk_score: int
    feedback_type: str
    comments: Optional[str]
    review_status: str
    
    class Config:
        from_attributes = True

@router.post("", response_model=FeedbackResponse)
def submit_feedback(
    req: FeedbackSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequirePermissions("feedback:submit")),
    workspace: Workspace = Depends(get_current_workspace)
):
    """Submit HITL feedback for a specific scan"""
    return FeedbackService.submit_feedback(
        db=db,
        workspace_id=workspace.id,
        user_id=current_user.id,
        scan_id=req.scan_id,
        feedback_type=req.feedback_type,
        comments=req.comments
    )

@router.get("", response_model=List[FeedbackResponse])
def get_feedback(
    status: Optional[str] = Query(None),
    limit: int = 100,
    skip: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequirePermissions("feedback:read")),
    workspace: Workspace = Depends(get_current_workspace)
):
    """Get feedback items with optional status filtering"""
    return FeedbackService.get_feedback(
        db=db,
        workspace_id=workspace.id,
        status=status,
        limit=limit,
        skip=skip
    )

@router.get("/stats")
def get_feedback_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(RequirePermissions("feedback:read")),
    workspace: Workspace = Depends(get_current_workspace)
) -> Dict:
    """Get high level statistics for feedback dashboard"""
    return FeedbackService.get_stats(db=db, workspace_id=workspace.id)

@router.put("/{feedback_id}/approve", response_model=FeedbackResponse)
def approve_feedback(
    feedback_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequirePermissions("feedback:approve")),
    workspace: Workspace = Depends(get_current_workspace)
):
    """Approve feedback for export to retraining datasets"""
    return FeedbackService.approve_feedback(
        db=db,
        workspace_id=workspace.id,
        feedback_id=feedback_id,
        user_id=current_user.id
    )

@router.put("/{feedback_id}/reject", response_model=FeedbackResponse)
def reject_feedback(
    feedback_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(RequirePermissions("feedback:approve")), # Needs approve permission to reject too
    workspace: Workspace = Depends(get_current_workspace)
):
    """Reject invalid feedback"""
    return FeedbackService.reject_feedback(
        db=db,
        workspace_id=workspace.id,
        feedback_id=feedback_id,
        user_id=current_user.id
    )
