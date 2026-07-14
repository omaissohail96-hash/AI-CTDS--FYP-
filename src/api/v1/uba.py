"""
User Behavior Analytics (UBA) Endpoints

RBAC:
  All UBA routes → uba:read permission
  (security_analyst, workspace_admin, super_admin)
"""
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.api import deps
from src.api.deps import RequirePermissions
from src.models.models import User, UserBehaviorEvent, UserBehaviorProfile, Workspace
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService

router = APIRouter()


@router.get("/stats")
async def get_uba_stats(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("uba:read")),
) -> Dict[str, Any]:
    return UserBehaviorAnalyticsService.workspace_stats(db, workspace.id)


@router.get("/users")
async def get_uba_users(
    limit: int = 50,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("uba:read")),
) -> List[Dict[str, Any]]:
    return UserBehaviorAnalyticsService.top_anomalous_users(
        db, workspace.id, limit=min(max(limit, 1), 200)
    )


@router.get("/anomalies")
async def get_uba_anomalies(
    limit: int = 100,
    risk_level: str | None = Query(None),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("uba:read")),
) -> List[Dict[str, Any]]:
    query = db.query(UserBehaviorEvent).filter(
        UserBehaviorEvent.workspace_id == workspace.id,
        UserBehaviorEvent.anomaly_score >= UserBehaviorAnalyticsService.ALERT_THRESHOLD,
    )
    if risk_level:
        query = query.filter(UserBehaviorEvent.risk_level == risk_level.upper())
    events = query.order_by(UserBehaviorEvent.timestamp.desc()).limit(min(max(limit, 1), 500)).all()
    return [UserBehaviorAnalyticsService.serialize_event(event) for event in events]


@router.get("/user/{user_id}")
async def get_uba_user_detail(
    user_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("uba:read")),
) -> Dict[str, Any]:
    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user id")
    return UserBehaviorAnalyticsService.user_detail(db, workspace.id, parsed_user_id)


@router.get("/risk-scores")
async def get_uba_risk_scores(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    _: User = Depends(RequirePermissions("uba:read")),
) -> List[Dict[str, Any]]:
    profiles = db.query(UserBehaviorProfile).filter(
        UserBehaviorProfile.workspace_id == workspace.id
    ).all()
    scores = []
    for profile in profiles:
        latest_event = db.query(UserBehaviorEvent).filter(
            UserBehaviorEvent.workspace_id == workspace.id,
            UserBehaviorEvent.user_id == profile.user_id,
        ).order_by(UserBehaviorEvent.timestamp.desc()).first()
        score = latest_event.anomaly_score if latest_event else profile.baseline_risk_score
        scores.append({
            "user_id": str(profile.user_id) if profile.user_id else None,
            "risk_score": int(score or 0),
            "risk_level": UserBehaviorAnalyticsService.risk_level(int(score or 0)),
            "baseline_risk_score": profile.baseline_risk_score,
            "last_seen": latest_event.timestamp.isoformat() if latest_event and latest_event.timestamp else None,
        })
    return sorted(scores, key=lambda item: item["risk_score"], reverse=True)
