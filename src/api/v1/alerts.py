"""
Alert Management API Endpoints
Real-time alert management and statistics
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
import uuid

from src.api import deps
from src.models.models import Workspace, Alert
from src.services.alert_service import AlertService, AlertSeverity
from src.utils.audit import AuditLogger

router = APIRouter()


class AlertResponse(BaseModel):
    """Alert response schema"""
    id: str
    workspace_id: str
    alert_type: str
    severity: str
    title: str
    description: str
    entity: str
    entity_type: Optional[str]
    source_vector: str
    risk_score: int
    ml_confidence: int
    indicators: Optional[list]
    correlated_events: int
    recommended_action: str
    resolved_status: bool
    resolved_at: Optional[str]
    notification_sent: bool
    email_sent: bool
    created_at: str
    
    class Config:
        from_attributes = True


class AlertResolveRequest(BaseModel):
    """Request to resolve an alert"""
    resolution_notes: Optional[str] = None


class AlertStatsResponse(BaseModel):
    """Alert statistics response"""
    total_alerts: int
    resolved_alerts: int
    unresolved_alerts: int
    unresolved_by_severity: dict
    top_alert_types: list
    top_entities: list


@router.get("/alerts", response_model=dict)
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    resolved: Optional[bool] = Query(None, description="Filter by resolution status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get alerts with optional filtering
    
    - **severity**: Filter by severity level (LOW, MEDIUM, HIGH, CRITICAL)
    - **resolved**: Filter by resolution status (true/false)
    - **limit**: Number of results (default 50, max 200)
    - **offset**: Pagination offset (default 0)
    
    Returns paginated alert list with statistics
    """
    try:
        # Validate severity if provided
        if severity and severity not in [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            raise HTTPException(status_code=400, detail="Invalid severity level")
        
        alerts, total = AlertService.get_alerts(
            db,
            workspace.id,
            severity=severity,
            resolved=resolved,
            limit=limit,
            offset=offset,
        )
        
        return {
            "alerts": [AlertResponse.from_orm(alert).dict() for alert in alerts],
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {str(e)}")


@router.get("/alerts/recent", response_model=dict)
async def get_recent_alerts(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get recent alerts from the last N hours
    
    - **hours**: Time period to fetch (default 24, max 7 days)
    - **limit**: Maximum number of results (default 20)
    
    Returns recent alerts ordered by timestamp descending
    """
    try:
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        alerts = db.query(Alert).filter(
            Alert.workspace_id == workspace.id,
            Alert.created_at >= cutoff_time,
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        
        return {
            "alerts": [AlertResponse.from_orm(alert).dict() for alert in alerts],
            "count": len(alerts),
            "hours": hours,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch recent alerts: {str(e)}")


@router.get("/alerts/critical", response_model=dict)
async def get_critical_alerts(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get all unresolved critical alerts
    
    Returns list of unresolved CRITICAL severity alerts
    """
    try:
        alerts = db.query(Alert).filter(
            Alert.workspace_id == workspace.id,
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.resolved_status == False,
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        
        return {
            "critical_alerts": [AlertResponse.from_orm(alert).dict() for alert in alerts],
            "count": len(alerts),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch critical alerts: {str(e)}")


@router.get("/alerts/stats", response_model=AlertStatsResponse)
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get alert statistics for workspace
    
    - **hours**: Time period to analyze (default 24, max 7 days)
    
    Returns comprehensive alert statistics including severity distribution
    """
    try:
        stats = AlertService.get_alert_stats(db, workspace.id, time_hours=hours)
        return AlertStatsResponse(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alert stats: {str(e)}")


@router.get("/alerts/unresolved-count", response_model=dict)
async def get_unresolved_count(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get count of unresolved alerts by severity
    
    Returns quick summary for alert badge counters
    """
    try:
        counts = AlertService.get_unresolved_alert_count(db, workspace.id)
        total = sum(counts.values())
        
        return {
            "total": total,
            "by_severity": counts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch unresolved count: {str(e)}")


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert_detail(
    alert_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Get detailed information about a specific alert
    
    Returns full alert details including indicators and recommended actions
    """
    try:
        alert = db.query(Alert).filter(
            Alert.id == alert_id,
            Alert.workspace_id == workspace.id,
        ).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return AlertResponse.from_orm(alert)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alert detail: {str(e)}")


@router.post("/alerts/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    request: AlertResolveRequest,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    current_user = Depends(deps.get_current_user),
):
    """
    Mark an alert as resolved
    
    Resolves the alert and logs the action to audit trail
    """
    try:
        alert = db.query(Alert).filter(
            Alert.id == alert_id,
            Alert.workspace_id == workspace.id,
        ).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        if alert.resolved_status:
            raise HTTPException(status_code=400, detail="Alert is already resolved")
        
        resolved_alert = AlertService.resolve_alert(
            db,
            alert.id,
            current_user.id,
            request.resolution_notes,
        )
        
        return AlertResponse.from_orm(resolved_alert)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {str(e)}")


@router.post("/alerts/{alert_id}/escalate", response_model=AlertResponse)
async def escalate_alert(
    alert_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    current_user = Depends(deps.get_current_user),
):
    """
    Escalate alert severity
    
    Increases alert severity by one level and logs the action
    """
    try:
        alert = db.query(Alert).filter(
            Alert.id == alert_id,
            Alert.workspace_id == workspace.id,
        ).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Escalate severity
        severity_order = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        current_idx = severity_order.index(alert.severity)
        
        if current_idx < len(severity_order) - 1:
            new_severity = severity_order[current_idx + 1]
            old_severity = alert.severity
            alert.severity = new_severity
            
            # Log escalation
            from src.models.models import AlertHistory
            history = AlertHistory(
                alert_id=alert.id,
                workspace_id=alert.workspace_id,
                user_id=current_user.id,
                action="escalated",
                previous_severity=old_severity,
                new_severity=new_severity,
            )
            db.add(history)
            
            # Audit log
            AuditLogger.log(
                db,
                action="alert_escalated",
                module="alert_service",
                status="success",
                workspace_id=workspace.id,
                user_id=current_user.id,
                metadata={
                    "alert_id": alert_id,
                    "from_severity": old_severity,
                    "to_severity": new_severity,
                }
            )
            
            db.commit()
        
        return AlertResponse.from_orm(alert)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to escalate alert: {str(e)}")


@router.get("/alerts/search", response_model=dict)
async def search_alerts(
    query: str = Query(..., min_length=1, max_length=255),
    severity: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
):
    """
    Search alerts by entity, title, or description
    
    - **query**: Search term (entity, domain, IP, etc.)
    - **severity**: Optional severity filter
    - **limit**: Maximum results
    
    Returns alerts matching the search criteria
    """
    try:
        search_filter = Alert.entity.ilike(f"%{query}%") | Alert.title.ilike(f"%{query}%") | Alert.description.ilike(f"%{query}%")
        
        alerts_query = db.query(Alert).filter(
            Alert.workspace_id == workspace.id,
            search_filter,
        )
        
        if severity:
            alerts_query = alerts_query.filter(Alert.severity == severity)
        
        alerts = alerts_query.order_by(Alert.created_at.desc()).limit(limit).all()
        
        return {
            "results": [AlertResponse.from_orm(alert).dict() for alert in alerts],
            "count": len(alerts),
            "query": query,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")
