"""
Prevention System API Endpoints
Intrusion Prevention System (IPS) management and monitoring
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
import uuid

from src.api import deps
from src.models.models import Workspace, User, BlockedEntity
from src.services.prevention_engine import PreventionEngine
from src.utils.audit import AuditLogger

router = APIRouter()


class BlockedEntityResponse(BaseModel):
    """Blocked entity response schema"""
    id: str
    entity: str
    entity_type: str
    severity: str
    reason: str
    blocked_until: str
    auto_generated: bool
    resolved_status: bool
    prevention_reason: str
    blocked_request_count: int
    created_at: str
    
    class Config:
        from_attributes = True


class PreventionStatsResponse(BaseModel):
    """Prevention statistics response"""
    active_blocks_count: int
    total_blocked_requests_24h: int
    blocks_by_severity: dict
    blocks_by_entity_type: dict
    auto_generated_blocks: int
    manual_blocks: int
    auto_unblock_scheduled: int


class UnblockRequest(BaseModel):
    """Request to unblock an entity"""
    reason: Optional[str] = None


class PreventionHistoryResponse(BaseModel):
    """Prevention history entry"""
    id: str
    entity: str
    entity_type: str
    severity: str
    reason: str
    blocked_until: str
    blocked_request_count: int
    created_at: str


class PaginatedBlockedEntitiesResponse(BaseModel):
    """Paginated blocked entities response"""
    total: int
    skip: int
    limit: int
    items: List[BlockedEntityResponse]


class PaginatedHistoryResponse(BaseModel):
    """Paginated history response"""
    total: int
    skip: int
    limit: int
    items: List[PreventionHistoryResponse]


class PreventionReasoningResponse(BaseModel):
    """Prevention reasoning explanation"""
    blocked_entity_id: str
    reasoning: str


@router.get("/blocked", response_model=PaginatedBlockedEntitiesResponse)
async def get_blocked_entities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    active_only: bool = Query(True),
    entity_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Get paginated list of blocked entities
    
    Query Parameters:
    - active_only: Only show active (non-expired) blocks
    - entity_type: Filter by IP, URL, or DOMAIN
    - severity: Filter by LOW, MEDIUM, HIGH, CRITICAL
    """
    try:
        entities, total = PreventionEngine.get_blocked_entities(
            db,
            workspace_id=workspace.id,
            skip=skip,
            limit=limit,
            active_only=active_only,
            entity_type_filter=entity_type,
            severity_filter=severity
        )
        
        return PaginatedBlockedEntitiesResponse(
            total=total,
            skip=skip,
            limit=limit,
            items=[BlockedEntityResponse.from_orm(e) for e in entities]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=PreventionStatsResponse)
async def get_prevention_stats(
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Get comprehensive prevention statistics for workspace
    
    Returns:
    - active_blocks_count: Number of currently active blocks
    - total_blocked_requests_24h: Requests blocked in last 24 hours
    - blocks_by_severity: Distribution by severity level
    - blocks_by_entity_type: Distribution by entity type (IP/URL/DOMAIN)
    - auto_generated_blocks: Blocks created automatically by system
    - manual_blocks: Blocks created manually by users
    - auto_unblock_scheduled: Blocks with auto-unblock scheduled
    """
    try:
        stats = PreventionEngine.get_prevention_stats(db, workspace_id=workspace.id)
        return PreventionStatsResponse(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock/{blocked_entity_id}", response_model=BlockedEntityResponse)
async def unblock_entity(
    blocked_entity_id: str,
    request: UnblockRequest,
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Manually unblock a previously blocked entity
    
    Requires admin or developer role to unblock entities
    """
    try:
        # Verify user has permission to unblock
        if current_user.role not in ["admin", "developer"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions to unblock entities")
        
        # Parse UUID
        try:
            entity_uuid = uuid.UUID(blocked_entity_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid entity ID format")
        
        # Check if entity exists and belongs to workspace
        blocked_entity = db.query(BlockedEntity).filter(
            BlockedEntity.id == entity_uuid,
            BlockedEntity.workspace_id == workspace.id
        ).first()
        
        if not blocked_entity:
            raise HTTPException(status_code=404, detail="Blocked entity not found")
        
        # Unblock the entity
        unblocked = PreventionEngine.unblock_entity(
            db,
            workspace_id=workspace.id,
            blocked_entity_id=entity_uuid,
            user_id=current_user.id
        )
        
        return BlockedEntityResponse.from_orm(unblocked)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history", response_model=PaginatedHistoryResponse)
async def get_prevention_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    hours: int = Query(24, ge=1, le=720),  # Up to 30 days
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Get prevention action history for specified time period
    
    Query Parameters:
    - hours: Number of hours to look back (default: 24, max: 720)
    - skip, limit: Pagination parameters
    """
    try:
        history, total = PreventionEngine.get_prevention_history(
            db,
            workspace_id=workspace.id,
            skip=skip,
            limit=limit,
            hours=hours
        )
        
        return PaginatedHistoryResponse(
            total=total,
            skip=skip,
            limit=limit,
            items=[PreventionHistoryResponse.from_orm(h) for h in history]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reasoning/{blocked_entity_id}", response_model=PreventionReasoningResponse)
async def get_prevention_reasoning(
    blocked_entity_id: str,
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Get detailed reasoning for why an entity was blocked
    
    Provides intelligent explanation of the prevention decision including
    severity level, prevention policy applied, and related investigations
    """
    try:
        # Parse UUID
        try:
            entity_uuid = uuid.UUID(blocked_entity_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid entity ID format")
        
        # Verify entity belongs to workspace
        blocked_entity = db.query(BlockedEntity).filter(
            BlockedEntity.id == entity_uuid,
            BlockedEntity.workspace_id == workspace.id
        ).first()
        
        if not blocked_entity:
            raise HTTPException(status_code=404, detail="Blocked entity not found")
        
        reasoning = PreventionEngine.get_prevention_reasoning(db, entity_uuid)
        
        return PreventionReasoningResponse(
            blocked_entity_id=blocked_entity_id,
            reasoning=reasoning
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cleanup")
async def trigger_cleanup(
    current_user: User = Depends(deps.get_current_user),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
):
    """
    Manually trigger cleanup of expired blocks
    
    Note: Cleanup is also scheduled to run automatically every 5 minutes
    Admin only endpoint
    """
    try:
        if current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Only admins can trigger cleanup")
        
        cleaned_count = PreventionEngine.cleanup_expired_blocks(db)
        
        # Log cleanup action
        AuditLogger.log(
            db,
            action="cleanup_expired_blocks",
            module="prevention_engine",
            status="success",
            workspace_id=workspace.id,
            user_id=current_user.id,
            metadata={"expired_blocks_cleaned": cleaned_count}
        )
        
        return {
            "status": "success",
            "expired_blocks_cleaned": cleaned_count
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
