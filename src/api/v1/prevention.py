"""
Prevention System API Endpoints
Intrusion Prevention System (IPS) management and monitoring

RBAC:
  GET  routes (blocked, stats, history, reasoning) → prevention:read
  POST routes (unblock, cleanup)                   → prevention:write
  (replaces hardcoded role checks)
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
import uuid

from src.api import deps
from src.api.deps import RequirePermissions
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
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    _: User = Depends(RequirePermissions("prevention:read")),
):
    """
    Get paginated list of blocked entities. Requires prevention:read.
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
            total=total, skip=skip, limit=limit,
            items=[BlockedEntityResponse.from_orm(e) for e in entities]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=PreventionStatsResponse)
async def get_prevention_stats(
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    _: User = Depends(RequirePermissions("prevention:read")),
):
    """Get comprehensive prevention statistics. Requires prevention:read."""
    try:
        stats = PreventionEngine.get_prevention_stats(db, workspace_id=workspace.id)
        return PreventionStatsResponse(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/unblock/{blocked_entity_id}", response_model=BlockedEntityResponse)
async def unblock_entity(
    blocked_entity_id: str,
    request: UnblockRequest,
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(RequirePermissions("prevention:write")),
):
    """
    Manually unblock a previously blocked entity.
    Requires prevention:write (security_analyst, workspace_admin, super_admin).
    """
    try:
        try:
            entity_uuid = uuid.UUID(blocked_entity_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid entity ID format")

        blocked_entity = db.query(BlockedEntity).filter(
            BlockedEntity.id == entity_uuid,
            BlockedEntity.workspace_id == workspace.id
        ).first()

        if not blocked_entity:
            raise HTTPException(status_code=404, detail="Blocked entity not found")

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
    hours: int = Query(24, ge=1, le=720),
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    _: User = Depends(RequirePermissions("prevention:read")),
):
    """Get prevention action history. Requires prevention:read."""
    try:
        history, total = PreventionEngine.get_prevention_history(
            db, workspace_id=workspace.id, skip=skip, limit=limit, hours=hours
        )
        return PaginatedHistoryResponse(
            total=total, skip=skip, limit=limit,
            items=[PreventionHistoryResponse.from_orm(h) for h in history]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reasoning/{blocked_entity_id}", response_model=PreventionReasoningResponse)
async def get_prevention_reasoning(
    blocked_entity_id: str,
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    _: User = Depends(RequirePermissions("prevention:read")),
):
    """Get detailed reasoning for why an entity was blocked. Requires prevention:read."""
    try:
        try:
            entity_uuid = uuid.UUID(blocked_entity_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid entity ID format")

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
    workspace: Workspace = Depends(deps.get_current_workspace),
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(RequirePermissions("prevention:write")),
):
    """
    Manually trigger cleanup of expired blocks.
    Requires prevention:write (replaces old hardcoded role == 'admin' check).
    """
    try:
        cleaned_count = PreventionEngine.cleanup_expired_blocks(db)

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
