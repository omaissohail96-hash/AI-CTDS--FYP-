"""
CyberGuard AI – API Key Management Router
=========================================

All endpoints require JWT authentication (dashboard users managing their own
workspace's keys).  External customers never call these endpoints; they use
the keys themselves to authenticate detection requests.

RBAC:
  GET  /api-keys/            → api_keys:read
  GET  /api-keys/{id}/stats  → api_keys:read
  POST /api-keys/create      → api_keys:write
  POST /api-keys/{id}/rotate → api_keys:write
  DELETE /api-keys/{id}      → api_keys:write
  (workspace_admin, super_admin only)
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.deps import RequirePermissions, get_current_workspace, get_db
from src.models.models import APIKey, APIKeyAuditLog, Workspace, User
from src.utils.audit import AuditLogger

router = APIRouter()

API_KEY_PREFIX = "cg_live_"


# ── Helpers ────────────────────────────────────────────────────────────────
def _generate_raw_key() -> str:
    """Return a cryptographically secure API key string with 32 bytes of entropy."""
    return f"{API_KEY_PREFIX}{secrets.token_hex(32)}"   # 64-char hex = 256 bits


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Request / Response schemas ─────────────────────────────────────────────
class APIKeyCreateRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=128)
    expires_in_days: Optional[int] = Field(
        None,
        description="Number of days until key expires. Omit for non-expiring key.",
        ge=1,
        le=3650,
    )


class APIKeyListItem(BaseModel):
    id: str
    label: str
    is_active: bool
    created_at: Optional[str]
    last_used: Optional[str]
    expires_at: Optional[str]
    usage_count: int
    successful_requests: int
    failed_requests: int
    last_used_ip: Optional[str]
    rotated_at: Optional[str]

    class Config:
        from_attributes = True


class APIKeyCreateResponse(BaseModel):
    id: str
    label: str
    api_key: str  # plaintext, shown only once
    expires_at: Optional[str]
    message: str = "Store this key securely — it will NOT be shown again."


class APIKeyStatsResponse(BaseModel):
    id: str
    label: str
    is_active: bool
    usage_count: int
    successful_requests: int
    failed_requests: int
    last_used: Optional[str]
    last_used_ip: Optional[str]
    expires_at: Optional[str]
    created_at: Optional[str]
    rotated_at: Optional[str]
    recent_audit_logs: List[Dict[str, Any]]


# ── Utilities ──────────────────────────────────────────────────────────────
def _fmt(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _key_to_item(k: APIKey) -> APIKeyListItem:
    return APIKeyListItem(
        id=str(k.id),
        label=k.label,
        is_active=k.is_active,
        created_at=_fmt(k.created_at),
        last_used=_fmt(k.last_used),
        expires_at=_fmt(k.expires_at),
        usage_count=k.usage_count or 0,
        successful_requests=k.successful_requests or 0,
        failed_requests=k.failed_requests or 0,
        last_used_ip=k.last_used_ip,
        rotated_at=_fmt(k.rotated_at),
    )


def _get_owned_key(key_id: str, workspace: Workspace, db: Session) -> APIKey:
    """Fetch a key that belongs to this workspace, or raise 404."""
    try:
        kid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid API key ID format.")

    key = db.query(APIKey).filter(
        APIKey.id == kid,
        APIKey.workspace_id == workspace.id,
    ).first()

    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")
    return key


# ── Endpoints ──────────────────────────────────────────────────────────────
@router.post("/create", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: APIKeyCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    workspace: Workspace = Depends(get_current_workspace),
    current_user: User = Depends(RequirePermissions("api_keys:write")),
) -> Any:
    """
    Generate a new API key for the workspace.
    Requires api_keys:write (workspace_admin, super_admin).

    The raw key is returned **once** in the response and never stored.
    Only its SHA-256 hash is persisted.
    """
    raw_key = _generate_raw_key()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
        if payload.expires_in_days
        else None
    )

    new_key = APIKey(
        workspace_id=workspace.id,
        key_hash=_hash_key(raw_key),
        label=payload.label,
        is_active=True,
        expires_at=expires_at,
        usage_count=0,
        successful_requests=0,
        failed_requests=0,
    )
    db.add(new_key)
    db.flush()

    log = APIKeyAuditLog(
        id=str(uuid.uuid4()),
        api_key_id=str(new_key.id),
        workspace_id=str(workspace.id),
        endpoint=str(request.url.path),
        method=request.method,
        status_code=201,
        client_ip=_get_ip(request),
        event="created",
    )
    db.add(log)

    AuditLogger.log(
        db,
        action="api_key_created",
        module="api_keys",
        workspace_id=workspace.id,
        user_id=current_user.id,
        metadata={"label": payload.label},
    )
    db.commit()

    return APIKeyCreateResponse(
        id=str(new_key.id),
        label=new_key.label,
        api_key=raw_key,
        expires_at=_fmt(expires_at),
    )


@router.get("/", response_model=List[APIKeyListItem])
def list_api_keys(
    db: Session = Depends(get_db),
    workspace: Workspace = Depends(get_current_workspace),
    _: User = Depends(RequirePermissions("api_keys:read")),
) -> Any:
    """
    List all API keys for the workspace (hashed values never exposed).
    Requires api_keys:read (workspace_admin, super_admin).
    """
    keys = (
        db.query(APIKey)
        .filter(APIKey.workspace_id == workspace.id)
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [_key_to_item(k) for k in keys]


@router.get("/{key_id}/stats", response_model=APIKeyStatsResponse)
def get_api_key_stats(
    key_id: str,
    db: Session = Depends(get_db),
    workspace: Workspace = Depends(get_current_workspace),
    _: User = Depends(RequirePermissions("api_keys:read")),
) -> Any:
    """
    Detailed usage statistics and recent audit logs for a single API key.
    Requires api_keys:read (workspace_admin, super_admin).
    """
    key = _get_owned_key(key_id, workspace, db)

    recent_logs = (
        db.query(APIKeyAuditLog)
        .filter(APIKeyAuditLog.api_key_id == key.id)
        .order_by(APIKeyAuditLog.created_at.desc())
        .limit(50)
        .all()
    )

    audit_entries = [
        {
            "id": str(log.id),
            "endpoint": log.endpoint,
            "method": log.method,
            "status_code": log.status_code,
            "client_ip": log.client_ip,
            "response_ms": log.response_ms,
            "event": log.event,
            "created_at": _fmt(log.created_at),
        }
        for log in recent_logs
    ]

    return APIKeyStatsResponse(
        id=str(key.id),
        label=key.label,
        is_active=key.is_active,
        usage_count=key.usage_count or 0,
        successful_requests=key.successful_requests or 0,
        failed_requests=key.failed_requests or 0,
        last_used=_fmt(key.last_used),
        last_used_ip=key.last_used_ip,
        expires_at=_fmt(key.expires_at),
        created_at=_fmt(key.created_at),
        rotated_at=_fmt(key.rotated_at),
        recent_audit_logs=audit_entries,
    )


@router.delete("/{key_id}", status_code=status.HTTP_200_OK)
def revoke_api_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
    workspace: Workspace = Depends(get_current_workspace),
    current_user: User = Depends(RequirePermissions("api_keys:write")),
) -> Any:
    """
    Revoke an API key (soft-delete).
    Requires api_keys:write (workspace_admin, super_admin).
    """
    key = _get_owned_key(key_id, workspace, db)

    key.is_active = False
    log = APIKeyAuditLog(
        id=str(uuid.uuid4()),
        api_key_id=str(key.id),
        workspace_id=str(workspace.id),
        endpoint=str(request.url.path),
        method=request.method,
        status_code=200,
        client_ip=_get_ip(request),
        event="revoked",
    )
    db.add(log)
    AuditLogger.log(
        db,
        action="api_key_revoked",
        module="api_keys",
        workspace_id=workspace.id,
        user_id=current_user.id,
        metadata={"key_id": key_id, "label": key.label},
    )
    db.commit()
    return {"message": f"API key '{key.label}' has been revoked."}


@router.post("/{key_id}/rotate", response_model=APIKeyCreateResponse)
def rotate_api_key(
    key_id: str,
    request: Request,
    db: Session = Depends(get_db),
    workspace: Workspace = Depends(get_current_workspace),
    current_user: User = Depends(RequirePermissions("api_keys:write")),
) -> Any:
    """
    Rotate an API key (new hash, new plaintext shown once).
    Requires api_keys:write (workspace_admin, super_admin).
    """
    key = _get_owned_key(key_id, workspace, db)

    if not key.is_active:
        raise HTTPException(status_code=400, detail="Cannot rotate a revoked API key.")

    raw_key = _generate_raw_key()
    key.key_hash = _hash_key(raw_key)
    key.rotated_at = datetime.now(timezone.utc)

    log = APIKeyAuditLog(
        id=str(uuid.uuid4()),
        api_key_id=str(key.id),
        workspace_id=str(workspace.id),
        endpoint=str(request.url.path),
        method=request.method,
        status_code=200,
        client_ip=_get_ip(request),
        event="rotated",
    )
    db.add(log)
    AuditLogger.log(
        db,
        action="api_key_rotated",
        module="api_keys",
        workspace_id=workspace.id,
        user_id=current_user.id,
        metadata={"key_id": key_id, "label": key.label},
    )
    db.commit()

    return APIKeyCreateResponse(
        id=str(key.id),
        label=key.label,
        api_key=raw_key,
        expires_at=_fmt(key.expires_at),
        message=(
            "Key rotated successfully. Store the new key securely — "
            "it will NOT be shown again."
        ),
    )


def _get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
