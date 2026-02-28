from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.api import deps
from src.models.models import APIKey, Workspace
import secrets
import hashlib
from pydantic import BaseModel

router = APIRouter()

class APIKeyCreate(BaseModel):
    label: str

class APIKeyResponse(BaseModel):
    id: str
    label: str
    key: Optional[str] = None # Only returned once upon creation
    is_active: bool
    created_at: str

@router.post("/keys", response_model=Dict[str, Any])
def create_api_key(
    *,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace),
    key_in: APIKeyCreate
) -> Any:
    """
    Generate a new API Key for the current workspace.
    """
    # Generate a secure random key
    raw_key = f"cg_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    
    new_key = APIKey(
        workspace_id=workspace.id,
        key_hash=key_hash,
        label=key_in.label
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)
    
    # Log key creation
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db, 
        action="api_key_created", 
        module="workspace", 
        workspace_id=workspace.id,
        metadata={"label": key_in.label}
    )

    return {
        "id": str(new_key.id),
        "label": new_key.label,
        "api_key": raw_key, # !!! IMPORTANT: Only shown once
        "message": "Store this key securely. It will not be shown again."
    }

@router.get("/keys")
def list_api_keys(
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace)
) -> Any:
    """
    List all active API keys for the workspace (hashed).
    """
    keys = db.query(APIKey).filter(APIKey.workspace_id == workspace.id).all()
    return [{"id": k.id, "label": k.label, "is_active": k.is_active, "created_at": k.created_at} for k in keys]

@router.delete("/keys/{key_id}")
def revoke_api_key(
    key_id: str,
    db: Session = Depends(deps.get_db),
    workspace: Workspace = Depends(deps.get_current_workspace)
) -> Any:
    """
    Revoke/Delete an API key.
    """
    key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.workspace_id == workspace.id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API Key not found")
    
    # Log revocation
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db, 
        action="api_key_revoked", 
        module="workspace", 
        workspace_id=workspace.id,
        metadata={"key_id": str(key_id)}
    )

    db.delete(key)
    db.commit()
    return {"message": "API Key revoked successfully"}
