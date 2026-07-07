from typing import Any
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from src.api import deps
from src.core import security
from src.models.models import User, RefreshToken

router = APIRouter()

@router.get("/")
def get_active_sessions(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get all active sessions (refresh tokens) for the current user."""
    sessions = db.query(RefreshToken).filter(
        RefreshToken.user_id == current_user.id,
        RefreshToken.revoked == False
    ).order_by(desc(RefreshToken.created_at)).all()
    
    return [
        {
            "id": str(s.id),
            "created_at": s.created_at,
            "expires_at": s.expires_at,
            "user_agent": s.user_agent,
            "client_ip": s.client_ip
        }
        for s in sessions
    ]

@router.delete("/{session_id}")
def revoke_session(
    session_id: uuid.UUID,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Revoke a specific session."""
    from datetime import datetime
    
    session = db.query(RefreshToken).filter(
        RefreshToken.id == session_id,
        RefreshToken.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    if session.revoked:
        return {"detail": "Session already revoked"}
        
    session.revoked = True
    session.revoked_at = datetime.utcnow()
    db.commit()
    
    return {"detail": "Session revoked successfully"}

@router.delete("/")
def revoke_all_sessions(
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Revoke all sessions (panic button)."""
    from src.api.v1.auth import _revoke_all_user_tokens
    
    count = _revoke_all_user_tokens(db, current_user.id)
    
    # Invalidate token family
    current_user.refresh_token_version = (current_user.refresh_token_version or 0) + 1
    db.commit()
    
    # Clear cookies
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    
    return {"detail": f"Revoked {count} sessions successfully"}
