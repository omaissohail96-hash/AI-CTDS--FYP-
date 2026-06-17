from datetime import datetime
from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from src.core.config import settings
from src.core.database import SessionLocal
from src.models.models import User, APIKey, Workspace
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService
import uuid

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token",
    auto_error=False,
)
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

def get_db() -> Generator:
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

async def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> Optional[User]:
    if not token:
        return None

    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=["HS256"]
        )
        token_data = payload.get("sub")
        if token_data is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate credentials",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    
    # Cast to UUID for SQLAlchemy compatibility with SQLite/Postgres
    try:
        user_uuid = uuid.UUID(token_data)
    except ValueError:
        raise HTTPException(status_code=403, detail="Invalid token subject")

    user = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

async def get_current_workspace(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user),
    api_key: Optional[str] = Depends(api_key_header)
) -> Workspace:
    # Scenario 1: Accessing via User Session (Dashboard)
    if current_user:
        workspace = db.query(Workspace).filter(Workspace.id == current_user.workspace_id).first()
        if not workspace:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return workspace
    
    # Scenario 2: Accessing via API Key (Enterprise / External)
    if api_key:
        import hashlib
        # We store SHA-256 hashes in the DB for security
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        key_entry = db.query(APIKey).filter(APIKey.key_hash == key_hash, APIKey.is_active == True).first()
        if not key_entry:
            raise HTTPException(status_code=403, detail="Invalid or inactive API Key")
        
        # Update last used timestamp (Fire and forget style)
        key_entry.last_used = datetime.utcnow()
        try:
            UserBehaviorAnalyticsService.record_event(
                db=db,
                workspace_id=key_entry.workspace_id,
                user_id=None,
                event_type="api_key_usage",
                endpoint_accessed="workspace_auth",
                metadata={"api_key_label": key_entry.label},
                commit=False,
            )
        except Exception as exc:
            print(f"UBA API-key telemetry failed: {exc}")
        db.commit()
        
        workspace = db.query(Workspace).filter(Workspace.id == key_entry.workspace_id).first()
        return workspace

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (JWT or X-API-KEY)",
    )
