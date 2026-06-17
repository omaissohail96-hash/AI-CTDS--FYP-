from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from src.api import deps
from src.core import security
from src.core.config import settings
from src.models.models import User, Workspace
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService
from pydantic import BaseModel, EmailStr

router = APIRouter()

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    workspace_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

@router.post("/register", response_model=Token)
def register_user(
    *,
    request: Request,
    db: Session = Depends(deps.get_db),
    user_in: UserRegister
) -> Any:
    """
    Register a new user and create their workspace.
    """
    user = db.query(User).filter(User.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )
    
    # 1. Create Workspace
    new_workspace = Workspace(name=user_in.workspace_name)
    db.add(new_workspace)
    db.commit()
    db.refresh(new_workspace)
    
    # 2. Create User
    new_user = User(
        email=user_in.email,
        hashed_password=security.get_password_hash(user_in.password),
        full_name=user_in.full_name,
        workspace_id=new_workspace.id,
        role="admin"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # 3. Log the security event
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db, 
        action="user_registered", 
        module="auth", 
        workspace_id=new_workspace.id,
        user_id=new_user.id,
        metadata={"email": new_user.email}
    )
    try:
        UserBehaviorAnalyticsService.record_event(
            db=db,
            workspace_id=new_workspace.id,
            user_id=new_user.id,
            event_type="user_registered",
            ip_address=request.client.host if request.client else None,
            endpoint_accessed=str(request.url.path),
        )
    except Exception as exc:
        print(f"UBA registration telemetry failed: {exc}")

    return {
        "access_token": security.create_access_token(
            new_user.id, expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    }

@router.post("/login/access-token", response_model=Token)
def login_access_token(
    request: Request,
    db: Session = Depends(deps.get_db), form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login, retrieve an access token for future requests.
    """
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        if user:
            try:
                UserBehaviorAnalyticsService.record_event(
                    db=db,
                    workspace_id=user.workspace_id,
                    user_id=user.id,
                    event_type="login_failed",
                    ip_address=request.client.host if request.client else None,
                    endpoint_accessed=str(request.url.path),
                )
            except Exception as exc:
                print(f"UBA failed-login telemetry failed: {exc}")
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # Log successful login
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db, 
        action="login_success", 
        module="auth", 
        workspace_id=user.workspace_id,
        user_id=user.id
    )
    try:
        UserBehaviorAnalyticsService.record_event(
            db=db,
            workspace_id=user.workspace_id,
            user_id=user.id,
            event_type="login_success",
            ip_address=request.client.host if request.client else None,
            endpoint_accessed=str(request.url.path),
        )
    except Exception as exc:
        print(f"UBA login telemetry failed: {exc}")

    return {
        "access_token": security.create_access_token(
            user.id, expires_delta=access_token_expires
        ),
        "token_type": "bearer",
    }
