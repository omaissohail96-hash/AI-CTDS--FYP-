"""
Updated auth routes with HttpOnly cookie-based JWT,
refresh token rotation, and explicit logout.

Backward compatible: Bearer token still returned in response body
for API clients. Cookie-based auth is the browser session path.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from src.api import deps
from src.core import security
from src.core.config import settings
from src.core.trusted_proxy import get_client_ip
from src.models.models import User, Workspace, RefreshToken, UserMFA
from src.models.models import WorkspaceUser
from src.core.rbac import WorkspaceRole
from src.services.user_behavior_analytics import UserBehaviorAnalyticsService

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    workspace_name: Optional[str] = None
    workspace_id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int  # seconds until access token expires


# ── Helpers ───────────────────────────────────────────────────────────────────

def _set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    """Set HttpOnly Secure cookies for browser session auth."""
    cookie_kwargs = {
        "httponly": settings.COOKIE_HTTPONLY,
        "samesite": settings.COOKIE_SAMESITE,
        "secure": settings.COOKIE_SECURE,
    }
    if settings.COOKIE_DOMAIN:
        cookie_kwargs["domain"] = settings.COOKIE_DOMAIN

    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **cookie_kwargs,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        **cookie_kwargs,
    )


def _store_refresh_token(db: Session, user: User, token: str, request: Request) -> RefreshToken:
    """Persist a refresh token hash in the database."""
    payload = security.decode_refresh_token(token)
    jti = payload.get("jti") if payload else None
    expires_at_ts = payload.get("exp") if payload else None

    import datetime as dt
    expires_at = (
        dt.datetime.utcfromtimestamp(expires_at_ts)
        if expires_at_ts
        else dt.datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    )

    refresh_entry = RefreshToken(
        user_id=user.id,
        token_hash=security.hash_refresh_token(token),
        jti=jti,
        expires_at=expires_at,
        user_agent=request.headers.get("user-agent", "")[:512],
        client_ip=get_client_ip(request),
    )
    db.add(refresh_entry)
    db.commit()
    return refresh_entry


def _record_successful_login(db: Session, user: User, request: Request) -> None:
    """Persist a successful sign-in for both password and federated auth."""
    client_ip = get_client_ip(request)
    user.last_login_ip = client_ip
    user.last_login_at = datetime.utcnow()
    user.login_count = (user.login_count or 0) + 1
    db.commit()

    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db,
        action="login_success",
        module="auth",
        workspace_id=user.workspace_id,
        user_id=user.id,
        metadata={"ip": client_ip},
    )
    try:
        UserBehaviorAnalyticsService.record_event(
            db=db,
            workspace_id=user.workspace_id,
            user_id=user.id,
            event_type="login_success",
            ip_address=client_ip,
            endpoint_accessed=str(request.url.path),
        )
    except Exception as exc:
        print(f"UBA login telemetry failed: {exc}")


def _revoke_refresh_token(db: Session, token: str) -> bool:
    """Mark a refresh token as revoked by its hash."""
    from datetime import datetime
    token_hash = security.hash_refresh_token(token)
    entry = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked == False,
    ).first()
    if entry:
        entry.revoked = True
        entry.revoked_at = datetime.utcnow()
        db.commit()
        return True
    return False


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register", response_model=Token)
def register_user(
    *,
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
    user_in: UserRegister,
) -> Any:
    """Register a workspace owner or a pending member of an existing workspace."""
    user = db.query(User).filter(User.email == user_in.email).first()
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )

    joining_workspace = None
    if user_in.workspace_id:
        try:
            workspace_uuid = uuid.UUID(user_in.workspace_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid workspace ID.")
        joining_workspace = db.query(Workspace).filter(Workspace.id == workspace_uuid).first()
        if not joining_workspace:
            raise HTTPException(status_code=404, detail="Workspace ID was not found.")
    elif not (user_in.workspace_name or "").strip():
        raise HTTPException(status_code=422, detail="Workspace name is required when creating a workspace.")

    # 1. Create a workspace only for users who explicitly create one.
    new_workspace = joining_workspace or Workspace(name=user_in.workspace_name.strip())
    if not joining_workspace:
        db.add(new_workspace)
        db.commit()
        db.refresh(new_workspace)

    # 2. Create User
    new_user = User(
        email=user_in.email,
        hashed_password=security.get_password_hash(user_in.password),
        full_name=user_in.full_name,
        workspace_id=new_workspace.id,
        role=WorkspaceRole.VIEWER.value if joining_workspace else WorkspaceRole.OWNER.value,
        refresh_token_version=0,
    )
    db.add(new_user)
    db.flush()
    db.add(WorkspaceUser(
        workspace_id=new_workspace.id,
        user_id=new_user.id,
        role=WorkspaceRole.VIEWER.value if joining_workspace else WorkspaceRole.OWNER.value,
        status="pending" if joining_workspace else "active",
    ))
    db.commit()
    db.refresh(new_user)

    # 3. Issue tokens
    access_token = security.create_access_token(new_user.id)
    refresh_token = security.create_refresh_token(new_user.id, token_version=new_user.refresh_token_version)
    _store_refresh_token(db, new_user, refresh_token, request)
    _set_auth_cookies(response, access_token, refresh_token)

    # 4. Audit + UBA
    from src.utils.audit import AuditLogger
    AuditLogger.log(
        db,
        action="user_registered",
        module="auth",
        workspace_id=new_workspace.id,
        user_id=new_user.id,
        metadata={"email": new_user.email},
    )
    try:
        UserBehaviorAnalyticsService.record_event(
            db=db,
            workspace_id=new_workspace.id,
            user_id=new_user.id,
            event_type="user_registered",
            ip_address=get_client_ip(request),
            endpoint_accessed=str(request.url.path),
        )
    except Exception as exc:
        print(f"UBA registration telemetry failed: {exc}")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": "pending" if joining_workspace else new_user.role,
        "workspace_access": "pending" if joining_workspace else "active",
    }


@router.post("/login/access-token", response_model=Token)
def login_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    """OAuth2 compatible token login with cookie + JSON response."""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        if user:
            try:
                UserBehaviorAnalyticsService.record_event(
                    db=db,
                    workspace_id=user.workspace_id,
                    user_id=user.id,
                    event_type="login_failed",
                    ip_address=get_client_ip(request),
                    endpoint_accessed=str(request.url.path),
                )
            except Exception as exc:
                print(f"UBA failed-login telemetry failed: {exc}")
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Check MFA
    user_mfa = db.query(UserMFA).filter(UserMFA.user_id == user.id).first()
    if user_mfa and user_mfa.enabled:
        # Issue an intermediate MFA token
        mfa_token = security.create_access_token(user.id, expires_delta=timedelta(minutes=5))
        return {
            "access_token": mfa_token,
            "token_type": "mfa",
            "expires_in": 300,
        }

    # Issue tokens
    access_token = security.create_access_token(user.id)
    refresh_token = security.create_refresh_token(user.id, token_version=user.refresh_token_version)
    _store_refresh_token(db, user, refresh_token, request)
    _set_auth_cookies(response, access_token, refresh_token)

    _record_successful_login(db, user, request)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": user.role,
    }


@router.post("/me/record-login")
def record_federated_login(
    request: Request,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> dict[str, Any]:
    """Record the completed OAuth sign-in initiated by the dashboard."""
    _record_successful_login(db, current_user, request)
    return {
        "last_login_ip": current_user.last_login_ip,
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
        "login_count": current_user.login_count,
    }


@router.post("/refresh")
def refresh_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
) -> Any:
    """
    Rotate refresh token:
      1. Validate the incoming refresh token (cookie or body)
      2. Revoke the old token
      3. Issue new access + refresh token pair
    """
    # Accept refresh token from cookie or Authorization header
    raw_token = request.cookies.get("refresh_token")
    if not raw_token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            raw_token = auth.split(" ", 1)[1]
    if not raw_token:
        raise HTTPException(status_code=401, detail="Refresh token not provided")

    payload = security.decode_refresh_token(raw_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Verify against DB (not revoked)
    token_hash = security.hash_refresh_token(raw_token)
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.revoked == False,
    ).first()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token revoked or not found")

    # Load user
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Verify token version matches (family invalidation)
    if payload.get("ver", -1) != user.refresh_token_version:
        # Possible token reuse after revocation — revoke all tokens for safety
        _revoke_all_user_tokens(db, user.id)
        raise HTTPException(status_code=401, detail="Token family invalidated. Please log in again.")

    # Rotate: revoke old, issue new
    _revoke_refresh_token(db, raw_token)
    new_access = security.create_access_token(user.id)
    new_refresh = security.create_refresh_token(user.id, token_version=user.refresh_token_version)
    _store_refresh_token(db, user, new_refresh, request)
    _set_auth_cookies(response, new_access, new_refresh)

    return {
        "access_token": new_access,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
) -> Any:
    """Revoke the current refresh token and clear auth cookies."""
    raw_token = request.cookies.get("refresh_token")
    if raw_token:
        _revoke_refresh_token(db, raw_token)

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"detail": "Logged out successfully"}


@router.post("/logout/all")
def logout_all_sessions(
    request: Request,
    response: Response,
    db: Session = Depends(deps.get_db),
    current_user: Optional[User] = Depends(deps.get_current_user),
) -> Any:
    """Revoke all refresh tokens for the current user (panic button)."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    count = _revoke_all_user_tokens(db, current_user.id)
    # Increment token version to invalidate all existing JWT families
    current_user.refresh_token_version = (current_user.refresh_token_version or 0) + 1
    db.commit()

    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"detail": f"Logged out from {count} session(s)"}


def _revoke_all_user_tokens(db: Session, user_id: uuid.UUID) -> int:
    """Revoke all active refresh tokens for a user."""
    from datetime import datetime
    tokens = db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False,
    ).all()
    now = datetime.utcnow()
    for t in tokens:
        t.revoked = True
        t.revoked_at = now
    db.commit()
    return len(tokens)


# ── Account / Session Info Endpoints ─────────────────────────────────────────

@router.get("/me")
def get_current_user_info(
    request: Request,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Return the authenticated user's profile including last login IP."""
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "workspace_id": str(current_user.workspace_id),
        "last_login_ip": current_user.last_login_ip,
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
        "login_count": current_user.login_count or 0,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "current_request_ip": get_client_ip(request),
    }


@router.get("/me/sessions")
def get_active_sessions(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Return all active (non-revoked) login sessions for the current user.
    Shows the IP address, user-agent, and creation time for each session.
    """
    sessions = db.query(RefreshToken).filter(
        RefreshToken.user_id == current_user.id,
        RefreshToken.revoked == False,
    ).order_by(RefreshToken.created_at.desc()).all()

    return {
        "total_active_sessions": len(sessions),
        "sessions": [
            {
                "session_id": str(s.id),
                "ip_address": s.client_ip,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "expires_at": s.expires_at.isoformat() if s.expires_at else None,
            }
            for s in sessions
        ],
    }


@router.get("/me/login-history")
def get_login_history(
    limit: int = 50,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Return the login history for the current user from UBA events.
    Shows each login attempt (success/failure) with IP address and timestamp.
    """
    from src.models.models import UserBehaviorEvent
    events = (
        db.query(UserBehaviorEvent)
        .filter(
            UserBehaviorEvent.user_id == current_user.id,
            UserBehaviorEvent.event_type.in_(["login_success", "login_failed"]),
        )
        .order_by(UserBehaviorEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    return {
        "user_id": str(current_user.id),
        "email": current_user.email,
        "last_login_ip": current_user.last_login_ip,
        "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
        "login_count": current_user.login_count or 0,
        "history": [
            {
                "event_type": e.event_type,
                "ip_address": e.ip_address,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "risk_level": e.risk_level,
                "anomaly_score": e.anomaly_score,
            }
            for e in events
        ],
    }


@router.get("/me/api-activity")
def get_api_consumer_activity(
    limit: int = 100,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Return recent API key usage logs for all keys in the current workspace.
    This lets workspace owners see which IPs are calling their API.
    """
    from src.models.models import APIKey, APIKeyAuditLog as AuditLog_
    workspace_id = str(current_user.workspace_id)

    # Get all API keys for this workspace
    api_keys = db.query(APIKey).filter(
        APIKey.workspace_id == current_user.workspace_id
    ).all()

    key_map = {str(k.id): k.label for k in api_keys}

    logs = (
        db.query(AuditLog_)
        .filter(AuditLog_.workspace_id == workspace_id)
        .order_by(AuditLog_.created_at.desc())
        .limit(limit)
        .all()
    )

    # Aggregate unique IPs per key
    ip_summary: dict = {}
    for log in logs:
        key_label = key_map.get(log.api_key_id, f"key:{log.api_key_id[:8]}…")
        ip = log.client_ip or "unknown"
        bucket = ip_summary.setdefault(key_label, {"ips": set(), "total_requests": 0})
        bucket["ips"].add(ip)
        bucket["total_requests"] += 1

    return {
        "workspace_id": workspace_id,
        "total_api_keys": len(api_keys),
        "recent_activity": [
            {
                "api_key_label": key_map.get(log.api_key_id, f"key:{log.api_key_id[:8]}…"),
                "client_ip": log.client_ip,
                "endpoint": log.endpoint,
                "method": log.method,
                "status_code": log.status_code,
                "event": log.event,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
        "unique_ips_per_key": {
            label: {
                "unique_ips": list(data["ips"]),
                "total_requests": data["total_requests"],
            }
            for label, data in ip_summary.items()
        },
    }
