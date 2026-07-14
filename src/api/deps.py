"""
CyberGuard AI – unified authentication + authorization dependencies.

Supports two coexisting authentication methods:

  1. JWT (dashboard / browser sessions)
     – extracted from HttpOnly cookie or Authorization: Bearer <jwt>

  2. API Key (external customers / integrations)
     – Authorization: Bearer cg_live_<token>
     – X-API-Key: cg_live_<token>

Both methods ultimately resolve to a Workspace and a role, which are then
injected into every protected endpoint via the dependency functions below.

RBAC
----
Use ``require_permissions(*perms)`` for permission-gated endpoints::

    @router.post("/resolve")
    def resolve(
        _: User = Depends(require_permissions("alerts:write")),
        ...
    ):

Use ``require_roles(*roles)`` for role-level gating::

    @router.delete("/key/{id}")
    def revoke(
        _: User = Depends(require_roles("workspace_admin", "super_admin")),
        ...
    ):
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generator, Optional, Set

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core import security
from src.core.database import SessionLocal
from src.models.models import (
    APIKey, APIKeyAuditLog, AuditLog, Permission, Role,
    RolePermission, User, Workspace
)

logger = logging.getLogger(__name__)

# ── OAuth2 scheme (auto_error=False so we can check cookies first) ─────────
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token",
    auto_error=False,
)

API_KEY_PREFIX = "cg_live_"

# Roles that exist in the system (canonical names)
VALID_ROLES = frozenset({"super_admin", "workspace_admin", "security_analyst", "viewer"})


# ── Database session ───────────────────────────────────────────────────────
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Auth context dataclass ─────────────────────────────────────────────────
@dataclass
class AuthContext:
    """Resolved authentication context for a single request."""
    workspace: Workspace
    user: Optional[User] = None          # Present for JWT auth only
    api_key: Optional[APIKey] = None     # Present for API key auth only
    auth_method: str = "jwt"             # "jwt" | "api_key"
    permissions: Set[str] = field(default_factory=set)  # Cached permission set


# ── Internal helpers ───────────────────────────────────────────────────────
def _hash_api_key(raw_key: str) -> str:
    """Return the canonical SHA-256 hex digest of a raw API key."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


def _get_raw_api_key(request: Request, bearer_token: Optional[str]) -> Optional[str]:
    """Extract a raw API key string from the request, if present."""
    # Priority 1: X-API-Key header
    xkey = request.headers.get("X-API-Key")
    if xkey:
        return xkey.strip()

    # Priority 2: Authorization: Bearer cg_live_...
    if bearer_token and bearer_token.startswith(API_KEY_PREFIX):
        return bearer_token.strip()

    return None


def _load_permissions(role_name: Optional[str], db: Session) -> Set[str]:
    """Load the permission set for a role from DB. Returns empty set on failure."""
    if not role_name:
        return set()
    role = db.query(Role).filter(Role.name == role_name).first()
    if not role:
        return set()
    perms = (
        db.query(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .filter(RolePermission.role_id == role.id)
        .all()
    )
    return {p[0] for p in perms}


def _resolve_api_key(raw_key: str, db: Session, request: Request) -> AuthContext:
    """
    Fully validate an API key and return its AuthContext.

    Raises HTTP 401 on any validation failure (key unknown, revoked,
    expired, workspace missing).
    """
    key_hash = _hash_api_key(raw_key)

    api_key: Optional[APIKey] = (
        db.query(APIKey)
        .filter(APIKey.key_hash == key_hash, APIKey.is_active == True)
        .first()
    )

    if not api_key:
        _write_audit(db, None, None, request, "invalid_key", 401)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
        )

    # ── Expiry check ────────────────────────────────────────────────────
    if api_key.expires_at:
        expires = api_key.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            _write_audit(db, api_key, api_key.workspace_id, request, "expired_key", 401)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired.",
            )

    # ── Workspace check ─────────────────────────────────────────────────
    workspace: Optional[Workspace] = (
        db.query(Workspace).filter(Workspace.id == api_key.workspace_id).first()
    )
    if not workspace:
        _write_audit(db, api_key, api_key.workspace_id, request, "missing_workspace", 401)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Workspace associated with this API key no longer exists.",
        )

    # ── Update usage stats ───────────────────────────────────────────────
    now = datetime.now(timezone.utc)
    api_key.last_used = now
    api_key.last_used_ip = _get_client_ip(request)
    api_key.usage_count = (api_key.usage_count or 0) + 1
    api_key.successful_requests = (api_key.successful_requests or 0) + 1

    _write_audit(db, api_key, workspace.id, request, "used", 200)
    db.commit()

    logger.info(
        "API key auth OK | label=%s workspace=%s ip=%s",
        api_key.label,
        workspace.id,
        api_key.last_used_ip,
    )
    # API keys get scans:create permission by default (detection use case)
    return AuthContext(
        workspace=workspace,
        api_key=api_key,
        auth_method="api_key",
        permissions={"scans:create", "scans:read"},
    )


def _resolve_jwt(token: str, db: Session) -> AuthContext:
    """Validate a JWT and return its AuthContext with permissions loaded."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[security.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        if user_id is None or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user: Optional[User] = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if user is None or not user.is_active:
        raise credentials_exception

    if not user.workspace_id:
        raise HTTPException(status_code=400, detail="User is not assigned to a workspace.")

    workspace: Optional[Workspace] = (
        db.query(Workspace).filter(Workspace.id == user.workspace_id).first()
    )
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found.")

    permissions = _load_permissions(user.role, db)

    return AuthContext(
        workspace=workspace,
        user=user,
        auth_method="jwt",
        permissions=permissions,
    )


def _write_audit(
    db: Session,
    api_key: Optional[APIKey],
    workspace_id,
    request: Request,
    event: str,
    status_code: int,
) -> None:
    """Write a row to api_key_audit_logs (best-effort, never raises)."""
    try:
        log = APIKeyAuditLog(
            id=str(uuid.uuid4()),
            api_key_id=str(api_key.id) if api_key else str(uuid.uuid4()),
            workspace_id=str(workspace_id) if workspace_id else str(uuid.uuid4()),
            endpoint=str(request.url.path),
            method=request.method,
            status_code=status_code,
            client_ip=_get_client_ip(request),
            event=event,
        )
        db.add(log)
    except Exception as exc:
        logger.warning("Failed to write API key audit log: %s", exc)


def _write_permission_denied_audit(
    db: Session,
    user: Optional[User],
    workspace_id,
    request: Request,
    required_permission: str,
    role: Optional[str],
) -> None:
    """Write an audit log entry for a permission-denied (403) event."""
    try:
        log = AuditLog(
            workspace_id=workspace_id,
            user_id=user.id if user else None,
            action="permission_denied",
            module="rbac",
            status="failure",
            event_metadata={
                "endpoint": str(request.url.path),
                "method": request.method,
                "required_permission": required_permission,
                "user_role": role,
                "client_ip": _get_client_ip(request),
            },
        )
        db.add(log)
        db.commit()
    except Exception as exc:
        logger.warning("Failed to write permission-denied audit log: %s", exc)


def _get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# Public dependencies
# ═══════════════════════════════════════════════════════════════════════════

def get_auth_context(
    request: Request,
    bearer_token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    """
    Resolve the authentication context for a request.

    Checks (in order):
      1. API key via X-API-Key header
      2. API key via Authorization: Bearer cg_live_<token>
      3. JWT via Authorization: Bearer <jwt>
      4. JWT via access_token HttpOnly cookie
    """
    # ── API key paths ───────────────────────────────────────────────────
    raw_api_key = _get_raw_api_key(request, bearer_token)
    if raw_api_key:
        return _resolve_api_key(raw_api_key, db, request)

    # ── JWT paths ───────────────────────────────────────────────────────
    cookie_token = request.cookies.get("access_token")
    jwt_token = cookie_token or bearer_token

    if not jwt_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Provide a JWT or API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _resolve_jwt(jwt_token, db)


def get_current_user(
    ctx: AuthContext = Depends(get_auth_context),
) -> User:
    """
    Returns the authenticated User.

    Raises HTTP 403 when the request was authenticated via an API key
    (no user object exists in that context).
    """
    if ctx.user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires user (JWT) authentication, not an API key.",
        )
    return ctx.user


def get_current_workspace(
    ctx: AuthContext = Depends(get_auth_context),
) -> Workspace:
    """Returns the Workspace, regardless of whether auth was JWT or API key."""
    return ctx.workspace


def get_optional_user(
    ctx: AuthContext = Depends(get_auth_context),
) -> Optional[User]:
    """Returns the User if authenticated via JWT, or None for API key requests."""
    return ctx.user


# ── Legacy get_token_from_request kept for backward compat ─────────────────
def get_token_from_request(
    request: Request,
    bearer_token: Optional[str] = Depends(oauth2_scheme),
) -> str:
    """
    Extract the access token from HttpOnly cookie or Authorization header.
    Cookie takes precedence for browser sessions.
    """
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token
    if bearer_token:
        return bearer_token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_api_key(
    request: Request,
    db: Session = Depends(get_db),
) -> APIKey:
    """
    Backward-compatible dependency: extract and validate an API key
    from X-API-Key or Authorization: Bearer cg_live_... headers.
    """
    raw_key = (
        request.headers.get("X-API-Key")
        or (
            request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if request.headers.get("Authorization", "").startswith("Bearer cg_live_")
            else None
        )
    )
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key required for this endpoint.",
        )
    ctx = _resolve_api_key(raw_key, db, request)
    return ctx.api_key


# ═══════════════════════════════════════════════════════════════════════════
# RBAC Dependency Factories
# ═══════════════════════════════════════════════════════════════════════════

class RequirePermissions:
    """
    FastAPI dependency that enforces one or more permissions.

    Usage::

        @router.post("/resolve")
        def resolve(
            current_user: User = Depends(RequirePermissions("alerts:write")),
        ):

    - API key auth: checks the key's permission set (currently scans:create, scans:read)
    - JWT auth: checks the user's role-derived permissions
    - Logs every 403 denial to the audit_logs table
    """

    def __init__(self, *required_permissions: str):
        self.required_permissions = list(required_permissions)

    def __call__(
        self,
        request: Request,
        ctx: AuthContext = Depends(get_auth_context),
        db: Session = Depends(get_db),
    ) -> User:
        # Re-load permissions if they are empty (shouldn't happen, but defensive)
        permissions = ctx.permissions
        if not permissions and ctx.user:
            permissions = _load_permissions(ctx.user.role, db)

        for req_perm in self.required_permissions:
            if req_perm not in permissions:
                role = ctx.user.role if ctx.user else "api_key"
                logger.warning(
                    "Permission denied | user=%s role=%s required=%s endpoint=%s",
                    ctx.user.id if ctx.user else "api_key",
                    role,
                    req_perm,
                    request.url.path,
                )
                _write_permission_denied_audit(
                    db,
                    ctx.user,
                    ctx.workspace.id,
                    request,
                    req_perm,
                    role,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required: '{req_perm}'.",
                )

        return ctx



class RequireRoles:
    """
    FastAPI dependency that enforces one of the specified roles.

    Usage::

        @router.delete("/key/{id}")
        def revoke(
            _: User = Depends(RequireRoles("workspace_admin", "super_admin")),
        ):
    """

    def __init__(self, *allowed_roles: str):
        self.allowed_roles = set(allowed_roles)

    def __call__(
        self,
        request: Request,
        ctx: AuthContext = Depends(get_auth_context),
        db: Session = Depends(get_db),
    ) -> User:
        if ctx.user is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This endpoint requires user (JWT) authentication.",
            )

        if ctx.user.role not in self.allowed_roles:
            logger.warning(
                "Role denied | user=%s role=%s allowed=%s endpoint=%s",
                ctx.user.id,
                ctx.user.role,
                self.allowed_roles,
                request.url.path,
            )
            _write_permission_denied_audit(
                db,
                ctx.user,
                ctx.workspace.id,
                request,
                f"role:{','.join(sorted(self.allowed_roles))}",
                ctx.user.role,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required one of: {sorted(self.allowed_roles)}.",
            )
        return ctx.user


# Convenience factory aliases (callable classes → reusable as Depends values)
def require_permissions(*perms: str):
    """Return a FastAPI dependency that requires all listed permissions."""
    return RequirePermissions(*perms)


def require_roles(*roles: str):
    """Return a FastAPI dependency that requires one of the listed roles."""
    return RequireRoles(*roles)
