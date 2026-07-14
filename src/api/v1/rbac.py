"""
CyberGuard AI – RBAC Management Endpoints
==========================================

GET  /api/v1/rbac/my-permissions  – Return the current user's role + permissions
GET  /api/v1/rbac/roles           – List all roles & permissions (super_admin only)
PUT  /api/v1/users/{user_id}/role – Change a user's role (workspace_admin+)
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.api.deps import (
    RequirePermissions,
    RequireRoles,
    get_auth_context,
    get_current_user,
    get_db,
    _load_permissions,
    AuthContext,
)
from src.models.models import Permission, Role, RolePermission, User, Workspace
from src.utils.audit import AuditLogger

router = APIRouter()

VALID_ROLES = {"super_admin", "workspace_admin", "security_analyst", "viewer"}


# ── Schemas ───────────────────────────────────────────────────────────────────

class MyPermissionsResponse(BaseModel):
    user_id: str
    email: str
    role: str
    permissions: List[str]


class RoleDetail(BaseModel):
    name: str
    description: Optional[str]
    permissions: List[str]


class RoleChangeRequest(BaseModel):
    role: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/my-permissions", response_model=MyPermissionsResponse)
def get_my_permissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Return the calling user's role and full permission set.
    Used by the frontend to gate UI components.
    """
    permissions = _load_permissions(current_user.role, db)
    return MyPermissionsResponse(
        user_id=str(current_user.id),
        email=current_user.email,
        role=current_user.role or "viewer",
        permissions=sorted(permissions),
    )


@router.get("/roles", response_model=List[RoleDetail])
def list_roles(
    db: Session = Depends(get_db),
    _: User = Depends(RequirePermissions("system:admin")),
) -> Any:
    """
    List all roles and their associated permissions.
    Requires system:admin permission (super_admin only).
    """
    roles = db.query(Role).all()
    result = []
    for role in roles:
        perms = (
            db.query(Permission.name)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .filter(RolePermission.role_id == role.id)
            .all()
        )
        result.append(RoleDetail(
            name=role.name,
            description=role.description,
            permissions=sorted(p[0] for p in perms),
        ))
    return result


@router.put("/users/{user_id}/role", response_model=Dict[str, Any])
def change_user_role(
    user_id: str,
    payload: RoleChangeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ctx: AuthContext = Depends(get_auth_context),
) -> Any:
    """
    Change the role of a user within the current workspace.

    Rules:
    - workspace_admin can assign: workspace_admin, security_analyst, viewer
    - super_admin can assign any role
    - Users cannot demote themselves
    - Workspace isolation: can only change users in own workspace
    """
    # Only workspace_admin+ can change roles
    if current_user.role not in {"workspace_admin", "super_admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only workspace admins and super admins can change user roles.",
        )

    new_role = payload.role
    if new_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role '{new_role}'. Valid roles: {sorted(VALID_ROLES)}.",
        )

    # Workspace admins cannot grant super_admin
    if current_user.role == "workspace_admin" and new_role == "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Workspace admins cannot grant the super_admin role.",
        )

    # Parse target user UUID
    try:
        target_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid user ID.")

    # Prevent self-demotion
    if target_uuid == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role.",
        )

    # Workspace isolation (non-super-admins can only change users in own workspace)
    target_user = db.query(User).filter(User.id == target_uuid).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if current_user.role != "super_admin":
        if str(target_user.workspace_id) != str(ctx.workspace.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify users outside your workspace.",
            )

    old_role = target_user.role
    target_user.role = new_role
    db.commit()

    AuditLogger.log(
        db,
        action="user_role_changed",
        module="rbac",
        status="success",
        workspace_id=ctx.workspace.id,
        user_id=current_user.id,
        metadata={
            "target_user_id": str(target_uuid),
            "target_email": target_user.email,
            "from_role": old_role,
            "to_role": new_role,
        },
    )

    return {
        "user_id": user_id,
        "email": target_user.email,
        "previous_role": old_role,
        "new_role": new_role,
        "message": f"Role updated from '{old_role}' to '{new_role}'.",
    }
